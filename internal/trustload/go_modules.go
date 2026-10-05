package trustload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
)

const GoModuleIndexPath = "modules/index.json"
const GoModuleIndexVersion = "tplaiter.dev/go-module-closure/v1"

var ErrGoModules = errors.New("TRUST_GO_MODULE_CLOSURE_UNAVAILABLE")

type GoModulePin struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Sum      string `json:"sum"`
	GoModSum string `json:"goModSum"`
}
type GoModuleIndex struct {
	APIVersion  string        `json:"apiVersion"`
	GoModSHA256 string        `json:"goModSHA256"`
	GoSumSHA256 string        `json:"goSumSHA256"`
	Modules     []GoModulePin `json:"modules"`
	// Files are immutable expanded public module bytes and Go download metadata.
	// They confer no executable permission; the adapter stages all as read-only.
	Files []ToolchainFile `json:"files"`
}
type GoModules struct {
	owner       *Runtime
	source      *trustverify.VerifiedResolution
	index       []byte
	declaration GoModuleIndex
	data        [][]byte
}

func validModuleSum(s string) bool {
	if !strings.HasPrefix(s, "h1:") {
		return false
	}
	b, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(s, "h1:"))
	return e == nil && len(b) == 32
}
func moduleCacheRoot(p GoModulePin) (string, error) {
	if module.Check(p.Path, p.Version) != nil {
		return "", ErrGoModules
	}
	ep, e := module.EscapePath(p.Path)
	if e != nil {
		return "", ErrGoModules
	}
	ev, e := module.EscapeVersion(p.Version)
	if e != nil {
		return "", ErrGoModules
	}
	return ep + "@" + ev, nil
}
func validModuleDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, e := hex.DecodeString(s[7:])
	return e == nil && strings.ToLower(s) == s
}
func ValidateGoModuleIndex(raw []byte) error {
	var v GoModuleIndex
	if len(raw) == 0 || len(raw) > 8<<20 || canonicaljson.DecodeStrict(raw, &v) != nil || v.APIVersion != GoModuleIndexVersion || !validModuleDigest(v.GoModSHA256) || !validModuleDigest(v.GoSumSHA256) || len(v.Modules) == 0 || len(v.Modules) > 512 || len(v.Files) == 0 || len(v.Files) > 20000 {
		return ErrGoModules
	}
	roots := map[string]bool{}
	last := ""
	for _, m := range v.Modules {
		root, e := moduleCacheRoot(m)
		if e != nil || m.Path <= last || !validModuleSum(m.Sum) || !validModuleSum(m.GoModSum) {
			return ErrGoModules
		}
		last = m.Path
		roots[root] = true
	}
	last = ""
	var total int64
	for _, f := range v.Files {
		if !fs.ValidPath(f.Path) || f.Path == "." || path.Clean(f.Path) != f.Path || strings.ContainsAny(f.Path, "\\\x00:\r\n") || f.Path <= last || f.Mode != "100644" || f.Size < 0 || f.Size > 32<<20 || !validModuleDigest(f.SHA256) || len(f.Chunks) == 0 || len(f.Chunks) > 8 {
			return ErrGoModules
		}
		last = f.Path
		total += f.Size
		if total > 256<<20 {
			return ErrGoModules
		}
		for _, c := range f.Chunks {
			if !validModuleDigest(c) {
				return ErrGoModules
			}
		}
		allowed := false
		for root := range roots {
			if strings.HasPrefix(f.Path, root+"/") {
				allowed = true
				break
			}
		}
		if strings.HasPrefix(f.Path, "cache/download/") {
			n := strings.TrimPrefix(f.Path, "cache/download/")
			parts := strings.Split(n, "/@v/")
			// No lists, locks, executable helpers or network endpoints are accepted.
			if len(parts) == 2 && !strings.Contains(parts[1], "/") && (strings.HasSuffix(parts[1], ".mod") || strings.HasSuffix(parts[1], ".info") || strings.HasSuffix(parts[1], ".ziphash")) {
				mp, e := module.UnescapePath(parts[0])
				ver := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(parts[1], ".ziphash"), ".info"), ".mod")
				mv, ve := module.UnescapeVersion(ver)
				allowed = e == nil && ve == nil && module.Check(mp, mv) == nil
			}
		}
		if !allowed {
			return ErrGoModules
		}
	}
	return nil
}

// ResolveGoModules uses only a freshly authenticated source and installed CAS.
// Public acquisition and checksum lookup happen before enrollment, never here.
func (r *Runtime) ResolveGoModules(ctx context.Context, source *trustverify.VerifiedResolution, goMod, goSum []byte) (*GoModules, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || source == nil || !source.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrGoModules
	}
	snapshot, e := r.TrustRuntime().VerifiedSnapshot(source)
	if e != nil {
		return nil, e
	}
	raw, ok := snapshot.Blob(GoModuleIndexPath)
	if !ok || ValidateGoModuleIndex(raw) != nil {
		return nil, ErrGoModules
	}
	var index GoModuleIndex
	if canonicaljson.DecodeStrict(raw, &index) != nil || moduleProjectDigest(goMod) != index.GoModSHA256 || evidencecas.Digest(goSum) != index.GoSumSHA256 {
		return nil, ErrGoModules
	}
	g := &GoModules{owner: r, source: source, index: append([]byte(nil), raw...), declaration: index}
	sums := map[string]string{}
	for _, line := range strings.Split(string(goSum), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !validModuleSum(f[2]) {
			return nil, ErrGoModules
		}
		k := f[0] + " " + f[1]
		if old, ok := sums[k]; ok && old != f[2] {
			return nil, ErrGoModules
		}
		sums[k] = f[2]
	}
	virtual := map[string][]byte{}
	for _, f := range index.Files {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		b := make([]byte, 0, int(f.Size))
		for _, ref := range f.Chunks {
			chunk, e := r.Read(ctx, ref)
			if e != nil || len(chunk) > 4<<20 || int64(len(b)+len(chunk)) > f.Size {
				return nil, ErrGoModules
			}
			b = append(b, chunk...)
		}
		if int64(len(b)) != f.Size || evidencecas.Digest(b) != f.SHA256 {
			return nil, ErrGoModules
		}
		virtual[f.Path] = b
		g.data = append(g.data, b)
	}
	for _, m := range index.Modules {
		if sums[m.Path+" "+m.Version] != m.Sum || sums[m.Path+" "+m.Version+"/go.mod"] != m.GoModSum {
			return nil, ErrGoModules
		}
		root, _ := moduleCacheRoot(m)
		names := []string{}
		lookup := map[string][]byte{}
		for n, b := range virtual {
			if strings.HasPrefix(n, root+"/") {
				rel := strings.TrimPrefix(n, root+"/")
				name := m.Path + "@" + m.Version + "/" + rel
				names = append(names, name)
				lookup[name] = b
			}
		}
		sort.Strings(names)
		h, e := dirhash.Hash1(names, func(n string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(lookup[n])), nil })
		if e != nil || h != m.Sum {
			return nil, ErrGoModules
		}
		ep, _ := module.EscapePath(m.Path)
		ev, _ := module.EscapeVersion(m.Version)
		cache := "cache/download/" + ep + "/@v/" + ev
		b, ok := virtual[cache+".mod"]
		if !ok {
			return nil, ErrGoModules
		}
		h, e = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
		if e != nil || h != m.GoModSum || (virtual[root+"/go.mod"] != nil && !bytes.Equal(b, virtual[root+"/go.mod"])) || string(virtual[cache+".ziphash"]) != m.Sum {
			return nil, ErrGoModules
		}
	}
	// Historical graph .mod metadata must also match the project's pinned go.sum.
	for n, b := range virtual {
		if strings.HasPrefix(n, "cache/download/") && strings.HasSuffix(n, ".mod") {
			parts := strings.Split(strings.TrimPrefix(n, "cache/download/"), "/@v/")
			mp, _ := module.UnescapePath(parts[0])
			mv, _ := module.UnescapeVersion(strings.TrimSuffix(parts[1], ".mod"))
			h, e := dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
			if e != nil || sums[mp+" "+mv+"/go.mod"] != h {
				return nil, ErrGoModules
			}
		}
	}
	return g, nil
}
func (g *GoModules) IndexBytes() []byte {
	if g == nil {
		return nil
	}
	return append([]byte(nil), g.index...)
}
func (g *GoModules) Files() ([]ToolchainFile, [][]byte) {
	if g == nil {
		return nil, nil
	}
	f := append([]ToolchainFile(nil), g.declaration.Files...)
	d := make([][]byte, len(g.data))
	for i := range d {
		f[i].Chunks = append([]string(nil), f[i].Chunks...)
		d[i] = append([]byte(nil), g.data[i]...)
	}
	return f, d
}
func (g *GoModules) Includes(path, version string) bool {
	if g == nil {
		return false
	}
	for _, m := range g.declaration.Modules {
		if m.Path == path && m.Version == version {
			return true
		}
	}
	return false
}
func (g *GoModules) Recheck(ctx context.Context, mod, sum []byte) error {
	if g == nil || g.owner == nil || g.owner.TrustRuntime() == nil {
		return ErrGoModules
	}
	fresh, e := g.owner.TrustRuntime().VerifySubject(ctx, g.source.Subject(), g.source.Evidence())
	if e != nil {
		return e
	}
	next, e := g.owner.ResolveGoModules(ctx, fresh, mod, sum)
	if e != nil {
		return e
	}
	if !bytes.Equal(g.index, next.index) {
		return ErrGoModules
	}
	return nil
}

// The cache closure is independent of the generated project's module name;
// the exact original go.mod still enters the execution request input closure.
func moduleProjectDigest(raw []byte) string {
	f, e := modfile.Parse("go.mod", raw, nil)
	if e != nil || f.Module == nil {
		return ""
	}
	if f.AddModuleStmt("tplaiter.invalid/project") != nil {
		return ""
	}
	b, e := f.Format()
	if e != nil {
		return ""
	}
	return evidencecas.Digest(b)
}
func GoModuleProjectDigest(raw []byte) string { return moduleProjectDigest(raw) }
