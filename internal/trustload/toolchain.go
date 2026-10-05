package trustload

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"runtime"
	"strings"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const ToolchainIndexPath = "toolchain/index.json"
const ToolchainIndexVersion = "tplaiter.dev/go-toolchain-index/v1"

var ErrToolchain = errors.New("TRUST_TOOLCHAIN_UNAVAILABLE")

type ToolchainFile struct {
	Path   string   `json:"path"`
	Mode   string   `json:"mode"`
	SHA256 string   `json:"sha256"`
	Size   int64    `json:"size"`
	Chunks []string `json:"chunks"`
}
type ToolchainIndex struct {
	APIVersion string          `json:"apiVersion"`
	GoVersion  string          `json:"goVersion"`
	GOOS       string          `json:"goos"`
	GOARCH     string          `json:"goarch"`
	Files      []ToolchainFile `json:"files"`
}

// GoToolchain is derived only from a runtime-verified source and its fixed CAS.
// Returned copies cannot alter the bound material.
type GoToolchain struct {
	runtime *Runtime
	source  *trustverify.VerifiedResolution
	index   []byte
	files   []ToolchainFile
	data    [][]byte
	version string
}

func (r *Runtime) ResolveGoToolchain(ctx context.Context, source *trustverify.VerifiedResolution) (*GoToolchain, error) {
	stable := r.TrustRuntime()
	if ctx == nil || stable == nil || source == nil || !source.ValidFor(stable, stable.Binding()) {
		return nil, ErrToolchain
	}
	snapshot, err := stable.VerifiedSnapshot(source)
	if err != nil {
		return nil, ErrToolchain
	}
	raw, ok := snapshot.Blob(ToolchainIndexPath)
	if !ok || ValidateGoToolchainIndex(raw) != nil {
		return nil, ErrToolchain
	}
	var index ToolchainIndex
	if canonicaljson.DecodeStrict(raw, &index) != nil || index.APIVersion != ToolchainIndexVersion || index.GOOS != runtime.GOOS || index.GOARCH != runtime.GOARCH || !strings.HasPrefix(index.GoVersion, "go1.") || len(index.Files) == 0 || len(index.Files) > 20000 {
		return nil, ErrToolchain
	}
	t := &GoToolchain{runtime: r, source: source, index: append([]byte(nil), raw...), version: index.GoVersion}
	last := ""
	var total int64
	required := map[string]bool{"bin/go": false, "VERSION": false, "src/runtime/runtime.go": false, "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/compile": false, "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/link": false, "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/asm": false}
	for _, f := range index.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Path <= last || f.Path == "." || f.Path == ".." || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "/") || strings.ContainsAny(f.Path, "\\\x00:") || strings.HasPrefix(f.Path, "../") || (f.Mode != "100644" && f.Mode != "100755") || f.Size < 0 || f.Size > 64<<20 || len(f.Chunks) > 16 {
			return nil, ErrToolchain
		}
		last = f.Path
		total += f.Size
		if total > 512<<20 {
			return nil, ErrToolchain
		}
		b := make([]byte, 0, int(f.Size))
		for _, ref := range f.Chunks {
			chunk, e := r.Read(ctx, ref)
			if e != nil || len(chunk) > 4<<20 || int64(len(b)+len(chunk)) > f.Size {
				return nil, ErrToolchain
			}
			b = append(b, chunk...)
		}
		if int64(len(b)) != f.Size || evidencecas.Digest(b) != f.SHA256 {
			return nil, ErrToolchain
		}
		if _, ok := required[f.Path]; ok {
			required[f.Path] = true
		}
		if f.Mode == "100755" {
			info, e := buildinfo.Read(bytes.NewReader(b))
			if e != nil || info.GoVersion != index.GoVersion {
				return nil, ErrToolchain
			}
			switch f.Path {
			case "bin/go":
				if info.Path != "cmd/go" {
					return nil, ErrToolchain
				}
			case "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/compile":
				if info.Path != "cmd/compile" {
					return nil, ErrToolchain
				}
			case "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/link":
				if info.Path != "cmd/link" {
					return nil, ErrToolchain
				}
			case "pkg/tool/" + runtime.GOOS + "_" + runtime.GOARCH + "/asm":
				if info.Path != "cmd/asm" {
					return nil, ErrToolchain
				}
			default:
				return nil, ErrToolchain
			}
		} else if f.Path == "bin/go" || strings.HasPrefix(f.Path, "pkg/tool/") {
			return nil, ErrToolchain
		}
		t.files = append(t.files, f)
		t.data = append(t.data, b)
	}
	for _, ok := range required {
		if !ok {
			return nil, ErrToolchain
		}
	}
	return t, nil
}
func (t *GoToolchain) IndexBytes() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.index...)
}
func (t *GoToolchain) Version() string {
	if t == nil {
		return ""
	}
	return t.version
}
func (t *GoToolchain) Driver() []byte {
	if t == nil {
		return nil
	}
	for i, f := range t.files {
		if f.Path == "bin/go" {
			return append([]byte(nil), t.data[i]...)
		}
	}
	return nil
}
func (t *GoToolchain) Files() ([]ToolchainFile, [][]byte) {
	if t == nil {
		return nil, nil
	}
	f := append([]ToolchainFile(nil), t.files...)
	b := make([][]byte, len(t.data))
	for i := range b {
		b[i] = append([]byte(nil), t.data[i]...)
		f[i].Chunks = append([]string(nil), f[i].Chunks...)
	}
	return f, b
}
func (t *GoToolchain) Recheck(ctx context.Context) error {
	if t == nil || t.runtime.TrustRuntime() == nil {
		return ErrToolchain
	}
	s := t.runtime.TrustRuntime()
	fresh, e := s.VerifySubject(ctx, t.source.Subject(), t.source.Evidence())
	if e != nil {
		return e
	}
	again, e := t.runtime.ResolveGoToolchain(ctx, fresh)
	if e != nil || !bytes.Equal(again.index, t.index) {
		return ErrToolchain
	}
	return nil
}

// ValidateGoToolchainIndex checks the bounded inert declaration. It never reads
// CAS, discovers a host tool, or conveys execution permission.
func ValidateGoToolchainIndex(raw []byte) error {
	var index ToolchainIndex
	if len(raw) == 0 || len(raw) > 8<<20 || canonicaljson.DecodeStrict(raw, &index) != nil || index.APIVersion != ToolchainIndexVersion || (index.GOOS != "darwin" && index.GOOS != "linux") || (index.GOARCH != "arm64" && index.GOARCH != "amd64") || !regexp.MustCompile(`^go1\.[0-9]+(\.[0-9]+)?$`).MatchString(index.GoVersion) || len(index.Files) == 0 || len(index.Files) > 20000 {
		return ErrToolchain
	}
	validDigest := func(s string) bool {
		if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
			return false
		}
		b, e := hex.DecodeString(s[7:])
		return e == nil && len(b) == 32 && strings.ToLower(s) == s
	}
	toolRoot := "pkg/tool/" + index.GOOS + "_" + index.GOARCH + "/"
	required := map[string]bool{"bin/go": false, "VERSION": false, "src/runtime/runtime.go": false, toolRoot + "compile": false, toolRoot + "link": false, toolRoot + "asm": false}
	executable := map[string]bool{"bin/go": true, toolRoot + "compile": true, toolRoot + "link": true, toolRoot + "asm": true}
	last := ""
	var total int64
	seen := map[string]bool{}
	for _, f := range index.Files {
		folded := strings.ToLower(f.Path)
		if f.Path <= last || f.Path == "." || f.Path == ".." || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\\\x00:") || seen[folded] || !validDigest(f.SHA256) || f.Size < 0 || f.Size > 64<<20 || len(f.Chunks) > 16 || (f.Size > 0 && len(f.Chunks) == 0) || int64(len(f.Chunks))*(4<<20) < f.Size || (f.Mode != "100644" && f.Mode != "100755") || (f.Mode == "100755") != executable[f.Path] {
			return ErrToolchain
		}
		for _, c := range f.Chunks {
			if !validDigest(c) {
				return ErrToolchain
			}
		}
		seen[folded] = true
		last = f.Path
		total += f.Size
		if total > 512<<20 {
			return ErrToolchain
		}
		if _, ok := required[f.Path]; ok {
			required[f.Path] = true
		}
	}
	for _, found := range required {
		if !found {
			return ErrToolchain
		}
	}
	return nil
}
