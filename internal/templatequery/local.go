// Package templatequery observes the local cache. These receipts are explicitly
// unauthenticated ranking data; no project writer or credential store is opened.
package templatequery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

const maxManifest = 1 << 20

var ErrSource = errors.New("DISCOVERY_SOURCE_UNAVAILABLE")
var ErrMetadata = errors.New("DISCOVERY_METADATA_INVALID")
var ErrOutputBudget = errors.New("DISCOVERY_OUTPUT_BUDGET")

type row struct {
	alias string
	entry state.TemplateEntry
}

func bounded(root *os.Root, name string, limit int) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, ErrSource
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(b) > limit {
		return nil, ErrSource
	}
	return b, nil
}
func index(home string) (state.Index, error) {
	empty := state.NewIndex(time.Time{})
	root, err := os.OpenRoot(home)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, ErrSource
	}
	defer root.Close()
	b, err := bounded(root, "index.yaml", 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, ErrSource
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	var idx state.Index
	if err := decoder.Decode(&idx); err != nil || idx.Version != state.IndexVersion {
		return empty, ErrSource
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return empty, ErrSource
	}
	if idx.Repos == nil {
		idx.Repos = map[string][]state.TemplateEntry{}
	}
	return idx, nil
}
func rows(idx state.Index) ([]row, error) {
	out := []row{}
	for alias, entries := range idx.Repos {
		for _, entry := range entries {
			out = append(out, row{alias, entry})
			if len(out) > 4096 {
				return nil, ErrSource
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.alias != b.alias {
			return a.alias < b.alias
		}
		if a.entry.Name != b.entry.Name {
			return a.entry.Name < b.entry.Name
		}
		if a.entry.Path != b.entry.Path {
			return a.entry.Path < b.entry.Path
		}
		aa, _ := json.Marshal(a.entry)
		bb, _ := json.Marshal(b.entry)
		return string(aa) < string(bb)
	})
	return out, nil
}
func clonePath(home, alias string) (string, error) {
	// Validate the locator even when all other fields came from a local cache.
	pin := d.SourcePin{Qualification: "local-observed", Repo: alias, Path: ".", Commit: strings.Repeat("a", 40), ManifestSHA256: "sha256:" + strings.Repeat("a", 64)}
	if !pin.Valid() {
		return "", ErrSource
	}
	root, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", ErrSource
	}
	clone := filepath.Join(root, "repos", alias)
	actual, err := filepath.EvalSymlinks(clone)
	if err != nil {
		return "", ErrSource
	}
	rel, err := filepath.Rel(root, actual)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrSource
	}
	// Do not follow a cache's Git-directory symlink into another repository.
	info, err := os.Lstat(filepath.Join(actual, ".git"))
	if err != nil || !info.IsDir() {
		return "", ErrSource
	}
	return actual, nil
}
func blob(ctx context.Context, clone, commit, name string) ([]byte, error) {
	if ctx == nil || !safePath(name) {
		return nil, ErrSource
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, ErrSource
	}
	// A fixed local-object command. No shell, credentials, hooks, checkout, or
	// partial-clone fetch; it is separate from the unrestricted process runner.
	cmd := exec.CommandContext(ctx, git, "--no-optional-locks", "-C", clone, "cat-file", "--batch")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1"}
	cmd.Stdin = strings.NewReader(commit + ":" + name + "\n")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, ErrSource
	}
	if cmd.Start() != nil {
		return nil, ErrSource
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	reader := bufio.NewReaderSize(pipe, 512)
	header, err := reader.ReadString('\n')
	if err != nil || len(header) > 256 {
		return nil, ErrSource
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || fields[1] != "blob" {
		return nil, ErrSource
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 1 || size > maxManifest {
		return nil, ErrSource
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(reader, b); err != nil {
		return nil, ErrSource
	}
	newline, err := reader.ReadByte()
	if err != nil || newline != '\n' {
		return nil, ErrSource
	}
	if err := cmd.Wait(); err != nil {
		return nil, ErrSource
	}
	return b, nil
}
func safePath(p string) bool {
	return p != "" && !strings.ContainsAny(p, "\\:\x00\r\n") && !path.IsAbs(p) && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}
func selection(ctx context.Context, home string, r row, commit string) (*manifest.Template, d.SourcePin, error) {
	var pin d.SourcePin
	if !safePath(r.entry.Path) {
		return nil, pin, ErrSource
	}
	clone, err := clonePath(home, r.alias)
	if err != nil {
		return nil, pin, err
	}
	if commit == "" {
		ref := r.entry.Ref
		if len(r.entry.Tags) > 0 {
			ref = r.entry.Tags[0]
		}
		if ref == "" {
			return nil, pin, ErrSource
		}
		commit, err = execx.LocalGitCommit(ctx, clone, ref)
		if err != nil {
			return nil, pin, ErrSource
		}
	}
	pin = d.SourcePin{Qualification: "local-observed", Repo: r.alias, Path: r.entry.Path, Commit: commit, ManifestSHA256: "sha256:" + strings.Repeat("0", 64)}
	if !pin.Valid() {
		return nil, pin, ErrSource
	}
	b, err := blob(ctx, clone, commit, path.Join(r.entry.Path, "template.manifest.yaml"))
	if err != nil {
		return nil, pin, err
	}
	tpl, err := manifest.ParseTemplate(b)
	if err != nil || tpl.Metadata.Name != r.entry.Name {
		return nil, pin, ErrMetadata
	}
	pin.ManifestSHA256 = d.Digest(b)
	return tpl, pin, nil
}
func declared(tpl *manifest.Template, pin d.SourcePin) (d.Candidate, error) {
	c := d.Candidate{SourcePin: pin, MetadataSHA256: pin.ManifestSHA256, Name: tpl.Metadata.Name, Version: tpl.Metadata.Version, Description: tpl.Metadata.Description, Labels: tpl.Metadata.Labels, CandidateKind: d.KindTemplate, Readiness: d.Unknown, Blocks: []d.Reference{}, Skills: []d.Reference{}}
	single := func(key string) (string, error) {
		v := c.Labels[key]
		if len(v) == 0 {
			return "", nil
		}
		if len(v) != 1 {
			return "", ErrMetadata
		}
		return v[0], nil
	}
	kind, err := single("candidate-kind")
	if err != nil {
		return c, err
	}
	if kind != "" {
		c.CandidateKind = d.Kind(kind)
	}
	readiness, err := single("readiness")
	if err != nil {
		return c, err
	}
	if readiness != "" {
		c.Readiness = d.Readiness(readiness)
	}
	references := func(key string, defaultKind d.Kind) ([]d.Reference, error) {
		out := []d.Reference{}
		known := map[string]bool{}
		kinds := map[string]d.Kind{}
		ready := map[string]d.Readiness{}
		for _, id := range c.Labels[key] {
			if id == "" || known[id] {
				return nil, ErrMetadata
			}
			known[id] = true
		}
		singular := "block"
		if key == "skills" {
			singular = "skill"
		}
		for _, v := range c.Labels[singular+"-kind"] {
			id, k, ok := strings.Cut(v, "=")
			if !ok || !known[id] || kinds[id] != "" || !d.Kind(k).Valid() {
				return nil, ErrMetadata
			}
			kinds[id] = d.Kind(k)
		}
		for _, v := range c.Labels[singular+"-readiness"] {
			id, k, ok := strings.Cut(v, "=")
			if !ok || !known[id] || ready[id] != "" || !d.Readiness(k).Valid() {
				return nil, ErrMetadata
			}
			ready[id] = d.Readiness(k)
		}
		for _, id := range c.Labels[key] {
			k := kinds[id]
			if k == "" {
				k = defaultKind
			}
			r := ready[id]
			if r == "" {
				r = d.Unknown
			}
			out = append(out, d.Reference{ID: id, SourcePin: pin, CandidateKind: k, Readiness: r, DeclarationStatus: "metadata-declared", Availability: "metadata-declared"})
		}
		return out, nil
	}
	c.Blocks, err = references("blocks", d.KindUnknown)
	if err != nil {
		return c, err
	}
	c.Skills, err = references("skills", d.KindSkill)
	if err != nil {
		return c, err
	}
	c, err = d.Identify(c)
	if err != nil {
		return c, ErrMetadata
	}
	return c, nil
}

// Discover reads only existing cache objects. A missing home or empty project
// produces an explicit bounded result and does not create a state skeleton.
func Discover(ctx context.Context, home, dir string, q d.Query) (d.Result, error) {
	q, err := d.Normalize(q)
	if err != nil {
		return d.Result{}, err
	}
	if dir != "" {
		q.Facts = ObserveProject(dir)
	}
	idx, err := index(home)
	if err != nil {
		return unavailable(q, "source_unavailable", "index")
	}
	rr, err := rows(idx)
	if err != nil {
		return unavailable(q, "budget_exhausted", "index")
	}
	truncated := false
	attempted := 0
	input := []d.Candidate{}
	failures := []d.Diagnostic{}
	for _, r := range rr {
		if ctx.Err() != nil {
			failures = append(failures, d.Diagnostic{Code: "budget_exhausted", Field: "time"})
			truncated = true
			break
		}
		attempted++
		tpl, pin, e := selection(ctx, home, r, "")
		if e != nil {
			code := "source_unavailable"
			if errors.Is(e, ErrMetadata) {
				code = "metadata_invalid"
			}
			if len(failures) < 16 {
				failures = append(failures, d.Diagnostic{Code: code, Field: "manifest"})
			}
			continue
		}
		c, e := declared(tpl, pin)
		if e != nil {
			if len(failures) < 16 {
				failures = append(failures, d.Diagnostic{Code: "metadata_invalid", Field: "declarations"})
			}
			continue
		}
		input = append(input, c)
	}
	result, err := d.Rank(q, input)
	if err != nil {
		return result, err
	}
	result.Budget.Considered = attempted
	result.Budget.Truncated = result.Budget.Truncated || truncated
	result.Diagnostics = append(failures, result.Diagnostics...)
	return d.Fit(result, q.MaxBytes)
}
func unavailable(q d.Query, code, field string) (d.Result, error) {
	r, err := d.Rank(q, nil)
	if err != nil {
		return r, err
	}
	r.Diagnostics = []d.Diagnostic{{Code: code, Field: field}}
	return d.Fit(r, q.MaxBytes)
}

// Show consumes an exact source receipt, not a movable version ref. It creates
// neither a checkout nor an authenticated trust resolution.
func Show(ctx context.Context, home, ref, commit, rawSHA string) (*manifest.Template, string, error) {
	if strings.Contains(ref, "@") || strings.Count(ref, "/") != 1 {
		return nil, "", ErrSource
	}
	alias, name, _ := strings.Cut(ref, "/")
	idx, err := index(home)
	if err != nil {
		return nil, "", err
	}
	rr, err := rows(idx)
	if err != nil {
		return nil, "", err
	}
	var selected *row
	for _, r := range rr {
		if r.alias == alias && r.entry.Name == name {
			if selected != nil {
				return nil, "", ErrSource
			}
			copy := r
			selected = &copy
		}
	}
	if selected == nil {
		return nil, "", ErrSource
	}
	tpl, pin, err := selection(ctx, home, *selected, commit)
	if err != nil || commit == "" || pin.ManifestSHA256 != rawSHA {
		return nil, "", ErrSource
	}
	return tpl, alias, nil
}

// ObserveProject reads a finite list of confined regular files. Descriptions,
// error messages and filesystem names never become settings or source grants.
func ObserveProject(dir string) d.ProjectFacts {
	facts := d.ProjectFacts{Status: "empty", Frameworks: []string{}, Evidence: []d.FactEvidence{}}
	root, err := os.OpenRoot(dir)
	if err != nil {
		facts.Status = "unavailable"
		return facts
	}
	defer root.Close()
	for _, name := range []string{"go.mod", "package.json", "Cargo.toml", ".tplaiter/project.yaml"} {
		b, err := bounded(root, name, 65536)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			facts.Status = "unavailable"
			return facts
		}
		facts.Status = "observed"
		facts.Evidence = append(facts.Evidence, d.FactEvidence{Path: name, SHA256: d.Digest(b)})
		switch name {
		case "go.mod":
			module, err := modfile.Parse("go.mod", b, nil)
			if err != nil || module.Module == nil || module.Module.Mod.Path == "" {
				facts.Status = "unavailable"
				return facts
			}
			facts.Language = "go"
			for _, req := range module.Require {
				if req.Mod.Path == "go.temporal.io/sdk" {
					facts.Frameworks = append(facts.Frameworks, "temporal")
				}
			}
		case "package.json":
			var pkg struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			}
			var object map[string]json.RawMessage
			if json.Unmarshal(b, &object) != nil || object == nil || json.Unmarshal(b, &pkg) != nil {
				facts.Status = "unavailable"
				return facts
			}
			if facts.Language != "" && facts.Language != "javascript" {
				facts.Status = "unavailable"
				return facts
			}
			facts.Language = "javascript"
			if pkg.Dependencies["typescript"] != "" || pkg.DevDependencies["typescript"] != "" {
				facts.Language = "typescript"
			}
			if pkg.Dependencies["react"] != "" || pkg.DevDependencies["react"] != "" {
				facts.Frameworks = append(facts.Frameworks, "react")
			}
			if pkg.Dependencies["next"] != "" || pkg.DevDependencies["next"] != "" {
				facts.Frameworks = append(facts.Frameworks, "next")
			}
			if pkg.Dependencies["react-router"] != "" || pkg.DevDependencies["react-router"] != "" || pkg.Dependencies["react-router-dom"] != "" || pkg.DevDependencies["react-router-dom"] != "" {
				facts.Frameworks = append(facts.Frameworks, "react-router")
			}

		case "Cargo.toml":
			// No TOML parser is installed in this module. Report the actual fixed
			// file receipt as unavailable instead of calling an existing Rust
			// project empty or inventing language/framework facts from its name.
			facts.Status = "unavailable"
			return facts
		case ".tplaiter/project.yaml":
			// Native New writes the existing ledger-backed v2 marker. Observe its
			// closed typed data without following ledger pointers or treating an
			// observed marker as authenticated project/source authority.
			var header struct {
				APIVersion string `yaml:"apiVersion"`
			}
			if yaml.Unmarshal(b, &header) != nil {
				facts.Status = "unavailable"
				return facts
			}
			decoder := yaml.NewDecoder(bytes.NewReader(b))
			decoder.KnownFields(true)
			switch header.APIVersion {
			case manifest.APIVersion:
				var marker manifest.Project
				if decoder.Decode(&marker) != nil || decoder.Decode(new(any)) != io.EOF || marker.Kind != manifest.KindProject {
					facts.Status = "unavailable"
					return facts
				}
				facts.Template = marker.Template.Repo + "/" + marker.Template.Name + "@" + marker.Template.Version
			case stateledger.ProjectV2APIVersion:
				var marker stateledger.ProjectV2
				if decoder.Decode(&marker) != nil || decoder.Decode(new(any)) != io.EOF || marker.Kind != manifest.KindProject || marker.ID == "" || strings.ContainsAny(marker.ID, " \t\r\n/\\\x00") || marker.Template.Repo == "" || marker.Template.Name == "" || marker.Template.RequestedRef == "" || !observedCommit(marker.Template.ResolvedCommit) || marker.Project == nil || marker.Answers == nil || marker.State != stateledger.StandardPointers() {
					facts.Status = "unavailable"
					return facts
				}
				facts.Template = marker.Template.Repo + "/" + marker.Template.Name + "@" + marker.Template.ResolvedCommit
			default:
				facts.Status = "unavailable"
				return facts
			}
		}
	}
	sort.Strings(facts.Frameworks)
	return facts
}

func observedCommit(s string) bool {
	return (len(s) == 40 || len(s) == 64) && strings.Trim(s, "0123456789abcdef") == ""
}
