package resources

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing/fstest"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	// NativeResourceLockPath is committed with the resource bytes, never afterwards.
	NativeResourceLockPath = ".tplaiter/resources.lock.json"
	nativeGeneratorPrefix  = ".tplaiter/generators/"
	maxNativeResources     = 256
	maxNativeResourceBytes = 1 << 20
	maxNativeResourceTotal = 16 << 20
)

// ResourceArtifact separates source provenance from the ownership inventory.
type ResourceArtifact struct {
	Path       string                 `json:"path"`
	SourcePath string                 `json:"sourcePath"`
	SHA256     string                 `json:"sha256"`
	Mode       uint32                 `json:"mode"`
	Source     provenance.RootSubject `json:"source"`
	Provider   trustverify.Provider   `json:"provider"`
}

// ResourceLockV2 binds inert images to the authenticated root lock and profile.
type ResourceLockV2 struct {
	Version        int                      `json:"version"`
	RootLockSHA256 string                   `json:"rootLockSHA256"`
	TrustProfile   bootstrap.ProfileBinding `json:"trustProfile"`
	Artifacts      []ResourceArtifact       `json:"artifacts"`
}

// ResourceImages contains exact inert bytes, with no execution or write method.
type ResourceImages struct {
	Files map[string][]byte
	Lock  ResourceLockV2
}

// retainedSnapshotFS exposes only Open over private copies of verified blobs.
// No checkout root, mutable MapFS or caller-supplied reader escapes this boundary.
type retainedSnapshotFS struct{ files fstest.MapFS }

func (s retainedSnapshotFS) Open(name string) (fs.File, error) { return s.files.Open(name) }

func retainSnapshot(snapshot *trustverify.SourceSnapshot) (retainedSnapshotFS, error) {
	if snapshot == nil {
		return retainedSnapshotFS{}, operationtrust.ErrSourceAdapterUnsupported
	}
	files := make(fstest.MapFS)
	for _, e := range snapshot.Entries() {
		if !fs.ValidPath(e.Path) || e.Path == "." {
			return retainedSnapshotFS{}, operationtrust.ErrSourceAdapterUnsupported
		}
		if e.Kind == "directory" && e.Mode == "40000" {
			continue
		}
		if e.Kind != "file" || (e.Mode != "100644" && e.Mode != "100755") {
			return retainedSnapshotFS{}, operationtrust.ErrSourceAdapterUnsupported
		}
		b, ok := snapshot.Blob(e.Path)
		if !ok || evidencecas.Digest(b) != e.ContentSHA256 {
			return retainedSnapshotFS{}, operationtrust.ErrSourceAdapterUnsupported
		}
		mode := fs.FileMode(0o444)
		if e.Mode == "100755" {
			mode = 0o555
		}
		files[e.Path] = &fstest.MapFile{Data: b, Mode: mode}
	}
	return retainedSnapshotFS{files}, nil
}

// ValidateNativeGenerators validates the complete inert native declaration gate.
// This pure validator confers no authority; the enrollment owner verifies the
// snapshot first. Directories and executable snippets are explicitly unsupported.
func ValidateNativeGenerators(snapshot *trustverify.SourceSnapshot) error {
	_, err := nativeGeneratorFiles(snapshot)
	return err
}

func nativeGeneratorFiles(snapshot *trustverify.SourceSnapshot) (map[string][]byte, error) {
	src, err := retainSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	// Both locator and raw manifest pin come from the retained contract, not args.
	manifestRaw, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil || len(manifestRaw) > maxNativeResourceBytes {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	contract, err := operationtrust.DecodeNativeContract(snapshot.ContractBytes(), manifestRaw)
	if err != nil {
		return nil, err
	}
	return nativeGeneratorContent(snapshot, src, contract.ManifestPath)
}

// ValidateNativeGeneratorsV2 validates retained v2 source declarations without
// conferring source admission, a runtime capability or execution permission.
func ValidateNativeGeneratorsV2(snapshot *trustverify.SourceSnapshot) error {
	src, err := retainSnapshot(snapshot)
	if err != nil {
		return err
	}
	raw, err := fs.ReadFile(src, "template.manifest.yaml")
	if err != nil || len(raw) > maxNativeResourceBytes {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	contract, err := contextsource.DecodeNativeContextContractV2(snapshot.ContractBytes(), raw)
	if err != nil {
		return err
	}
	_, err = nativeGeneratorContent(snapshot, src, contract.ManifestPath)
	return err
}

func nativeGeneratorContent(snapshot *trustverify.SourceSnapshot, src retainedSnapshotFS, manifestPath string) (map[string][]byte, error) {
	manifestRaw, err := fs.ReadFile(src, manifestPath)
	if err != nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if err := nativeManifestShape(manifestRaw); err != nil {
		return nil, err
	}
	tpl, err := manifest.ParseTemplate(manifestRaw)
	if err != nil || tpl.Validate() != nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || operationtrust.ValidateBoundNativeCommands(snapshot, tpl) != nil || tpl.AIConfig.Path != "" {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	refs := make(map[string]string)
	add := func(ref string) error {
		if !nativeResourcePath(ref) {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		folded := strings.ToLower(ref)
		if prior, ok := refs[folded]; ok && prior != ref {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		refs[folded] = ref
		if len(refs) > maxNativeResources {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		return nil
	}
	if len(tpl.Generators) > maxNativeResources {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	count := 0
	for _, g := range tpl.Generators {
		if g.Target != "" && !nativeTargetPath(g.Target) {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
		count += len(g.Targets) + len(g.Anchors) + 1
		if count > maxNativeResources {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
		if g.Snippet != "" {
			if err := add(g.Snippet); err != nil {
				return nil, err
			}
		}
		for _, target := range g.Targets {
			if !nativeTargetPath(target.Target) {
				return nil, operationtrust.ErrSourceAdapterUnsupported
			}
			if err := add(target.Snippet); err != nil {
				return nil, err
			}
		}
		for _, anchor := range g.Anchors {
			if !nativeResourcePath(anchor.File) || strings.TrimSpace(anchor.Anchor) == "" || len(anchor.Anchor) > 1024 || strings.ContainsRune(anchor.Anchor, 0) {
				return nil, operationtrust.ErrSourceAdapterUnsupported
			}
			if err := add(anchor.Insert); err != nil {
				return nil, err
			}
		}
	}
	files := make(map[string][]byte, len(refs))
	total := 0
	for _, ref := range refs {
		stat, err := fs.Stat(src, ref)
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o444 || stat.Size() > maxNativeResourceBytes {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
		total += int(stat.Size())
		if total > maxNativeResourceTotal {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
		b, err := fs.ReadFile(src, ref)
		if err != nil || bytes.Contains(b, []byte("tplater:managed-")) {
			return nil, operationtrust.ErrSourceAdapterUnsupported
		}
		files[nativeGeneratorPrefix+ref] = b
	}
	// File/directory and case-folded ancestor collisions cannot reach publication.
	if !nativeImagePaths(files) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	return files, nil
}

// PlanNativeGeneratorImages accepts an actual runtime capability, never a
// trusted boolean. It derives subject, evidence and parser inputs from that
// capability and compares every binding field with the prepared root lock.
func PlanNativeGeneratorImages(runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution, root provenance.RootTemplateLock) (*ResourceImages, error) {
	if runtime == nil || resolution == nil || !resolution.ValidFor(runtime, runtime.Binding()) || root.Validate() != nil || !root.TrustProfile.Equal(runtime.Binding()) {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	snapshot, err := runtime.VerifiedSnapshot(resolution)
	if err != nil {
		return nil, err
	}
	e := resolution.Evidence()
	source := provenance.RootSubjectFromTrust(resolution.Subject(), bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}, e.CheckpointCAS, e.InclusionProofCAS)
	if root.Root != source {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	files, err := nativeGeneratorFiles(snapshot)
	if err != nil {
		return nil, err
	}
	lock := ResourceLockV2{Version: 2, RootLockSHA256: root.RootLockSHA256, TrustProfile: root.TrustProfile, Artifacts: []ResourceArtifact{}}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		lock.Artifacts = append(lock.Artifacts, ResourceArtifact{Path: p, SourcePath: strings.TrimPrefix(p, nativeGeneratorPrefix), SHA256: evidencecas.Digest(files[p]), Mode: 0o644, Source: source, Provider: nativeProvider(source)})
	}
	images := &ResourceImages{Files: files, Lock: lock}
	if err := images.Validate(root); err != nil {
		return nil, err
	}
	return images, nil
}

// DecodeResourceLockV2 is closed and bounded. Historical empty, unbound locks
// remain readable by legacy consumers, but cannot authenticate native images.
func DecodeResourceLockV2(raw []byte) (*ResourceLockV2, error) {
	var lock ResourceLockV2
	if len(raw) == 0 || len(raw) > maxNativeResourceTotal || canonicaljson.DecodeStrict(raw, &lock) != nil || lock.Version != 2 || lock.Artifacts == nil || len(lock.Artifacts) > maxNativeResources || lock.TrustProfile.Validate() != nil || !nativeDigest(lock.RootLockSHA256) {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	if lock.validateSchema() != nil {
		return nil, operationtrust.ErrSourceAdapterUnsupported
	}
	return &lock, nil
}

// Validate checks the complete lock/image/root pair before transaction sealing.
func (images *ResourceImages) Validate(root provenance.RootTemplateLock) error {
	if images == nil || root.Validate() != nil {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	l := images.Lock
	if l.validateSchema() != nil || l.Version != 2 || l.Artifacts == nil || len(l.Artifacts) > maxNativeResources || len(l.Artifacts) != len(images.Files) || l.RootLockSHA256 != root.RootLockSHA256 || !l.TrustProfile.Equal(root.TrustProfile) || !nativeImagePaths(images.Files) {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	last, total := "", 0
	for _, a := range l.Artifacts {
		b, exists := images.Files[a.Path]
		if !exists || !nativeResourcePath(a.SourcePath) || a.Path != nativeGeneratorPrefix+a.SourcePath || a.Path <= last || a.Mode != 0o644 || a.Source != root.Root || a.Provider != nativeProvider(root.Root) || a.SHA256 != evidencecas.Digest(b) || len(b) > maxNativeResourceBytes {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		total += len(b)
		if total > maxNativeResourceTotal {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		last = a.Path
	}
	return nil
}

func nativeProvider(s provenance.RootSubject) trustverify.Provider {
	return trustverify.Provider{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}
}

func nativeDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, c := range s[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func nativeResourcePath(p string) bool {
	if !fs.ValidPath(p) || p == "." || len(p) > 1024 || strings.Count(p, "/") >= 64 {
		return false
	}
	for _, c := range p {
		if c < 0x21 || c > 0x7e || c == '\\' || c == ':' {
			return false
		}
	}
	for _, part := range strings.Split(p, "/") {
		folded := strings.ToLower(part)
		if len(part) > 255 || strings.HasSuffix(part, ".") || folded == ".git" || folded == ".tplaiter" || folded == ".tplater" {
			return false
		}
	}
	return true
}

func nativeImagePaths(files map[string][]byte) bool {
	nodes := make(map[string]string, len(files))
	filePaths := make(map[string]bool, len(files))
	for p := range files {
		if !strings.HasPrefix(p, nativeGeneratorPrefix) || !nativeResourcePath(strings.TrimPrefix(p, nativeGeneratorPrefix)) {
			return false
		}
		filePaths[strings.ToLower(p)] = true
		for n := p; n != "."; n = path.Dir(n) {
			folded := strings.ToLower(n)
			if prior, ok := nodes[folded]; ok && prior != n {
				return false
			}
			nodes[folded] = n
		}
	}
	for p := range filePaths {
		for parent := path.Dir(p); parent != "."; parent = path.Dir(parent) {
			if filePaths[parent] {
				return false
			}
		}
	}
	return true
}

func (l ResourceLockV2) validateSchema() error {
	if l.Version != 2 || l.Artifacts == nil || len(l.Artifacts) > maxNativeResources || !nativeDigest(l.RootLockSHA256) || l.TrustProfile.Validate() != nil {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	files := make(map[string][]byte, len(l.Artifacts))
	last := ""
	for _, a := range l.Artifacts {
		if !nativeResourcePath(a.SourcePath) || a.Path != nativeGeneratorPrefix+a.SourcePath || a.Path <= last || a.Mode != 0o644 || !nativeDigest(a.SHA256) || a.Source.Validate() != nil || a.Provider != nativeProvider(a.Source) {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		files[a.Path] = nil
		last = a.Path
	}
	if !nativeImagePaths(files) {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	return nil
}

var nativeTargetExpression = regexp.MustCompile(`{{[^{}]+}}`)

func nativeTargetPath(p string) bool {
	return nativeResourcePath(nativeTargetExpression.ReplaceAllString(p, "name")) && !strings.ContainsAny(nativeTargetExpression.ReplaceAllString(p, "name"), "{}")
}

func nativeManifestShape(raw []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil || len(doc.Content) != 1 {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return operationtrust.ErrSourceAdapterUnsupported
	}
	var walk func(*yaml.Node) error
	walk = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
			return operationtrust.ErrSourceAdapterUnsupported
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				key := n.Content[i]
				folded := strings.ToLower(key.Value)
				if key.Kind != yaml.ScalarNode || key.Value == "<<" || seen[folded] {
					return operationtrust.ErrSourceAdapterUnsupported
				}
				seen[folded] = true
			}
		}
		for _, child := range n.Content {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(doc.Content[0])
}
