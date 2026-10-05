package naming

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
)

const algorithm = "tplaiter.naming-migration/v1"

// supportedLegacyWriter is a compiled-in capability, not a CLI assertion. It
// identifies the frozen legacy executable exercised against the tombstone
// adapter. Other legacy formats must be rejected before planning writes.
const supportedLegacyWriter = "tplater-8356cc1d9c066af0253bff9d3f50fc28c51863d0"

var legacyTombstone = []byte("tplaiter migration tombstone\n")

// Root names a classified state ledger. Apply refuses unclassified roots.
type Root struct {
	Kind              string  `json:"kind"`
	SourceRoot        string  `json:"sourceRoot"`
	DestinationRoot   string  `json:"destinationRoot"`
	ArchiveRoot       string  `json:"archiveRoot,omitempty"`
	Entries           []Entry `json:"entries"`
	SourceDigest      string  `json:"sourceDigest"`
	DestinationDigest string  `json:"destinationDigest"`
	// Relocations belong to the home ledger: projects.yaml is authoritative
	// home state, so it must not be captured again as an overlapping root.
	// Each declaration is bound to a separately captured project marker.
	Relocations []Relocation `json:"relocations,omitempty"`
}

// Relocation is an explicit, sealed request to change one authoritative
// projects.yaml path. ID, oldPath and the paired project preimage prevent a
// registry entry from being retargeted merely because a directory happens to
// have a similar name.
type Relocation struct {
	ID                  string `json:"id"`
	OldPath             string `json:"oldPath"`
	NewPath             string `json:"newPath"`
	ProjectMarkerDigest string `json:"projectMarkerDigest"`
}
type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Bytes  []byte `json:"bytes"`
	Digest string `json:"digest"`
}
type Plan struct {
	Schema      string `json:"schema"`
	Algorithm   string `json:"algorithm"`
	Profile     string `json:"profile"`
	WriterFloor string `json:"writerFloor"`
	Roots       []Root `json:"roots"`
	Digest      string `json:"digest"`
	// R0 one-root projections remain verifiable and must agree with Roots[0].
	SourceRoot      string  `json:"sourceRoot,omitempty"`
	DestinationRoot string  `json:"destinationRoot,omitempty"`
	Entries         []Entry `json:"entries,omitempty"`
	SourceDigest    string  `json:"sourceDigest,omitempty"`
}
type Receipt struct {
	Schema            string `json:"schema"`
	Algorithm         string `json:"algorithm"`
	PlanDigest        string `json:"planDigest"`
	SourceRoot        string `json:"sourceRoot"`
	DestinationRoot   string `json:"destinationRoot"`
	SourceDigest      string `json:"sourceDigest"`
	DestinationDigest string `json:"destinationDigest"`
	TransactionID     string `json:"transactionId"`
	CommittedAt       string `json:"committedAt"`
	Roots             []Root `json:"roots,omitempty"`
}
type journal struct {
	Plan   Plan     `json:"plan"`
	Phase  string   `json:"phase"`
	Stages []string `json:"stages"`
}

func digestBytes(domain string, v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	_, _ = io.WriteString(h, domain)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p Plan) seal() (Plan, error) {
	p.Digest = ""
	d, e := digestBytes(PlanSchema, p)
	p.Digest = d
	return p, e
}

func (p Plan) normalizedRoots() ([]Root, error) {
	if len(p.Roots) == 0 && p.SourceRoot != "" {
		return []Root{{Kind: "home", SourceRoot: p.SourceRoot, DestinationRoot: p.DestinationRoot, Entries: p.Entries, SourceDigest: p.SourceDigest}}, nil
	}
	if len(p.Roots) == 0 {
		return nil, errors.New("naming: plan has no roots")
	}
	if p.SourceRoot != "" && (p.SourceRoot != p.Roots[0].SourceRoot || p.DestinationRoot != p.Roots[0].DestinationRoot || p.SourceDigest != p.Roots[0].SourceDigest) {
		return nil, errors.New("naming: legacy root projection disagrees")
	}
	return p.Roots, nil
}

func (p Plan) Verify() error {
	if p.Schema != PlanSchema || p.Algorithm != algorithm || p.Profile != "oss" || p.WriterFloor != supportedLegacyWriter || p.Digest == "" {
		return errors.New("naming: invalid plan identity")
	}
	q := p
	q.Digest = ""
	d, e := digestBytes(PlanSchema, q)
	if e != nil || d != p.Digest {
		return errors.New("naming: plan digest mismatch")
	}
	roots, e := p.normalizedRoots()
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if !supportedRootKind(r.Kind) {
			return fmt.Errorf("naming: unsupported root kind %q", r.Kind)
		}
		if !canonicalAbsolute(r.SourceRoot) || !canonicalAbsolute(r.DestinationRoot) || r.SourceRoot == r.DestinationRoot || seen[r.Kind] {
			return errors.New("naming: unsafe root ledger")
		}
		if r.Kind == "project" && !validProjectRoots(r.SourceRoot, r.DestinationRoot) {
			return errors.New("naming: project roots must be sibling .tplater and .tplaiter directories")
		}
		seen[r.Kind] = true
		if e := validateEntries(r.Entries); e != nil {
			return e
		}
		if err := refuseNativeEntries(r); err != nil {
			return err
		}
		d, e := digestBytes("tplaiter.dev/naming-source/v1", r.Entries)
		if e != nil || d != r.SourceDigest {
			return fmt.Errorf("naming: source digest mismatch for %s", r.Kind)
		}
		if err := verifyLegacyFormat(r); err != nil {
			return err
		}
		after, err := destinationEntries(r)
		if err != nil {
			return err
		}
		afterDigest, err := digestBytes("tplaiter.dev/naming-source/v1", after)
		if err != nil || afterDigest != r.DestinationDigest {
			return fmt.Errorf("naming: destination digest mismatch for %s", r.Kind)
		}
	}
	if err := verifyRelocations(roots); err != nil {
		return err
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if rootsOverlap(roots[i].SourceRoot, roots[j].SourceRoot) || rootsOverlap(roots[i].DestinationRoot, roots[j].DestinationRoot) || rootsOverlap(roots[i].SourceRoot, roots[j].DestinationRoot) || rootsOverlap(roots[i].DestinationRoot, roots[j].SourceRoot) {
				return fmt.Errorf("naming: overlapping root ledgers %s and %s", roots[i].Kind, roots[j].Kind)
			}
		}
	}
	return nil
}

func validateEntries(es []Entry) error {
	seen := map[string]bool{}
	for _, e := range es {
		if e.Path == "" || filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path || e.Path == "." || strings.HasPrefix(e.Path, ".."+string(filepath.Separator)) || strings.Contains(e.Path, "\x00") {
			return fmt.Errorf("naming: unsafe entry path %q", e.Path)
		}
		if seen[e.Path] {
			return fmt.Errorf("naming: duplicate entry %q", e.Path)
		}
		seen[e.Path] = true
		if credentialPath(e.Path) {
			return errors.New("naming: credential capability is excluded")
		}
		h := sha256.Sum256(e.Bytes)
		if hex.EncodeToString(h[:]) != e.Digest {
			return fmt.Errorf("naming: entry digest mismatch for %s", e.Path)
		}
	}
	return nil
}

func credentialPath(path string) bool {
	switch strings.ToLower(filepath.Base(path)) {
	case "tplater.db", "auth.json", "credentials.json", "credentials.db":
		return true
	}
	return false
}

// PlanRoots is pure with respect to destinations. Credential filenames are
// rejected before any ReadFile call; generic migration has no credential capability.
func PlanRoots(roots []Root) (Plan, error) {
	if len(roots) == 0 {
		return Plan{}, errors.New("naming: no roots requested")
	}
	for i := range roots {
		r := &roots[i]
		if !canonicalAbsolute(r.SourceRoot) || !canonicalAbsolute(r.DestinationRoot) {
			return Plan{}, errors.New("naming: roots must be canonical absolute paths")
		}
		if r.SourceRoot == r.DestinationRoot {
			return Plan{}, errors.New("naming: source and destination are identical")
		}
		if !supportedRootKind(r.Kind) {
			return Plan{}, fmt.Errorf("naming: unsupported root kind %q", r.Kind)
		}
		if r.Kind == "project" && !validProjectRoots(r.SourceRoot, r.DestinationRoot) {
			return Plan{}, errors.New("naming: project roots must be sibling .tplater and .tplaiter directories")
		}
		if e := activeTransaction(r.SourceRoot); e != nil {
			return Plan{}, e
		}
		es, e := capture(r.SourceRoot)
		if e != nil {
			return Plan{}, e
		}
		r.Entries = es
		r.SourceDigest, e = digestBytes("tplaiter.dev/naming-source/v1", es)
		if e != nil {
			return Plan{}, e
		}
		if e := verifyLegacyFormat(*r); e != nil {
			return Plan{}, e
		}
	}
	if err := bindRelocations(roots); err != nil {
		return Plan{}, err
	}
	if err := verifyRelocations(roots); err != nil {
		return Plan{}, err
	}
	for i := range roots {
		after, err := destinationEntries(roots[i])
		if err != nil {
			return Plan{}, err
		}
		roots[i].DestinationDigest, err = digestBytes("tplaiter.dev/naming-source/v1", after)
		if err != nil {
			return Plan{}, err
		}
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if rootsOverlap(roots[i].SourceRoot, roots[j].SourceRoot) || rootsOverlap(roots[i].DestinationRoot, roots[j].DestinationRoot) || rootsOverlap(roots[i].SourceRoot, roots[j].DestinationRoot) || rootsOverlap(roots[i].DestinationRoot, roots[j].SourceRoot) { //nolint:gosec // false positive: i < j < len(roots)
				return Plan{}, fmt.Errorf("naming: overlapping root ledgers %s and %s", roots[i].Kind, roots[j].Kind) //nolint:gosec // false positive: i < j < len(roots)
			}
		}
	}
	p := Plan{Schema: PlanSchema, Algorithm: algorithm, Profile: "oss", WriterFloor: supportedLegacyWriter, Roots: roots}
	p.SourceRoot, p.DestinationRoot, p.Entries, p.SourceDigest = roots[0].SourceRoot, roots[0].DestinationRoot, roots[0].Entries, roots[0].SourceDigest
	return p.seal()
}

func supportedRootKind(kind string) bool { return kind == "home" || kind == "project" }

// validProjectRoots makes the migration unit explicit: the roots are marker
// directories under the same project root, not arbitrary directories.
func validProjectRoots(source, destination string) bool {
	return filepath.Base(source) == LegacyProjectDir &&
		filepath.Base(destination) == ProjectDir &&
		filepath.Dir(source) == filepath.Dir(destination)
}

func canonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

// verifyLegacyFormat is the narrow adapter gate for the frozen legacy writer.
// It is deliberately based on the on-disk schema markers, never a caller flag.
func verifyLegacyFormat(r Root) error {
	var marker string
	switch r.Kind {
	case "home":
		marker = "state.yaml"
	case "project":
		marker = "project.yaml"
	default:
		return fmt.Errorf("naming: unsupported root kind %q", r.Kind)
	}
	if r.Kind == "home" {
		seenProjects := false
		for _, e := range r.Entries {
			if e.Path == "projects.yaml" {
				seenProjects = true
				if _, err := decodeLegacyProjects(e.Bytes); err != nil {
					return fmt.Errorf("naming: unsupported projects registry: %w", err)
				}
			}
			if e.Path == "config.yaml" {
				var config legacyConfig
				if err := decodeLegacyYAML(e.Bytes, &config); err != nil || config.Version != 1 {
					return errors.New("naming: unsupported home config format")
				}
			}
		}
		if len(r.Relocations) != 0 && !seenProjects {
			return errors.New("naming: relocation requires projects.yaml")
		}
	}
	for _, e := range r.Entries {
		if e.Path != marker {
			continue
		}
		if r.Kind == "home" {
			var state legacyRunState
			if err := decodeLegacyYAML(e.Bytes, &state); err != nil || state.Version != 1 {
				return errors.New("naming: unsupported home legacy format")
			}
		}
		if r.Kind == "project" {
			var project legacyProject
			if err := decodeLegacyYAML(e.Bytes, &project); err != nil || project.APIVersion != "tplater.dev/v1alpha1" || project.Kind != "Project" {
				return errors.New("naming: unsupported project legacy format")
			}
			if project.Baseline != ".tplater/baseline.json" {
				return errors.New("naming: unsupported project baseline path")
			}
			for _, baseline := range r.Entries {
				if baseline.Path == "baseline.json" {
					return nil
				}
			}
			return errors.New("naming: unsupported project legacy format: missing baseline.json")
		}
		return nil
	}
	return fmt.Errorf("naming: unsupported %s legacy format: missing %s", r.Kind, marker)
}

type legacyRunState struct {
	Version         int       `yaml:"version"`
	LastUpdateCheck time.Time `yaml:"lastUpdateCheck"`
}
type legacyConfig struct {
	Version int `yaml:"version"`
	Repos   []struct {
		Alias  string `yaml:"alias"`
		URL    string `yaml:"url"`
		Branch string `yaml:"branch,omitempty"`
		Type   string `yaml:"type"`
	} `yaml:"repos"`
	Defaults struct{} `yaml:"defaults"`
	Updates  struct {
		Check bool `yaml:"check"`
	} `yaml:"updates"`
}
type legacyProjects struct {
	Version int                `yaml:"version"`
	Items   []legacyProjectRef `yaml:"items"`
}
type legacyProjectRef struct {
	ID          string                `yaml:"id"`
	Path        string                `yaml:"path"`
	Template    legacyProjectTemplate `yaml:"template"`
	CreatedAt   time.Time             `yaml:"createdAt"`
	LastSeenAt  time.Time             `yaml:"lastSeenAt"`
	BaselineSHA string                `yaml:"baselineSHA"`
}

func decodeLegacyProjects(b []byte) (legacyProjects, error) {
	var projects legacyProjects
	if err := decodeLegacyYAML(b, &projects); err != nil {
		return legacyProjects{}, err
	}
	if projects.Version != 1 {
		return legacyProjects{}, errors.New("unsupported projects version")
	}
	ids := map[string]bool{}
	for _, item := range projects.Items {
		if item.ID == "" || item.Path == "" || ids[item.ID] {
			return legacyProjects{}, errors.New("invalid or duplicate project registry id")
		}
		ids[item.ID] = true
	}
	return projects, nil
}

type legacyProject struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	ID         string                `yaml:"id"`
	Template   legacyProjectTemplate `yaml:"template"`
	Project    legacyProjectInfo     `yaml:"project"`
	Settings   map[string]any        `yaml:"settings"`
	Runtime    legacyProjectRuntime  `yaml:"runtime"`
	Baseline   string                `yaml:"baseline"`
}

type legacyProjectTemplate struct {
	Repo    string `yaml:"repo"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type legacyProjectInfo struct {
	Name   string `yaml:"name"`
	Slug   string `yaml:"slug"`
	Module string `yaml:"module"`
	System string `yaml:"system"`
	Domain string `yaml:"domain"`
}

type legacyProjectRuntime struct {
	Port int `yaml:"port"`
}

func decodeLegacyYAML(b []byte, out any) error {
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple legacy YAML documents")
		}
		return err
	}
	return nil
}

// bindRelocations fills the marker digest only from the captured project
// entry. Callers declare identities and paths; they cannot invent proof.
func bindRelocations(roots []Root) error {
	var home *Root
	projects := map[string]Root{}
	for i := range roots {
		if roots[i].Kind == "home" {
			home = &roots[i]
		}
		if roots[i].Kind == "project" {
			projects[filepath.Clean(roots[i].SourceRoot)] = roots[i]
		}
	}
	if home == nil {
		return nil
	}
	for i := range home.Relocations {
		move := &home.Relocations[i]
		projectRoot, ok := projects[filepath.Join(filepath.Clean(move.NewPath), LegacyProjectDir)]
		if !ok {
			continue
		}
		if marker, ok := entryNamed(projectRoot.Entries, "project.yaml"); ok {
			if move.ProjectMarkerDigest != "" && move.ProjectMarkerDigest != marker.Digest {
				return errors.New("naming: relocation marker digest conflicts with preimage")
			}
			move.ProjectMarkerDigest = marker.Digest
		}
	}
	return nil
}

// verifyRelocations establishes the complete compare-and-swap relationship
// before Apply creates a journal or staging directory. Offline records do not
// appear here and are intentionally never stat'ed.
func verifyRelocations(roots []Root) error {
	var home *Root
	projects := map[string]Root{}
	for i := range roots {
		r := &roots[i]
		if r.Kind == "home" {
			home = r
		}
		if r.Kind == "project" {
			projects[filepath.Clean(r.SourceRoot)] = *r
		}
	}
	if home == nil || len(home.Relocations) == 0 {
		return nil
	}
	var registry Entry
	found := false
	for _, e := range home.Entries {
		if e.Path == "projects.yaml" {
			registry, found = e, true
			break
		}
	}
	if !found {
		return errors.New("naming: relocation requires projects.yaml")
	}
	entries, err := decodeLegacyProjects(registry.Bytes)
	if err != nil {
		return fmt.Errorf("naming: decode relocation registry: %w", err)
	}
	byID := map[string]legacyProjectRef{}
	for _, item := range entries.Items {
		byID[item.ID] = item
	}
	seenID, seenOld, seenNew := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, move := range home.Relocations {
		if move.ID == "" || !canonicalAbsolute(move.OldPath) || !canonicalAbsolute(move.NewPath) || move.ProjectMarkerDigest == "" || len(move.ProjectMarkerDigest) != 64 || move.OldPath == move.NewPath || seenID[move.ID] || seenOld[move.OldPath] || seenNew[move.NewPath] {
			return errors.New("naming: ambiguous relocation declaration")
		}
		seenID[move.ID], seenOld[move.OldPath], seenNew[move.NewPath] = true, true, true
		item, ok := byID[move.ID]
		if !ok || item.Path != move.OldPath {
			return fmt.Errorf("naming: relocation registry preimage mismatch for %q", move.ID)
		}
		// The directory may already have been moved by the user. The paired
		// marker is therefore at the declared new location; oldPath is proved
		// solely by the immutable registry preimage and is never stat'ed.
		projectRoot, ok := projects[filepath.Join(filepath.Clean(move.NewPath), LegacyProjectDir)]
		if !ok || filepath.Clean(projectRoot.DestinationRoot) != filepath.Join(filepath.Clean(move.NewPath), ProjectDir) {
			return fmt.Errorf("naming: relocation has no paired project root for %q", move.ID)
		}
		marker, ok := entryNamed(projectRoot.Entries, "project.yaml")
		if !ok || marker.Digest != move.ProjectMarkerDigest {
			return fmt.Errorf("naming: relocation marker preimage mismatch for %q", move.ID)
		}
		var p legacyProject
		if err := decodeLegacyYAML(marker.Bytes, &p); err != nil || p.ID != move.ID {
			return fmt.Errorf("naming: relocation project id mismatch for %q", move.ID)
		}
	}
	return nil
}

func entryNamed(entries []Entry, path string) (Entry, bool) {
	for _, e := range entries {
		if e.Path == path {
			return e, true
		}
	}
	return Entry{}, false
}

func rootsOverlap(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

func PlanHome(source, destination string) (Plan, error) {
	return PlanRoots([]Root{{Kind: "home", SourceRoot: source, DestinationRoot: destination}})
}

// destinationEntries produces the versioned after-image. Source entries stay
// untouched in the plan and archive, so legacy evidence keeps its exact bytes.
// The only project field that is location-bound is baseline: after migration it
// must name the new marker directory rather than traverse the tombstone.
func destinationEntries(r Root) ([]Entry, error) {
	out := append([]Entry(nil), r.Entries...)
	if r.Kind == "home" {
		if len(r.Relocations) == 0 {
			return out, nil
		}
		for i := range out {
			if out[i].Path != "projects.yaml" {
				continue
			}
			projects, err := decodeLegacyProjects(out[i].Bytes)
			if err != nil {
				return nil, fmt.Errorf("naming: decode registry after-image: %w", err)
			}
			moves := map[string]Relocation{}
			for _, move := range r.Relocations {
				moves[move.ID] = move
			}
			for j := range projects.Items {
				if move, ok := moves[projects.Items[j].ID]; ok {
					projects.Items[j].Path = move.NewPath
				}
			}
			b, err := yaml.Marshal(projects)
			if err != nil {
				return nil, fmt.Errorf("naming: encode registry after-image: %w", err)
			}
			h := sha256.Sum256(b)
			out[i].Bytes, out[i].Digest = b, hex.EncodeToString(h[:])
			return out, nil
		}
		return nil, errors.New("naming: registry after-image missing projects.yaml")
	}
	if r.Kind != "project" {
		return out, nil
	}
	for i := range out {
		if out[i].Path != "project.yaml" {
			continue
		}
		var project legacyProject
		if err := decodeLegacyYAML(out[i].Bytes, &project); err != nil {
			return nil, fmt.Errorf("naming: decode project after-image: %w", err)
		}
		project.Baseline = ".tplaiter/baseline.json"
		b, err := yaml.Marshal(project)
		if err != nil {
			return nil, fmt.Errorf("naming: encode project after-image: %w", err)
		}
		h := sha256.Sum256(b)
		out[i].Bytes, out[i].Digest = b, hex.EncodeToString(h[:])
		return out, nil
	}
	return nil, errors.New("naming: project after-image missing project.yaml")
}

func capture(source string) ([]Entry, error) {
	var es []Entry
	e := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		if rel == "." {
			return nil
		}
		if credentialPath(rel) {
			return errors.New("naming: credential capability is excluded")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("naming: symlink is not migratable: %s", rel)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("naming: unsupported file: %s", rel)
		}
		b, x := os.ReadFile(path) //nolint:gosec // walk over the caller-selected project tree; non-regular entries are rejected above
		if x != nil {
			return x
		}
		h := sha256.Sum256(b)
		es = append(es, Entry{Path: rel, Mode: uint32(info.Mode().Perm()), Bytes: b, Digest: hex.EncodeToString(h[:])})
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
	return es, nil
}

// activeTransaction refuses a root that still carries durable transaction
// journals or pending markers. Persistent advisory locks do not prove that a
// transaction is still active. The probe list is the shared state-ledger
// classification (internal/stateledger/ledgerpath), so migrate-state and the
// ledger inventory agree on what counts as transaction evidence.
func activeTransaction(root string) error {
	if err := refuseNativeRelocation(root); err != nil {
		return err
	}
	rel, err := ledgerpath.TransactionEvidence(root)
	if err != nil {
		return fmt.Errorf("naming: %w", err)
	}
	if rel != "" {
		return fmt.Errorf("naming: active transaction at %s", filepath.FromSlash(rel))
	}
	return nil
}

func (p Plan) writeCanonical(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return writeDurable(path, append(b, '\n'), 0o600)
}

func writeDurable(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".naming-*")
	if e != nil {
		return e
	}
	n := f.Name()
	defer os.Remove(n)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if x := f.Close(); e == nil {
		e = x
	}
	if e == nil {
		e = os.Rename(n, path)
	}
	if e == nil {
		e = syncDir(filepath.Dir(path))
	}
	return e
}

// Apply uses a durable, retained journal: a crash never causes evidence to be
// erased. Roots are locked in lexical order and every source preimage is read
// again while locked, preventing a stale plan from being applied.
func Apply(p Plan) (Receipt, error) {
	if e := p.Verify(); e != nil {
		return Receipt{}, e
	}
	roots, _ := p.normalizedRoots()
	roots = migrationOrder(roots)
	locks, e := lockRoots(roots)
	if e != nil {
		return Receipt{}, e
	}
	defer unlockRoots(locks)
	var prior Receipt
	allCommitted := true
	for i, r := range roots {
		if _, x := os.Stat(r.DestinationRoot); x == nil {
			if got, ok := matchingReceipt(r, p); ok {
				if i == 0 {
					prior = got
				}
				continue
			}
			return Receipt{}, fmt.Errorf("naming: destination exists for %s", r.Kind)
		} else if !os.IsNotExist(x) {
			return Receipt{}, x
		}
		allCommitted = false
	}
	if allCommitted {
		return prior, nil
	}
	// A partly committed transaction must be resumed from its durable journal,
	// never continued by a fresh Apply invocation.
	for _, r := range roots {
		if _, x := os.Stat(r.DestinationRoot); x == nil {
			return Receipt{}, fmt.Errorf("naming: incomplete committed destination %s", r.Kind)
		}
	}
	for _, r := range roots {
		if e := activeTransaction(r.SourceRoot); e != nil {
			return Receipt{}, e
		}
		if e := GuardLegacyWrite(r.SourceRoot); e != nil {
			return Receipt{}, e
		}
		es, x := capturePreimage(r.SourceRoot, r)
		if x != nil {
			return Receipt{}, x
		}
		d, _ := digestBytes("tplaiter.dev/naming-source/v1", es)
		if d != r.SourceDigest {
			return Receipt{}, fmt.Errorf("naming: stale source preimage for %s", r.Kind)
		}
	}
	jp := filepath.Join(filepath.Dir(roots[0].DestinationRoot), ".tplaiter-naming-migration-"+p.Digest[:16]+".json")
	stages := make([]string, len(roots))
	for i, r := range roots {
		s, x := os.MkdirTemp(filepath.Dir(r.DestinationRoot), ".tplaiter-migration-")
		if x != nil {
			return Receipt{}, x
		}
		stages[i] = s
	}
	j := journal{Plan: p, Phase: "staging", Stages: stages}
	if e := p.writeCanonical(jp, j); e != nil {
		return Receipt{}, e
	}
	for i, r := range roots {
		entries, x := destinationEntries(r)
		if x != nil {
			return Receipt{}, x
		}
		for _, x := range entries {
			dst := filepath.Join(stages[i], x.Path)
			if e := os.MkdirAll(filepath.Dir(dst), 0o700); e != nil {
				return Receipt{}, e
			}
			if e := os.WriteFile(dst, x.Bytes, os.FileMode(x.Mode)); e != nil {
				return Receipt{}, e
			}
		}
		if e := syncTree(stages[i]); e != nil {
			return Receipt{}, e
		}
	}
	r, e := receiptForPlan(p, time.Now().UTC().Format(time.RFC3339Nano))
	if e != nil {
		return Receipt{}, e
	}
	for i := range roots {
		if e := p.writeCanonical(filepath.Join(stages[i], "migration.receipt.json"), r); e != nil {
			return Receipt{}, e
		}
		if roots[i].Kind == "home" {
			f, err := lockHomeWriter(stages[i])
			if err != nil {
				return Receipt{}, err
			}
			defer unlockRoots([]*os.File{f})
		}
	}
	j.Phase = "committing"
	if e := p.writeCanonical(jp, j); e != nil {
		return Receipt{}, e
	}
	for i, root := range roots {
		if e := os.Rename(stages[i], root.DestinationRoot); e != nil {
			return Receipt{}, e
		}
		if e := syncDir(filepath.Dir(root.DestinationRoot)); e != nil {
			return Receipt{}, e
		}
		if e := sealLegacyRoot(root.SourceRoot, p.Digest); e != nil {
			return Receipt{}, e
		}
	}
	j.Phase = "committed"
	if e := p.writeCanonical(jp, j); e != nil {
		return Receipt{}, e
	}
	return r, nil
}

func migrationOrder(roots []Root) []Root {
	ordered := append([]Root(nil), roots...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Kind == "home" {
			return ordered[j].Kind != "home"
		}
		return false
	})
	return ordered
}

func legacyArchive(source, digest string) string {
	return filepath.Join(filepath.Dir(source), "."+filepath.Base(source)+".tplaiter-legacy-"+digest[:16])
}

// sealLegacyRoot retains the exact legacy tree outside active discovery, then
// occupies the old pathname with a regular file. The frozen legacy writer
// fails before its own writes because every child path is ENOTDIR.
func sealLegacyRoot(source, digest string) error {
	archive := legacyArchive(source, digest)
	archiveInfo, archiveErr := os.Lstat(archive)
	if archiveErr != nil && !os.IsNotExist(archiveErr) {
		return archiveErr
	}
	sourceInfo, sourceErr := os.Lstat(source)
	if sourceErr != nil && !os.IsNotExist(sourceErr) {
		return sourceErr
	}
	if archiveErr == nil {
		if sourceErr == nil {
			if sourceInfo.Mode().IsRegular() {
				if err := GuardLegacyWrite(source); errors.Is(err, ErrLegacyWrite) {
					return nil
				}
			}
			return fmt.Errorf("naming: inconsistent legacy source and archive: %s", source)
		}
		// This is the durable recovery path for a crash after source->archive
		// rename but before creation of the incompatible old-path tombstone.
		if !archiveInfo.IsDir() {
			return fmt.Errorf("naming: legacy archive is not a directory: %s", archive)
		}
		if err := writeDurable(source, legacyTombstone, 0o600); err != nil {
			return fmt.Errorf("naming: finish legacy tombstone: %w", err)
		}
		return nil
	}
	if sourceErr != nil {
		return fmt.Errorf("naming: missing legacy source without archive: %s", source)
	}
	if err := os.Rename(source, archive); err != nil {
		return fmt.Errorf("naming: archive legacy root: %w", err)
	}
	if err := syncDir(filepath.Dir(source)); err != nil {
		return err
	}
	if err := writeDurable(source, legacyTombstone, 0o600); err != nil {
		return fmt.Errorf("naming: write legacy tombstone: %w", err)
	}
	return nil
}

func matchingReceipt(root Root, p Plan) (Receipt, bool) {
	r, err := receiptAtDestination(root, p)
	if err != nil {
		return Receipt{}, false
	}
	archive := legacyArchive(root.SourceRoot, p.Digest)
	archiveInfo, err := os.Lstat(archive)
	if err != nil || !archiveInfo.IsDir() {
		return Receipt{}, false
	}
	entries, err := capturePreimage(archive, root)
	if err != nil {
		return Receipt{}, false
	}
	digest, err := digestBytes("tplaiter.dev/naming-source/v1", entries)
	if err != nil || digest != root.SourceDigest {
		return Receipt{}, false
	}
	return r, true
}

func receiptAtDestination(root Root, p Plan) (Receipt, error) {
	r, err := readReceipt(filepath.Join(root.DestinationRoot, "migration.receipt.json"))
	if err != nil {
		return Receipt{}, err
	}
	if err := validateReceipt(p, r); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// expectedReceipt derives every immutable receipt field from the sealed plan.
// CommittedAt is intentionally excluded: it records when this otherwise fixed
// transaction was committed and is not an authority-bearing input.
func expectedReceipt(p Plan) (Receipt, error) {
	if err := p.Verify(); err != nil {
		return Receipt{}, err
	}
	roots, err := p.normalizedRoots()
	if err != nil {
		return Receipt{}, err
	}
	roots = migrationOrder(roots)
	for i := range roots {
		roots[i].ArchiveRoot = legacyArchive(roots[i].SourceRoot, p.Digest)
	}
	first := roots[0]
	return Receipt{
		Schema: ReceiptSchema, Algorithm: algorithm, PlanDigest: p.Digest,
		SourceRoot: first.SourceRoot, DestinationRoot: first.DestinationRoot,
		SourceDigest: first.SourceDigest, DestinationDigest: first.DestinationDigest,
		TransactionID: p.Digest[:16], Roots: roots,
	}, nil
}

func receiptForPlan(p Plan, committedAt string) (Receipt, error) {
	r, err := expectedReceipt(p)
	if err != nil {
		return Receipt{}, err
	}
	r.CommittedAt = committedAt
	return r, nil
}

// validateReceipt is the only trust boundary for a receipt. It deliberately
// compares ordered roots, including redundant top-level projection, against
// the sealed plan instead of treating fields in the receipt as a new plan.
func validateReceipt(p Plan, got Receipt) error {
	want, err := expectedReceipt(p)
	if err != nil {
		return err
	}
	if got.Schema != want.Schema || got.Algorithm != want.Algorithm ||
		got.PlanDigest != want.PlanDigest || got.TransactionID != want.TransactionID ||
		got.SourceRoot != want.SourceRoot || got.DestinationRoot != want.DestinationRoot ||
		got.SourceDigest != want.SourceDigest || got.DestinationDigest != want.DestinationDigest ||
		!reflect.DeepEqual(got.Roots, want.Roots) {
		return errors.New("naming: receipt does not bind sealed plan")
	}
	if got.CommittedAt == "" {
		return errors.New("naming: receipt has no commit time")
	}
	if _, err := time.Parse(time.RFC3339Nano, got.CommittedAt); err != nil {
		return fmt.Errorf("naming: invalid receipt commit time: %w", err)
	}
	return nil
}

// receiptPlan reconstructs the only plan a receipt may describe. Receipts are
// emitted from PlanRoots, whose immutable root ledger is sufficient to verify
// the sealed digest; archive paths are receipt-only derived evidence.
func receiptPlan(got Receipt) (Plan, error) {
	roots := append([]Root(nil), got.Roots...)
	for i := range roots {
		roots[i].ArchiveRoot = ""
	}
	p := Plan{Schema: PlanSchema, Algorithm: algorithm, Profile: "oss", WriterFloor: supportedLegacyWriter, Roots: roots, Digest: got.PlanDigest}
	if len(roots) != 0 {
		p.SourceRoot, p.DestinationRoot, p.Entries, p.SourceDigest = roots[0].SourceRoot, roots[0].DestinationRoot, roots[0].Entries, roots[0].SourceDigest
	}
	if err := validateReceipt(p, got); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func readReceipt(path string) (Receipt, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Receipt{}, err
	}
	if !info.Mode().IsRegular() {
		return Receipt{}, errors.New("naming: receipt is not a regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Receipt{}, err
	}
	// Defend the check/read boundary as well as refusing links before reads.
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return Receipt{}, errors.New("naming: receipt changed while reading")
	}
	if err := rejectDuplicateJSON(b); err != nil {
		return Receipt{}, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var receipt Receipt
	if err := d.Decode(&receipt); err != nil {
		return Receipt{}, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Receipt{}, errors.New("naming: receipt has trailing JSON")
	}
	return receipt, nil
}

func rejectDuplicateJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func() error
	value = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("naming: duplicate receipt JSON field")
				}
				seen[name] = true
				if err := value(); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		case '[':
			for d.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err := d.Token()
			return err
		default:
			return errors.New("naming: invalid receipt JSON delimiter")
		}
	}
	if err := value(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("naming: receipt has trailing JSON")
	}
	return nil
}

// Recover resumes only a durable committing journal. It never invents a plan:
// every destination must either contain the matching receipt or its recorded
// staged directory. A staging journal is deliberately left for an operator to
// inspect/abort because no destination rename has begun.
func Recover(journalPath string) (Receipt, error) {
	b, err := os.ReadFile(journalPath)
	if err != nil {
		return Receipt{}, err
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		return Receipt{}, err
	}
	if j.Phase != "committing" {
		return Receipt{}, fmt.Errorf("naming: journal phase %q is not recoverable", j.Phase)
	}
	if err := j.Plan.Verify(); err != nil {
		return Receipt{}, err
	}
	roots, _ := j.Plan.normalizedRoots()
	roots = migrationOrder(roots)
	if len(j.Stages) != len(roots) {
		return Receipt{}, errors.New("naming: journal stage ledger mismatch")
	}
	locks, err := lockRoots(roots)
	if err != nil {
		return Receipt{}, err
	}
	defer unlockRoots(locks)
	receipt, err := receiptForPlan(j.Plan, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return Receipt{}, err
	}
	// Validate every recovery input before a seal, rename, or journal write.
	// A forged later stage must not cause an earlier root to be sealed.
	committed := make([]Receipt, len(roots))
	existingDestination := make([]bool, len(roots))
	pending := make([]bool, len(roots))
	for i, root := range roots {
		if _, err := os.Lstat(root.DestinationRoot); err == nil {
			got, err := receiptAtDestination(root, j.Plan)
			if err != nil {
				return Receipt{}, fmt.Errorf("naming: divergent recovery destination %s", root.Kind)
			}
			if err := sourceOrArchiveMatches(root, j.Plan.Digest); err != nil {
				return Receipt{}, fmt.Errorf("naming: stale recovery source for %s: %w", root.Kind, err)
			}
			committed[i], existingDestination[i] = got, true
			continue
		} else if !os.IsNotExist(err) {
			return Receipt{}, err
		}
		if err := verifyStage(j.Stages[i], root, j.Plan); err != nil {
			return Receipt{}, fmt.Errorf("naming: invalid recovery stage for %s: %w", root.Kind, err)
		}
		if err := sourceOrArchiveMatches(root, j.Plan.Digest); err != nil {
			return Receipt{}, fmt.Errorf("naming: stale recovery source for %s: %w", root.Kind, err)
		}
		if err := refuseNativeRecoveryRelocation(root); err != nil {
			return Receipt{}, err
		}
		pending[i] = true
	}
	for i, root := range roots {
		if pending[i] && root.Kind == "home" {
			f, err := lockHomeWriter(j.Stages[i])
			if err != nil {
				return Receipt{}, err
			}
			defer unlockRoots([]*os.File{f})
		}
	}
	for i, root := range roots {
		if existingDestination[i] {
			if err := sealLegacyRoot(root.SourceRoot, j.Plan.Digest); err != nil {
				return Receipt{}, err
			}
			receipt = committed[i]
			continue
		}
		if !pending[i] {
			return Receipt{}, errors.New("naming: recovery root was not preflighted")
		}
		if err := os.Rename(j.Stages[i], root.DestinationRoot); err != nil {
			return Receipt{}, err
		}
		if err := syncDir(filepath.Dir(root.DestinationRoot)); err != nil {
			return Receipt{}, err
		}
		if err := sealLegacyRoot(root.SourceRoot, j.Plan.Digest); err != nil {
			return Receipt{}, err
		}
	}
	j.Phase = "committed"
	if err := j.Plan.writeCanonical(journalPath, j); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func sourceOrArchiveMatches(root Root, digest string) error {
	archive := legacyArchive(root.SourceRoot, digest)
	archiveInfo, archiveErr := os.Lstat(archive)
	sourceInfo, sourceErr := os.Lstat(root.SourceRoot)
	if archiveErr != nil && !os.IsNotExist(archiveErr) {
		return archiveErr
	}
	if sourceErr != nil && !os.IsNotExist(sourceErr) {
		return sourceErr
	}
	path := root.SourceRoot
	if archiveErr == nil {
		if !archiveInfo.IsDir() {
			return errors.New("archive is not a directory")
		}
		// A changed source beside an archive is ambiguous. Only the exact
		// tombstone proves that source->archive had already completed.
		if sourceErr == nil {
			if !sourceInfo.Mode().IsRegular() || !errors.Is(GuardLegacyWrite(root.SourceRoot), ErrLegacyWrite) {
				return errors.New("source exists beside archive")
			}
		}
		path = archive
	} else if sourceErr != nil || !sourceInfo.IsDir() {
		return errors.New("missing source preimage")
	}
	entries, err := capturePreimage(path, root)
	if err != nil {
		return err
	}
	got, err := digestBytes("tplaiter.dev/naming-source/v1", entries)
	if err != nil {
		return err
	}
	if got != root.SourceDigest {
		return errors.New("source/archive preimage mismatch")
	}
	return nil
}

func verifyStage(stage string, root Root, p Plan) error {
	info, err := os.Lstat(stage)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe stage directory")
	}
	expected := map[string]Entry{"migration.receipt.json": {}}
	entries, err := destinationEntries(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		expected[e.Path] = e
	}
	err = filepath.Walk(stage, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(stage, path)
		if rel == "." || info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("unsupported stage entry")
		}
		e, ok := expected[rel]
		if !ok {
			if root.Kind == "home" && rel == ledgerpath.HomeLock && info.Size() == 0 && info.Mode().Perm() == 0o600 {
				return nil
			}
			return fmt.Errorf("unexpected stage entry %s", rel)
		}
		delete(expected, rel)
		b, err := os.ReadFile(path) //nolint:gosec // walk over the caller-selected project tree; non-regular entries are rejected above
		if err != nil {
			return err
		}
		if rel == "migration.receipt.json" {
			r, err := readReceipt(path)
			if err != nil {
				return err
			}
			return validateReceipt(p, r)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != e.Digest || uint32(info.Mode().Perm()) != e.Mode {
			return fmt.Errorf("stage preimage mismatch %s", rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("missing stage entries")
	}
	return nil
}

func lockRoots(roots []Root) ([]*os.File, error) {
	set := map[string]bool{}
	for _, r := range roots {
		// Keep lock files beside, never inside, a captured root: otherwise the
		// migration's own advisory lock would make the source preimage stale.
		set[filepath.Join(filepath.Dir(r.SourceRoot), "."+filepath.Base(r.SourceRoot)+".tplaiter-naming.lock")] = true
		set[filepath.Join(filepath.Dir(r.DestinationRoot), "."+filepath.Base(r.DestinationRoot)+".tplaiter-naming.lock")] = true
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	fs := []*os.File{}
	for _, p := range paths {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
		if e != nil {
			unlockRoots(fs)
			return nil, e
		}
		if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
			_ = f.Close()
			unlockRoots(fs)
			return nil, e
		}
		fs = append(fs, f)
	}
	for _, r := range roots {
		if r.Kind != "home" {
			continue
		}
		for _, root := range []string{r.SourceRoot, r.DestinationRoot} {
			info, err := os.Lstat(root)
			if os.IsNotExist(err) || (err == nil && info.Mode().IsRegular()) {
				continue // Absent destination or sealed source tombstone.
			}
			if err != nil || !info.IsDir() {
				unlockRoots(fs)
				return nil, fmt.Errorf("naming: unsafe home lock root %s", root)
			}
			if root == r.DestinationRoot {
				if _, err := os.Lstat(filepath.Join(root, ledgerpath.HomeLock)); os.IsNotExist(err) {
					continue // Never add a lock to an existing foreign destination.
				}
			}
			f, err := lockHomeWriter(root)
			if err != nil {
				unlockRoots(fs)
				return nil, err
			}
			fs = append(fs, f)
		}
	}
	return fs, nil
}

// lockHomeWriter uses the same persistent inode and exclusive flock as
// state.WithLock. Refuse a busy writer instead of waiting on a stale plan.
func lockHomeWriter(root string) (*os.File, error) {
	p := filepath.Join(root, ledgerpath.HomeLock)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("naming: unsafe home writer lock")
	}
	if err == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("naming: home writer lock unavailable: %w", err)
	}
	return f, nil
}

// An absent lock at plan time may be created by Apply's writer coordination.
// Preserve it on disk, but do not treat that empty advisory file as a change
// to the sealed state preimage. Existing lock bytes remain part of the plan.
func capturePreimage(path string, root Root) ([]Entry, error) {
	entries, err := capture(path)
	if err != nil || root.Kind != "home" {
		return entries, err
	}
	for _, e := range root.Entries {
		if e.Path == ledgerpath.HomeLock {
			return entries, nil
		}
	}
	for i, e := range entries {
		if e.Path == ledgerpath.HomeLock && len(e.Bytes) == 0 && e.Mode == 0o600 {
			return append(entries[:i], entries[i+1:]...), nil
		}
	}
	return entries, nil
}

func unlockRoots(fs []*os.File) {
	for i := len(fs) - 1; i >= 0; i-- {
		_ = syscall.Flock(int(fs[i].Fd()), syscall.LOCK_UN)
		_ = fs[i].Close()
	}
}

func syncTree(root string) error {
	return filepath.Walk(root, func(path string, i os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if i.IsDir() {
			return nil
		}
		f, e := os.Open(path) //nolint:gosec // walk over the caller-selected project tree; directories are skipped above
		if e != nil {
			return e
		}
		e = f.Sync()
		_ = f.Close()
		return e
	})
}

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	e = f.Sync()
	_ = f.Close()
	return e
}
