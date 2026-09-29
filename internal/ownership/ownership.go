// Package ownership keeps a deterministic, project-local record of rendered
// template paths. It is deliberately independent from update's transaction
// journal: this package only plans a ledger image and transformed actions;
// update owns durable application and rollback of those images.
package ownership

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// InventoryRelPath is the deterministic ledger for rendered template paths.
const InventoryRelPath = naming.ProjectDir + "/ownership.json"

// reservedUpdateDir holds the update transaction engine's journal and CAS.
const reservedUpdateDir = naming.ProjectDir + "/update"

const inventoryVersion = 1

// Kind describes a materialized project path. The empty value is intentionally
// never written: old file-only images remain regular files.
type Kind string

const (
	KindFile    Kind = "file"
	KindSymlink Kind = "symlink"
)

// Policy is the project marker's ownership section. All values are slash-glob
// patterns, not filesystem paths supplied to the host OS.
type Policy struct {
	Exclude      []string
	SkipIfExists []string
	Restore      []string
}

// Artifact is one template-owned desired image. SHA256 hashes file bytes or,
// for a symlink, its literal link target. Mode is meaningful for regular files
// only; Target is meaningful for safe relative symlinks only.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode,omitempty"`
	Kind   Kind   `json:"kind,omitempty"`
	Target string `json:"target,omitempty"`
}

// Decision is an observable policy decision from the latest planned update.
// It is persisted in the ledger so a dry-run/journal inspection has an ordered
// JSON explanation of why a rendered mutation was suppressed.
type Decision struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Inventory is versioned and canonical JSON. Tombstones are durable evidence
// that an owned path was removed by the user; a future target cannot recreate
// it until Policy.Restore explicitly matches that path.
type Inventory struct {
	Version    int        `json:"version"`
	Artifacts  []Artifact `json:"artifacts,omitempty"`
	Tombstones []string   `json:"tombstones,omitempty"`
	Skipped    []Decision `json:"skipped,omitempty"`
}

// State is a raw project image used by the ownership planner. Data holds file
// bytes or the literal link target. An absent state has Exists=false.
type State struct {
	Exists bool
	Data   []byte
	Mode   fs.FileMode
	Kind   Kind
}

// Operation is an update-plan operation expressed without importing update.
type Operation string

const (
	Keep   Operation = "keep"
	Write  Operation = "write"
	Delete Operation = "delete"
)

// Action is a generic rendered-file plan action. For a symlink write Content
// is its link target and SymlinkTarget is the same string kept for readability
// at the adapter boundary.
type Action struct {
	Path          string
	Operation     Operation
	Content       []byte
	Reason        string
	Conflict      bool
	Mode          fs.FileMode
	SymlinkTarget string
}

// Change is the ownership-ledger mutation. Nil Before/After represents an
// absent inventory file; it is ready for direct adaptation to a transaction
// mutation and is never written by this package.
type Change struct {
	Path   string
	Before []byte
	After  []byte
}

// Input contains fully rendered target artifacts and the ordinary 3-way plan.
// BasePaths are used only while adopting pre-ledger projects: a missing base
// path is conservatively treated as a user deletion rather than recreated.
type Input struct {
	Policy         Policy
	BasePaths      []string
	Desired        map[string]Artifact
	Actions        []Action
	TargetBaseline map[string]string
}

// Overlay is the no-write result of Build.
type Overlay struct {
	Actions   []Action
	Change    *Change
	Inventory Inventory
	Skipped   []Decision
	Baseline  map[string]string
}

// Build applies ownership policy to an update plan and stages the resulting
// ledger image. It never mutates root. Callers must transactionally apply both
// the returned Actions and Change together.
func Build(root string, in Input) (*Overlay, error) {
	policy, err := compilePolicy(in.Policy)
	if err != nil {
		return nil, err
	}
	for rel, artifact := range in.Desired {
		if rel != artifact.Path {
			return nil, fmt.Errorf("ownership: desired map key %q differs from artifact path %q", rel, artifact.Path)
		}
		if err := validateArtifact(artifact); err != nil {
			return nil, err
		}
	}

	previous, rawBefore, inventoryExists, err := loadInventory(root)
	if err != nil {
		return nil, err
	}
	prior := make(map[string]Artifact, len(previous.Artifacts))
	for _, artifact := range previous.Artifacts {
		prior[artifact.Path] = artifact
	}
	tombstones := make(map[string]struct{}, len(previous.Tombstones))
	for _, rel := range previous.Tombstones {
		tombstones[rel] = struct{}{}
	}

	actions, err := canonicalActions(in.Actions)
	if err != nil {
		return nil, err
	}
	states := map[string]State{}
	stateFor := func(rel string) (State, error) {
		if state, ok := states[rel]; ok {
			return state, nil
		}
		state, readErr := ReadState(root, rel)
		if readErr != nil {
			return State{}, readErr
		}
		states[rel] = state
		return state, nil
	}

	// Projects created before ownership.json are adopted conservatively. A base
	// path already absent before the first ledger write is a deletion intent,
	// never a request to recreate it merely because an upstream template changed.
	if !inventoryExists {
		basePaths, pathsErr := canonicalPaths(in.BasePaths)
		if pathsErr != nil {
			return nil, pathsErr
		}
		for _, rel := range basePaths {
			state, stateErr := stateFor(rel)
			if stateErr != nil {
				return nil, stateErr
			}
			if !state.Exists {
				tombstones[rel] = struct{}{}
			}
		}
	}
	for _, artifact := range previous.Artifacts {
		state, stateErr := stateFor(artifact.Path)
		if stateErr != nil {
			return nil, stateErr
		}
		if !state.Exists {
			tombstones[artifact.Path] = struct{}{}
		}
	}

	baseline := cloneStrings(in.TargetBaseline)
	decisions := map[string]Decision{}
	blocked := map[string]string{}
	setActualBaseline := func(rel string) error {
		state, stateErr := stateFor(rel)
		if stateErr != nil {
			return stateErr
		}
		if !state.Exists {
			delete(baseline, rel)
			return nil
		}
		baseline[rel] = hash(state.Data)
		return nil
	}
	mark := func(rel, reason string) {
		if _, exists := decisions[rel]; !exists {
			decisions[rel] = Decision{Path: rel, Reason: reason}
		}
		if _, exists := blocked[rel]; !exists {
			blocked[rel] = reason
		}
	}

	for i := range actions {
		action := &actions[i]
		_, desired := in.Desired[action.Path]
		_, tombstoned := tombstones[action.Path]
		if tombstoned && desired && policy.restore.matches(action.Path) {
			delete(tombstones, action.Path)
			tombstoned = false
		}

		if policy.exclude.matches(action.Path) {
			if action.Operation != Keep {
				suppressAction(action)
				mark(action.Path, "exclude")
			}
			if err := setActualBaseline(action.Path); err != nil {
				return nil, err
			}
			continue
		}
		if tombstoned && desired {
			if action.Operation != Keep {
				suppressAction(action)
			}
			mark(action.Path, "tombstone")
			if err := setActualBaseline(action.Path); err != nil {
				return nil, err
			}
			continue
		}
		if action.Operation == Write && policy.skipIfExists.matches(action.Path) {
			state, stateErr := stateFor(action.Path)
			if stateErr != nil {
				return nil, stateErr
			}
			if state.Exists {
				suppressAction(action)
				mark(action.Path, "skipIfExists")
				if err := setActualBaseline(action.Path); err != nil {
					return nil, err
				}
			}
		}
	}

	artifacts := make(map[string]Artifact, len(in.Desired)+len(prior))
	for _, rel := range sortedArtifactPaths(in.Desired) {
		if _, tombstoned := tombstones[rel]; tombstoned {
			continue
		}
		if _, isBlocked := blocked[rel]; isBlocked {
			if old, existed := prior[rel]; existed {
				artifacts[rel] = old
			}
			continue
		}
		artifacts[rel] = in.Desired[rel]
	}
	// An excluded upstream deletion keeps the previously owned artifact as an
	// explicit policy choice. Other upstream deletions naturally remove it.
	for rel, old := range prior {
		if _, stillDesired := in.Desired[rel]; stillDesired {
			continue
		}
		if policy.exclude.matches(rel) {
			state, stateErr := stateFor(rel)
			if stateErr != nil {
				return nil, stateErr
			}
			if state.Exists {
				artifacts[rel] = old
				if err := setActualBaseline(rel); err != nil {
					return nil, err
				}
			}
		}
	}

	next := Inventory{Version: inventoryVersion, Artifacts: sortedArtifacts(artifacts), Tombstones: sortedSet(tombstones), Skipped: sortedDecisions(decisions)}
	var change *Change
	if len(next.Artifacts) != 0 || len(next.Tombstones) != 0 || len(next.Skipped) != 0 {
		encoded, marshalErr := json.MarshalIndent(next, "", "  ")
		if marshalErr != nil {
			return nil, fmt.Errorf("ownership: marshal inventory: %w", marshalErr)
		}
		encoded = append(encoded, '\n')
		if !inventoryExists || !bytes.Equal(rawBefore, encoded) {
			change = &Change{Path: InventoryRelPath, Before: clone(rawBefore), After: encoded}
		}
	} else if inventoryExists {
		change = &Change{Path: InventoryRelPath, Before: clone(rawBefore)}
	}
	return &Overlay{Actions: actions, Change: change, Inventory: next, Skipped: sortedDecisions(decisions), Baseline: baseline}, nil
}

// suppressAction turns a pending rendered write into a genuine no-op.  Mode
// and SymlinkTarget are write metadata, so retaining either after a policy
// suppression would produce an impossible Action image (a Keep action that
// still describes a symlink publish).
func suppressAction(action *Action) {
	action.Operation = Keep
	action.Content = nil
	action.Conflict = false
	action.Mode = 0
	action.SymlinkTarget = ""
}

// Initialize writes the initial ownership ledger for a newly rendered project.
// Existing ledgers are never overwritten: creation is the only non-transaction
// lifecycle writer, and a partial/new collision must fail rather than erase
// ownership evidence.
func Initialize(root string, artifacts map[string]Artifact) error {
	for rel, artifact := range artifacts {
		if rel != artifact.Path {
			return fmt.Errorf("ownership: desired map key %q differs from artifact path %q", rel, artifact.Path)
		}
		if err := validateArtifact(artifact); err != nil {
			return err
		}
	}
	state, err := ReadState(root, InventoryRelPath)
	if err != nil {
		return err
	}
	if state.Exists {
		return errors.New("ownership: initial inventory already exists")
	}
	data, err := json.MarshalIndent(Inventory{Version: inventoryVersion, Artifacts: sortedArtifacts(artifacts)}, "", "  ")
	if err != nil {
		return fmt.Errorf("ownership: marshal initial inventory: %w", err)
	}
	data = append(data, '\n')
	path, err := safeProjectPath(root, InventoryRelPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tplaiter-ownership-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("ownership: initial inventory already exists")
		}
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// ArtifactFor returns a validated serialized ownership image for bytes or a
// safe relative symlink. It is shared by the render/update adapter and tests.
func ArtifactFor(rel string, data []byte, mode fs.FileMode, linkTarget string) (Artifact, error) {
	if err := validatePath(rel); err != nil {
		return Artifact{}, err
	}
	artifact := Artifact{Path: rel, SHA256: hash(data)}
	if linkTarget != "" {
		if err := ValidateRelativeSymlink(rel, linkTarget); err != nil {
			return Artifact{}, err
		}
		artifact.Kind, artifact.Target = KindSymlink, linkTarget
		return artifact, nil
	}
	if mode == 0 {
		mode = 0o644
	}
	artifact.Kind, artifact.Mode = KindFile, uint32(mode.Perm())
	return artifact, nil
}

// ReadState reads one project image without following a final symlink. Every
// parent must be a real directory; final symlinks are accepted only when their
// literal relative target stays lexically within the project namespace.
func ReadState(root, rel string) (State, error) {
	full, err := safeProjectPath(root, rel)
	if err != nil {
		return State{}, err
	}
	info, err := os.Lstat(full)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, linkErr := os.Readlink(full)
		if linkErr != nil {
			return State{}, linkErr
		}
		if err := ValidateRelativeSymlink(rel, target); err != nil {
			return State{}, err
		}
		return State{Exists: true, Data: []byte(target), Kind: KindSymlink}, nil
	}
	if !info.Mode().IsRegular() {
		return State{}, fmt.Errorf("ownership: target is not a regular file or safe symlink: %s", rel)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return State{}, err
	}
	return State{Exists: true, Data: data, Mode: info.Mode().Perm(), Kind: KindFile}, nil
}

// ValidateRelativeSymlink rejects absolute, NUL-containing, or root-escaping
// link targets. It permits a relative `..` only when the resolved lexical path
// remains inside the project (for example bin/tool -> ../scripts/tool).
func ValidateRelativeSymlink(rel, target string) error {
	if err := validatePath(rel); err != nil {
		return err
	}
	if target == "" || strings.ContainsRune(target, 0) || strings.Contains(target, "\\") || filepath.IsAbs(filepath.FromSlash(target)) {
		return fmt.Errorf("ownership: unsafe symlink target %q for %s", target, rel)
	}
	resolved := path.Clean(path.Join(path.Dir(rel), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") || path.IsAbs(resolved) {
		return fmt.Errorf("ownership: symlink target escapes project root: %s -> %s", rel, target)
	}
	return nil
}

type matcher struct{ res []*regexp.Regexp }

func compilePolicy(policy Policy) (struct{ exclude, skipIfExists, restore matcher }, error) {
	exclude, err := compileMatcher(policy.Exclude)
	if err != nil {
		return struct{ exclude, skipIfExists, restore matcher }{}, fmt.Errorf("ownership.exclude: %w", err)
	}
	skip, err := compileMatcher(policy.SkipIfExists)
	if err != nil {
		return struct{ exclude, skipIfExists, restore matcher }{}, fmt.Errorf("ownership.skipIfExists: %w", err)
	}
	restore, err := compileMatcher(policy.Restore)
	if err != nil {
		return struct{ exclude, skipIfExists, restore matcher }{}, fmt.Errorf("ownership.restore: %w", err)
	}
	return struct{ exclude, skipIfExists, restore matcher }{exclude, skip, restore}, nil
}

func compileMatcher(patterns []string) (matcher, error) {
	out := matcher{res: make([]*regexp.Regexp, 0, len(patterns))}
	for _, pattern := range patterns {
		if err := validatePattern(pattern); err != nil {
			return matcher{}, err
		}
		out.res = append(out.res, globRegexp(pattern))
	}
	return out, nil
}

func (m matcher) matches(rel string) bool {
	for _, re := range m.res {
		if re.MatchString(rel) {
			return true
		}
	}
	return false
}

func loadInventory(root string) (Inventory, []byte, bool, error) {
	state, err := ReadState(root, InventoryRelPath)
	if err != nil {
		return Inventory{}, nil, false, err
	}
	if !state.Exists {
		return Inventory{Version: inventoryVersion}, nil, false, nil
	}
	if state.Kind != KindFile {
		return Inventory{}, nil, false, errors.New("ownership: inventory must be a regular file")
	}
	var inventory Inventory
	dec := json.NewDecoder(bytes.NewReader(state.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inventory); err != nil {
		return Inventory{}, nil, false, fmt.Errorf("ownership: parse inventory: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Inventory{}, nil, false, errors.New("ownership: inventory has trailing data")
	}
	if inventory.Version != inventoryVersion {
		return Inventory{}, nil, false, fmt.Errorf("ownership: unsupported inventory version %d", inventory.Version)
	}
	artifacts := map[string]struct{}{}
	for _, artifact := range inventory.Artifacts {
		if err := validateArtifact(artifact); err != nil {
			return Inventory{}, nil, false, err
		}
		if _, seen := artifacts[artifact.Path]; seen {
			return Inventory{}, nil, false, fmt.Errorf("ownership: duplicate artifact %q", artifact.Path)
		}
		artifacts[artifact.Path] = struct{}{}
	}
	tombstones := map[string]struct{}{}
	for _, rel := range inventory.Tombstones {
		if err := validatePath(rel); err != nil {
			return Inventory{}, nil, false, err
		}
		if _, collides := artifacts[rel]; collides {
			return Inventory{}, nil, false, fmt.Errorf("ownership: artifact %q is also tombstoned", rel)
		}
		if _, seen := tombstones[rel]; seen {
			return Inventory{}, nil, false, fmt.Errorf("ownership: duplicate tombstone %q", rel)
		}
		tombstones[rel] = struct{}{}
	}
	decisions := map[string]struct{}{}
	for _, decision := range inventory.Skipped {
		if err := validatePath(decision.Path); err != nil || decision.Reason == "" {
			return Inventory{}, nil, false, fmt.Errorf("ownership: invalid skipped decision %q", decision.Path)
		}
		if _, seen := decisions[decision.Path]; seen {
			return Inventory{}, nil, false, fmt.Errorf("ownership: duplicate skipped decision %q", decision.Path)
		}
		decisions[decision.Path] = struct{}{}
	}
	inventory.Artifacts = sortedArtifacts(sliceArtifacts(inventory.Artifacts))
	inventory.Tombstones = sortedSet(tombstones)
	inventory.Skipped = sortedDecisions(sliceDecisions(inventory.Skipped))
	return inventory, clone(state.Data), true, nil
}

func canonicalActions(actions []Action) ([]Action, error) {
	out := make([]Action, len(actions))
	copy(out, actions)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	for i := range out {
		action := &out[i]
		if err := validatePath(action.Path); err != nil {
			return nil, err
		}
		if i > 0 && out[i-1].Path == action.Path {
			return nil, fmt.Errorf("ownership: duplicate action %q", action.Path)
		}
		switch action.Operation {
		case Keep, Write, Delete:
		default:
			return nil, fmt.Errorf("ownership: invalid action operation %q", action.Operation)
		}
		if action.Conflict && action.Operation != Write {
			return nil, fmt.Errorf("ownership: conflict action %q is not a write", action.Path)
		}
		if action.Operation != Write && action.SymlinkTarget != "" {
			return nil, fmt.Errorf("ownership: non-write action %q has a symlink target", action.Path)
		}
		if action.SymlinkTarget != "" {
			if err := ValidateRelativeSymlink(action.Path, action.SymlinkTarget); err != nil {
				return nil, err
			}
			if !bytes.Equal(action.Content, []byte(action.SymlinkTarget)) {
				return nil, fmt.Errorf("ownership: symlink action %q target bytes differ", action.Path)
			}
		}
		action.Content = clone(action.Content)
	}
	return out, nil
}

func validateArtifact(artifact Artifact) error {
	if err := validatePath(artifact.Path); err != nil {
		return err
	}
	if !validDigest(artifact.SHA256) {
		return fmt.Errorf("ownership: invalid artifact digest for %s", artifact.Path)
	}
	switch artifact.Kind {
	case "", KindFile:
		if artifact.Mode > 0o777 || artifact.Target != "" {
			return fmt.Errorf("ownership: invalid regular artifact %s", artifact.Path)
		}
	case KindSymlink:
		if artifact.Mode != 0 {
			return fmt.Errorf("ownership: symlink artifact %s has mode", artifact.Path)
		}
		if err := ValidateRelativeSymlink(artifact.Path, artifact.Target); err != nil {
			return err
		}
		if artifact.SHA256 != hash([]byte(artifact.Target)) {
			return fmt.Errorf("ownership: symlink artifact %s target digest mismatch", artifact.Path)
		}
	default:
		return fmt.Errorf("ownership: invalid artifact kind %q", artifact.Kind)
	}
	return nil
}

func safeProjectPath(root, rel string) (string, error) {
	if err := validateStatePath(rel); err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("ownership: project root is not a real directory")
	}
	current := absRoot
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		if i == len(parts)-1 {
			break
		}
		entry, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return filepath.Join(absRoot, filepath.FromSlash(rel)), nil
		}
		if statErr != nil {
			return "", statErr
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
			return "", fmt.Errorf("ownership: unsafe target parent %s", current)
		}
	}
	return current, nil
}

func validatePath(rel string) error {
	if err := validateStatePath(rel); err != nil {
		return err
	}
	if rel == InventoryRelPath {
		return fmt.Errorf("ownership: reserved path %q", rel)
	}
	return nil
}

func validateStatePath(rel string) error {
	if rel == "" || strings.Contains(rel, "\\") || strings.HasPrefix(rel, "/") || !fs.ValidPath(rel) {
		return fmt.Errorf("ownership: unsafe path %q", rel)
	}
	clean := path.Clean(rel)
	if clean != rel || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("ownership: unsafe path %q", rel)
	}
	if rel == reservedUpdateDir || strings.HasPrefix(rel, reservedUpdateDir+"/") {
		return fmt.Errorf("ownership: reserved path %q", rel)
	}
	return nil
}

func validatePattern(pattern string) error {
	if pattern == "" || strings.TrimSpace(pattern) != pattern || strings.Contains(pattern, "\\") || strings.HasPrefix(pattern, "/") || strings.ContainsRune(pattern, 0) {
		return fmt.Errorf("invalid glob %q", pattern)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("invalid glob %q", pattern)
		}
	}
	return nil
}

func globRegexp(glob string) *regexp.Regexp {
	segments := strings.Split(glob, "/")
	var b strings.Builder
	b.WriteString("^")
	needSlash := false
	for i, segment := range segments {
		if segment == "**" && len(segments) > 1 {
			if i == 0 {
				b.WriteString("(?:.*/)?")
			} else if i == len(segments)-1 {
				if needSlash {
					b.WriteString("/")
				}
				b.WriteString(".*")
			} else {
				if needSlash {
					b.WriteString("/")
				}
				b.WriteString("(?:.*/)?")
			}
			needSlash = false
			continue
		}
		if needSlash {
			b.WriteString("/")
		}
		for _, r := range segment {
			switch r {
			case '*':
				b.WriteString("[^/]*")
			case '?':
				b.WriteString("[^/]")
			default:
				b.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		needSlash = true
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func sortedArtifacts(values map[string]Artifact) []Artifact {
	paths := sortedArtifactPaths(values)
	out := make([]Artifact, 0, len(paths))
	for _, rel := range paths {
		artifact := values[rel]
		if artifact.Kind == KindFile {
			artifact.Kind = ""
		}
		out = append(out, artifact)
	}
	return out
}

func sortedArtifactPaths(values map[string]Artifact) []string {
	paths := make([]string, 0, len(values))
	for rel := range values {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	return paths
}

func sliceArtifacts(values []Artifact) map[string]Artifact {
	out := make(map[string]Artifact, len(values))
	for _, artifact := range values {
		out[artifact.Path] = artifact
	}
	return out
}

func sortedDecisions(values map[string]Decision) []Decision {
	paths := make([]string, 0, len(values))
	for rel := range values {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	out := make([]Decision, 0, len(paths))
	for _, rel := range paths {
		out = append(out, values[rel])
	}
	return out
}

func sliceDecisions(values []Decision) map[string]Decision {
	out := make(map[string]Decision, len(values))
	for _, decision := range values {
		out[decision.Path] = decision
	}
	return out
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for rel := range values {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

func canonicalPaths(paths []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, rel := range paths {
		if err := validatePath(rel); err != nil {
			return nil, err
		}
		set[rel] = struct{}{}
	}
	return sortedSet(set), nil
}

func cloneStrings(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func clone(data []byte) []byte {
	if data == nil {
		return nil
	}
	return append([]byte(nil), data...)
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
