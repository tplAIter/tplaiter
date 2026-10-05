package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/stateledger"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

// InspectionStatus describes evidence, never recovery or mutation admission.
type InspectionStatus string

const (
	InspectionActive          InspectionStatus = "active"
	InspectionCommitted       InspectionStatus = "committed"
	InspectionRolledBack      InspectionStatus = "rolled-back"
	InspectionFuture          InspectionStatus = "future"
	InspectionUnsupportedKind InspectionStatus = "unsupported-kind"
	InspectionUnsafe          InspectionStatus = "unsafe"
	InspectionMissingCAS      InspectionStatus = "missing-cas"
	InspectionMissingImages   InspectionStatus = "missing-images"
	InspectionUnresolved      InspectionStatus = "unresolved"
)

// ErrInspectionChanged means the writer changed a receipt during observation.
var ErrInspectionChanged = errors.New("project transaction: inspection changed")

// ErrInspectionUncovered means the selected installed runtime has not proved
// this receipt's authority. It never asserts foreign ownership or corruption.
var ErrInspectionUncovered = errors.New("project transaction: runtime coverage unresolved")

// ReceiptDurability reports the limit of a read-only observation. Successful
// reads, stable inode metadata and authenticated phases cannot prove a prior
// file/directory fsync completed. This API never confirms or repairs durability.
type ReceiptDurability string

const (
	ReceiptDurabilityUnverified  ReceiptDurability = "unverified"
	ReceiptDurabilityNotObserved ReceiptDurability = "not-observable-readonly"
)

// JournalInspection contains no key, material, writable transaction or setter.
// Terminal reports a verified historical terminal receipt with valid retained
// images, not confirmed durable publication or authority to recover, migrate
// or execute the historical plan.
type JournalInspection struct {
	id, kind, version, phase, planDigest, receiptDigest string
	status                                              InspectionStatus
	issues                                              []InspectionStatus
	sealed, terminal                                    bool
	sourceReferences                                    int
}

func (i JournalInspection) ID() string            { return i.id }
func (i JournalInspection) Kind() string          { return i.kind }
func (i JournalInspection) Version() string       { return i.version }
func (i JournalInspection) Phase() string         { return i.phase }
func (i JournalInspection) PlanDigest() string    { return i.planDigest }
func (i JournalInspection) ReceiptDigest() string { return i.receiptDigest }
func (i JournalInspection) Status() InspectionStatus {
	if i.status == "" {
		return InspectionUnresolved
	}
	return i.status
}

func (i JournalInspection) Issues() []InspectionStatus {
	return append([]InspectionStatus(nil), i.issues...)
}
func (i JournalInspection) Sealed() bool          { return i.sealed }
func (i JournalInspection) Terminal() bool        { return i.terminal }
func (i JournalInspection) SourceReferences() int { return i.sourceReferences }

// Durability never derives writer success from cached state or visible receipts.
func (i JournalInspection) Durability() ReceiptDurability {
	if i.sealed {
		return ReceiptDurabilityNotObserved
	}
	return ReceiptDurabilityUnverified
}

// InspectJournal is an optimistic, read-only observation of existing receipts.
// It never calls runtimeKey, privateDirectory, Open, Acquire, lock or a mutator.
func InspectJournal(ctx context.Context, runtime *trustload.Runtime, home, id string) (JournalInspection, error) {
	out := JournalInspection{id: id, status: InspectionUnsafe}
	if ctx == nil || runtime == nil || runtime.TrustRuntime() == nil || !inspectionID(id) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return out, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// An untrusted kind selects only a verifier; it never supplies admission.
	if raw, err := privateRead(filepath.Join(journalDir(home, id), "plan.json"), 128<<20); err == nil {
		var outer envelope
		var header struct {
			Kind string `json:"kind"`
		}
		if canonicaljson.DecodeStrict(raw, &outer) == nil && json.Unmarshal(outer.Payload, &header) == nil && header.Kind == NativeLinkKind {
			return inspectFirstMarker(ctx, runtime, home, id)
		}
	}
	pc := runtime.ProjectContext()
	trusted := runtime.TrustRuntime()
	if trusted == nil || pc.RootPath == "" || pc.ProjectID == "" || overlaps(pc.RootPath, home) {
		return out, ErrAuthentication
	}
	markerID, err := inspectionMarker(pc.RootPath)
	if err != nil {
		return out, err
	}
	if err := trusted.CheckProjectIdentity(ctx, pc.RootPath, markerID); err != nil {
		return out, err
	}
	dir := journalDir(home, id)
	planRaw, err := privateRead(filepath.Join(dir, "plan.json"), 128<<20)
	if err != nil {
		out.status = InspectionUnresolved
		return out, err
	}
	// The header is diagnostic only. Unknown layouts never supply a trusted phase.
	var outer envelope
	if err := canonicaljson.DecodeStrict(planRaw, &outer); err != nil {
		return out, errors.Join(ErrAuthentication, err)
	}
	var header struct {
		Version string `json:"apiVersion"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(outer.Payload, &header); err != nil {
		return out, errors.Join(ErrAuthentication, err)
	}
	out.version, out.kind = header.Version, header.Kind
	if header.Version != APIVersion {
		if strings.HasPrefix(header.Version, "tplaiter.dev/project-transaction/") {
			out.status = InspectionFuture
		}
		return out, nil
	}
	if header.Kind != NativeGeneratorKind && header.Kind != NativeUpdateKind {
		out.status = InspectionUnsupportedKind
		return out, nil
	}
	scratch := runtime.ScratchRoot()
	if scratch == "" || !filepath.IsAbs(scratch) || filepath.Clean(scratch) != scratch {
		return out, ErrAuthentication
	}
	// Read only an already existing runtime-owned authority. Missing authority
	// is reported, never initialized, and no value crosses this API boundary.
	key, err := privateRead(filepath.Join(scratch, "project-transaction-authority", "seal.key"), 32)
	if err != nil || len(key) != 32 {
		out.status = InspectionUnresolved
		return out, ErrAuthentication
	}
	defer func() { clear(key) }()
	tx := &Transaction{runtime: runtime, key: key, dir: dir, plan: immutable{Kind: header.Kind}}
	if err := tx.readSigned("plan.json", &tx.plan); err != nil {
		// A failed MAC against ONE selected runtime does not prove corruption of
		// another project's journal. An independently authenticated current-layout
		// state receipt can still establish this authority's conflicting plan.
		var state progress
		if stateErr := tx.readSigned("state.json", &state); stateErr != nil || state.APIVersion != APIVersion || state.Kind != header.Kind || state.ID != id {
			out.status = InspectionUnresolved
			return out, errors.Join(ErrInspectionUncovered, err)
		}
		return out, err
	}
	p := tx.plan
	if p.Material.Root != pc.RootPath || p.Material.ProjectID != pc.ProjectID {
		out.status = InspectionUnresolved
		return out, ErrInspectionUncovered
	}
	if p.APIVersion != APIVersion || p.Kind != header.Kind || p.ID != id || p.Material.Root != pc.RootPath || p.Material.Home != home || p.Material.ProjectID != pc.ProjectID || !p.Material.Binding.Equal(trusted.Binding()) {
		return out, ErrAuthentication
	}
	if err := inspectionMaterial(p.Material); err != nil {
		return out, err
	}
	if rootImage, ok := p.Material.Before["."]; ok {
		after, exists := p.Material.After["."]
		if !exists || !sameFile(rootImage, after) || (Identity{rootImage.Device, rootImage.Inode}) != p.RootIdentity {
			return out, ErrAuthentication
		}
	}

	stateRaw, err := privateRead(filepath.Join(dir, "state.json"), 128<<20)
	if err != nil {
		out.status = InspectionUnresolved
		return out, err
	}
	// A future progress layout is diagnostic only, just like a future plan.
	var stateEnvelope envelope
	if err := canonicaljson.DecodeStrict(stateRaw, &stateEnvelope); err != nil {
		return out, errors.Join(ErrAuthentication, err)
	}
	var stateHeader struct {
		Version string `json:"apiVersion"`
		Kind    string `json:"kind"`
	}
	if err := json.Unmarshal(stateEnvelope.Payload, &stateHeader); err != nil {
		return out, errors.Join(ErrAuthentication, err)
	}
	if stateHeader.Version != APIVersion {
		if strings.HasPrefix(stateHeader.Version, "tplaiter.dev/project-transaction/") {
			out.status = InspectionFuture
		}
		return out, nil
	}
	if stateHeader.Kind != NativeGeneratorKind && stateHeader.Kind != NativeUpdateKind {
		out.status = InspectionUnsupportedKind
		return out, nil
	}
	if err := tx.readSigned("state.json", &tx.state); err != nil {
		return out, err
	}
	s := tx.state
	if s.APIVersion != APIVersion || s.Kind != p.Kind || s.ID != id || s.Fingerprint != p.Material.Fingerprint {
		return out, ErrAuthentication
	}
	if err := tx.validateSteps(); err != nil {
		return out, err
	}
	status, terminal, err := inspectionPhase(s)
	if err != nil {
		return out, err
	}
	for _, bound := range []struct {
		name     string
		identity Identity
	}{{home, p.HomeIdentity}, {pc.RootPath, p.RootIdentity}} {
		info, err := confinedLstat(bound.name)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || bound.identity.Inode == 0 || fileID(info) != bound.identity {
			return out, ErrAuthentication
		}
	}
	info, err := confinedLstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return out, ErrAuthentication
	}
	tx.images = filepath.Join(pc.RootPath, ".tplaiter", "project-transactions", id)
	imageIssue := inspectImages(ctx, tx, terminal)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	refs, err := inspectionReferences(p.Material)
	if err != nil {
		return out, err
	}
	out.sourceReferences = len(refs)
	for _, ref := range refs {
		_, err := runtime.Read(ctx, ref)
		if err == nil {
			continue
		}
		if cause := ctx.Err(); cause != nil {
			return out, cause
		}
		if errors.Is(err, fs.ErrNotExist) {
			out.issues = appendInspectionIssue(out.issues, InspectionMissingCAS)
		} else {
			out.issues = appendInspectionIssue(out.issues, InspectionUnsafe)
		}
	}
	// Re-read both receipts before projecting a trusted phase. No optimistic
	// snapshot can silently combine a changing writer's plan and progress.
	for _, record := range []struct {
		name string
		raw  []byte
	}{{"plan.json", planRaw}, {"state.json", stateRaw}} {
		actual, err := privateRead(filepath.Join(dir, record.name), 128<<20)
		if err != nil || !bytes.Equal(actual, record.raw) {
			out.status = InspectionActive
			return out, ErrInspectionChanged
		}
	}
	if runtime.TrustRuntime() != trusted || runtime.ScratchRoot() != scratch {
		return out, ErrAuthentication
	}
	freshMarkerID, err := inspectionMarker(pc.RootPath)
	if err != nil {
		return out, err
	}
	if err := trusted.CheckProjectIdentity(ctx, pc.RootPath, freshMarkerID); err != nil {
		return out, err
	}
	out.sealed = true
	out.phase = s.Phase
	out.planDigest = evidencecas.Digest(planRaw)
	out.receiptDigest = evidencecas.Digest(stateRaw)
	out.status = status
	if imageIssue != "" {
		out.issues = appendInspectionIssue(out.issues, imageIssue)
		out.status = imageIssue
	}
	out.terminal = terminal && imageIssue == ""
	if slices.Contains(out.issues, InspectionUnsafe) {
		out.terminal = false
		out.status = InspectionUnsafe
	}
	if out.status == InspectionActive && slices.Contains(out.issues, InspectionMissingCAS) {
		out.status = InspectionMissingCAS
	}
	return out, nil
}

func inspectionID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func appendInspectionIssue(in []InspectionStatus, status InspectionStatus) []InspectionStatus {
	if !slices.Contains(in, status) {
		return append(in, status)
	}
	return in
}

func inspectionMaterial(m Material) error {
	if m.Fingerprint == "" || !strings.HasPrefix(m.Fingerprint, "sha256:") || len(m.Fingerprint) != 71 || !json.Valid(m.Intent) || len(m.Before) == 0 || len(m.After) == 0 {
		return ErrAuthentication
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(m.Fingerprint, "sha256:")); err != nil {
		return ErrAuthentication
	}
	for _, images := range []map[string]File{m.Before, m.After} {
		for name, image := range images {
			if !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.ContainsAny(name, "\\\x00\n\r") || name == "." && !image.Directory || image.Mode > 0o777 || len(image.Data) > 16<<20 || image.Directory && len(image.Data) != 0 {
				return ErrAuthentication
			}
		}
	}
	if m.Registry != nil {
		for _, image := range []File{m.Registry.Before, m.Registry.After} {
			if image.Directory || image.Mode > 0o777 || len(image.Data) > 16<<20 {
				return ErrAuthentication
			}
		}
		if m.Registry.Before.Inode == 0 {
			return ErrAuthentication
		}
	}
	for _, name := range m.ReadOnlyPaths {
		if _, ok := m.Before[name]; !ok {
			return ErrAuthentication
		}
		after, ok := m.After[name]
		if !ok || !sameFile(m.Before[name], after) {
			return ErrAuthentication
		}
	}
	return nil
}

func inspectionPhase(s progress) (InspectionStatus, bool, error) {
	switch s.Phase {
	case "preparing", "prepared", "applying", "rolling-back", "rollback-conflicts":
		return InspectionActive, false, nil
	case "committed":
		for _, step := range s.Steps {
			if !step.Intent || !step.Done || step.Undone {
				return InspectionUnsafe, false, ErrAuthentication
			}
		}
		return InspectionCommitted, true, nil
	case "rolled-back":
		for _, step := range s.Steps {
			if !step.Undone {
				return InspectionUnsafe, false, ErrAuthentication
			}
		}
		return InspectionRolledBack, true, nil
	default:
		return InspectionUnsafe, false, ErrAuthentication
	}
}

// Terminal images are checked against their retained side only. Present-day
// project targets can differ after later legitimate transactions and are not
// checked against an archived terminal plan.
func inspectImages(ctx context.Context, tx *Transaction, terminal bool) InspectionStatus {
	// Use the published engine's actual slot projections, including registry
	// slots held in the journal and deletions with no prepared afterimage.
	for _, bound := range []struct {
		name     string
		identity Identity
	}{{tx.images, tx.state.ImageIdentity}, {tx.dir, tx.state.ReceiptIdentity}} {
		info, err := confinedLstat(bound.name)
		if os.IsNotExist(err) {
			return InspectionMissingImages
		}
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || bound.identity.Inode == 0 || fileID(info) != bound.identity {
			return InspectionUnsafe
		}
	}
	for _, directory := range []string{tx.images, tx.dir} {
		allowed := map[string]bool{}
		if directory == tx.dir {
			allowed["plan.json"] = true
			allowed["state.json"] = true
		}
		for _, step := range tx.state.Steps {
			parent, _ := tx.slotDirectory(step)
			if parent == directory {
				allowed[step.Slot] = true
			}
		}
		entries, err := confinedReadDir(directory)
		if err != nil {
			return InspectionUnsafe
		}
		for _, entry := range entries {
			if !allowed[entry.Name()] {
				return InspectionUnsafe
			}
		}
	}
	for _, step := range tx.state.Steps {
		if ctx.Err() != nil {
			return InspectionUnsafe
		}
		before, after, existed := tx.stepFiles(step)
		slot := tx.slotPath(step)
		_, err := confinedLstat(slot)
		if step.Delete {
			// Before deletion/after rollback there is no slot. During an interrupted
			// intent either state is possible; current targets are deliberately ignored.
			mustAbsent := step.Undone || terminal && tx.state.Phase == "rolled-back" || !step.Intent
			mustPresent := step.Done && !step.Undone || terminal && tx.state.Phase == "committed"
			if mustAbsent {
				if !os.IsNotExist(err) {
					return InspectionUnsafe
				}
				continue
			}
			if os.IsNotExist(err) {
				if mustPresent {
					return InspectionMissingImages
				}
				continue
			}
			if checkPath(slot, before, Identity{before.Device, before.Inode}) != nil {
				return InspectionUnsafe
			}
			continue
		}
		if terminal && tx.state.Phase == "committed" {
			if !existed {
				if !os.IsNotExist(err) {
					return InspectionUnsafe
				}
				continue
			}
			if os.IsNotExist(err) {
				return InspectionMissingImages
			}
			if checkPath(slot, before, Identity{before.Device, before.Inode}) != nil {
				return InspectionUnsafe
			}
		} else if terminal || !step.Intent || step.Undone {
			if os.IsNotExist(err) {
				return InspectionMissingImages
			}
			if checkPath(slot, after, step.AfterIdentity) != nil {
				return InspectionUnsafe
			}
		} else if existed {
			if os.IsNotExist(err) {
				return InspectionMissingImages
			}
			if checkPath(slot, after, step.AfterIdentity) != nil && checkPath(slot, before, Identity{before.Device, before.Inode}) != nil {
				return InspectionUnsafe
			}
		} else if err != nil && !os.IsNotExist(err) {
			return InspectionUnsafe
		} else if err == nil && checkPath(slot, after, step.AfterIdentity) != nil {
			return InspectionUnsafe
		}
	}
	return ""
}

// References come from both sealed before/after lock pairs, not current mutable
// project files. This also covers both source closures of a native update.
func inspectionReferences(m Material) ([]string, error) {
	unique := map[string]bool{}
	for _, images := range []map[string]File{m.Before, m.After} {
		rootFile, rok := images[".tplaiter/root-template.lock.json"]
		dependencyFile, dok := images[".tplaiter/template.lock.json"]
		if !rok || !dok || rootFile.Directory || dependencyFile.Directory {
			return nil, ErrAuthentication
		}
		root, err := provenance.DecodeRootTemplateLock(rootFile.Data)
		if err != nil {
			return nil, errors.Join(ErrAuthentication, err)
		}
		dependencies, err := provenance.DecodeTemplateLock(dependencyFile.Data)
		if err != nil {
			return nil, errors.Join(ErrAuthentication, err)
		}
		if provenance.ValidateLockPair(*root, *dependencies) != nil || !root.TrustProfile.Equal(m.Binding) {
			return nil, ErrAuthentication
		}
		subjects := append([]provenance.DependencySubject{provenance.DependencySubject(root.Root)}, dependencies.Dependencies...)
		for _, subject := range subjects {
			for _, ref := range []string{subject.StatementCAS, subject.SignatureCAS, subject.CheckpointCAS, subject.InclusionProofCAS} {
				unique[ref] = true
			}
		}
	}
	refs := make([]string, 0, len(unique))
	for ref := range unique {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}

// inspectionMarker reads the CURRENT confined marker, not the historical plan
// image or the installed context's expected ID. Marker modes differ from private
// journal modes; privateRead therefore cannot be used for this ledger file.
func inspectionMarker(projectRoot string) (string, error) {
	name := filepath.Join(projectRoot, ".tplaiter/project.yaml")
	held, base, err := confinedParent(name)
	if err != nil {
		return "", err
	}
	defer held.Close()
	info, err := held.Lstat(base)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || !singleLink(info) || (info.Mode().Perm() != 0o644 && info.Mode().Perm() != 0o600) || info.Size() > 1<<20 {
		return "", ErrAuthentication
	}
	file, err := held.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", ErrAuthentication
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return "", err
	}
	if len(raw) > 1<<20 {
		return "", ErrAuthentication
	}
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return "", errors.Join(ErrAuthentication, err)
	}
	if !inspectionMarkerNodes(&document) {
		return "", ErrAuthentication
	}
	var marker stateledger.ProjectV2
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&marker); err != nil {
		return "", errors.Join(ErrAuthentication, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", ErrAuthentication
	}
	if marker.APIVersion != stateledger.ProjectV2APIVersion || marker.Kind != "Project" || marker.ID == "" {
		return "", ErrAuthentication
	}
	fresh, err := held.Lstat(base)
	if err != nil || !os.SameFile(info, fresh) || fresh.Mode() != info.Mode() || fresh.Size() != info.Size() || !fresh.ModTime().Equal(info.ModTime()) || checkStorageParent(held, name) != nil {
		return "", ErrInspectionChanged
	}
	return marker.ID, nil
}

func inspectionMarkerNodes(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode {
		return false
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if !inspectionMarkerNodes(child) {
			return false
		}
	}
	return true
}
