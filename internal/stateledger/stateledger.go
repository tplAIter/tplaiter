package stateledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/naming"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	inventory "github.com/tplAIter/tplaiter/internal/projecttransaction/inventory/catalog"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// Wire identities.
const (
	// ProjectV1 is the legacy project marker (manifest.APIVersion).
	ProjectV1 = "tplater.dev/v1alpha1"
	// ProjectV2APIVersion is the ledger-backed project marker.
	ProjectV2APIVersion = "tplaiter.dev/project/v2"
	StatePlanV1         = "tplaiter.dev/state-migration-plan/v1"
	StateReportV1       = "tplaiter.dev/state-ledger-report/v1"
)

// StateDir is the project state directory every ledger lives in.
const StateDir = naming.ProjectDir

var (
	ErrFutureVersion = errors.New("stateledger: future state version")
	ErrDowngrade     = errors.New("stateledger: downgrade is not supported")
	ErrUnsafe        = errors.New("stateledger: unsafe state")
	ErrPolicyOrigin  = errors.New("stateledger: lock is not bound to the verified trust profile")
	ErrDigest        = errors.New("stateledger: sealed digest mismatch")
	ErrEvidence      = errors.New("stateledger: evidence unavailable or invalid")
	// ErrProjectIdentity reports an absent fresh project check or a marker/root mismatch.
	ErrProjectIdentity = errors.New("stateledger: project identity is not bound to the selected installed context")
	// ErrLegacyLock reports a profileless v1 root or dependency lock. It must
	// be re-resolved through the trust runtime (update) before the ledger can
	// accept it; the ledger never upgrades trust evidence by itself.
	ErrLegacyLock = errors.New("stateledger: legacy v1 lock is not bound to a trust profile")
)

// BindingAuthority is the verified trust runtime seen by the ledger.
// *trustverify.Runtime implements it. The development runtime deliberately
// does not (it has no CheckBinding), and a development binding is refused at
// runtime as well, so an unverified profile can never vouch for stable state.
type BindingAuthority interface {
	Binding() bootstrap.ProfileBinding
	CheckBinding(bootstrap.ProfileBinding) error
}

// ProjectIdentityAuthority checks observed marker/root data using a fresh
// authenticated project reader. A profile binding alone cannot vouch for it.
// Both strings are observations, never caller-provided expected authority.
type ProjectIdentityAuthority interface {
	CheckProjectIdentity(context.Context, string, string) error
}

var _ ProjectIdentityAuthority = (*trustverify.Runtime)(nil)

var _ BindingAuthority = (*trustverify.Runtime)(nil)

// RootEvidence is supplied by a verifier after it checked the actual root
// lock. It cannot be injected through Options.
type RootEvidence struct {
	Origin         string
	TemplatePath   string
	RequestedRef   string
	Commit         string
	RootLockSHA256 string
}

// RootVerifier re-verifies the project's root lock against its source.
type RootVerifier interface {
	VerifyRoot(context.Context, string) (RootEvidence, error)
}

// ManifestEvidence proves that the locked root template declares no
// dependencies, extends or blocks, which is the only case in which an empty
// dependency lock may be synthesized.
type ManifestEvidence struct {
	ManifestSHA256 string
	RootLockSHA256 string
	RootCommit     string
	NoDependencies bool
	NoExtends      bool
	NoBlocks       bool
}

// ManifestVerifier produces ManifestEvidence for the verified root.
type ManifestVerifier interface {
	VerifyDependencyFree(context.Context, string, RootEvidence) (ManifestEvidence, error)
}

// SecretLocator deliberately contains no absolute host path.
type SecretLocator struct {
	RootID       string
	RelativePath string
	Mode         uint32
}

// SecretDigestResult classifies one home file. A classified file is never
// opened by the ledger; the provider supplies its digest.
type SecretDigestResult struct {
	Classified bool
	Digest     string
}

// SecretDigestProvider is consulted for every home file before it is opened.
type SecretDigestProvider interface {
	DigestSecret(context.Context, SecretLocator) (SecretDigestResult, error)
}

// ProtectedReceipt represents platform evidence only; no raw secure-store
// path or bytes can enter plans or reports.
type ProtectedReceipt struct {
	AuthorityID             string `json:"authorityId"`
	HighestAcceptedSequence uint64 `json:"highestAcceptedSequence"`
	EnvelopePayloadSHA256   string `json:"envelopePayloadSHA256"`
	RevocationEpoch         uint64 `json:"revocationEpoch"`
	CheckpointDigest        string `json:"checkpointDigest"`
	TreeSize                uint64 `json:"treeSize"`
	JournalStatus           string `json:"journalStatus"`
	JournalDigest           string `json:"journalDigest"`
	Backend                 string `json:"backend"`
	Protection              string `json:"protection"`
	BackendProtected        bool   `json:"backendProtected"`
}

// Options configures Inventory and Plan.
type Options struct {
	HomeRoot         string
	SecretProvider   SecretDigestProvider
	ProtectedReceipt *ProtectedReceipt
	RootVerifier     RootVerifier
	ManifestVerifier ManifestVerifier
}

// StableVerifyOptions contains only read-only verification dependencies.
type StableVerifyOptions struct {
	HomeRoot string
	CAS      evidencecas.Reader
	// SecretProvider is called before any home file is opened. It is required
	// when HomeRoot is set and must classify credential files.
	SecretProvider SecretDigestProvider
}

// VerifyStable validates the complete committed state inventory and its
// sealed root/dependency locks without creating caches, contacting Git, or
// writing any state. The returned snapshot is an observation and must not be
// treated as an authorization token.
func VerifyStable(ctx context.Context, projectRoot string, authority BindingAuthority, opts StableVerifyOptions) (*Snapshot, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context required", ErrUnsafe)
	}
	if err := requireStable(authority); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, home, err := validateRoots(projectRoot, opts.HomeRoot)
	if err != nil {
		return nil, err
	}
	marker, markerMode, err := stableReadWithMode(filepath.Join(root, StateDir, "project.yaml"))
	if err != nil {
		return nil, fmt.Errorf("%w: project marker: %w", ErrUnsafe, err)
	}
	var project ProjectV2
	if err := decodeYAMLStrict(marker, &project); err != nil {
		return nil, fmt.Errorf("%w: project marker: %w", ErrUnsafe, err)
	}
	if err := validateV2(project); err != nil {
		return nil, err
	}
	if err := checkProjectIdentity(ctx, authority, root, project.ID); err != nil {
		return nil, err
	}
	snapshot, err := InventoryContext(ctx, root, Options{HomeRoot: home, SecretProvider: opts.SecretProvider})
	if err != nil {
		return nil, err
	}
	if err := checkMarkerInventory(snapshot, marker, markerMode); err != nil {
		return nil, err
	}
	if err := validateJournalState(snapshot.Entries, home); err != nil {
		return nil, err
	}
	for _, pointer := range project.State.all() {
		if !safeRelative(pointer) || !strings.HasPrefix(pointer, StateDir+"/") {
			return nil, fmt.Errorf("%w: invalid state pointer %q", ErrUnsafe, pointer)
		}
		if _, err := stableRead(filepath.Join(root, filepath.FromSlash(pointer))); err != nil {
			return nil, fmt.Errorf("%w: required ledger %s: %w", ErrUnsafe, pointer, err)
		}
	}
	rootLock, dependencyLock, err := readLockPair(root)
	if err != nil {
		return nil, err
	}
	if err := authority.CheckBinding(rootLock.TrustProfile); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafe, ErrPolicyOrigin)
	}
	if opts.CAS != nil {
		if err := verifyLockEvidence(ctx, opts.CAS, rootLock, dependencyLock); err != nil {
			return nil, err
		}
	}
	// Reobserve the actual marker, not just the identity cached before inventory.
	currentMarker, currentMode, err := stableReadWithMode(filepath.Join(root, StateDir, "project.yaml"))
	if err != nil {
		return nil, fmt.Errorf("%w: project marker reobservation: %w", ErrUnsafe, err)
	}
	var currentProject ProjectV2
	if err := decodeYAMLStrict(currentMarker, &currentProject); err != nil {
		return nil, fmt.Errorf("%w: project marker reobservation: %w", ErrUnsafe, err)
	}
	if err := validateV2(currentProject); err != nil {
		return nil, err
	}
	if !bytes.Equal(marker, currentMarker) || markerMode != currentMode {
		return nil, fmt.Errorf("%w: project marker observation changed", ErrUnsafe)
	}
	if err := checkMarkerInventory(snapshot, currentMarker, currentMode); err != nil {
		return nil, err
	}
	if err := checkProjectIdentity(ctx, authority, root, currentProject.ID); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// VerifyDependencyLocks validates the canonical root and dependency lock
// pair without requiring the rest of the project state. It is the narrow
// read-only boundary used by `deps verify`: an empty dependency list is
// accepted only after strict decoding, root binding and self-hash validation
// have succeeded, and every referenced evidence object must be present in cas.
func VerifyDependencyLocks(ctx context.Context, projectRoot string, authority BindingAuthority, cas evidencecas.Reader) error {
	if err := requireStable(authority); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, _, err := validateRoots(projectRoot, "")
	if err != nil {
		return err
	}
	rootLock, dependencyLock, err := readLockPair(root)
	if err != nil {
		return err
	}
	if err := authority.CheckBinding(rootLock.TrustProfile); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafe, ErrPolicyOrigin)
	}
	if cas == nil {
		return fmt.Errorf("%w: read-only evidence CAS is required", ErrUnsafe)
	}
	return verifyLockEvidence(ctx, cas, rootLock, dependencyLock)
}

func requireStable(authority BindingAuthority) error {
	if authority == nil {
		return fmt.Errorf("%w: stable verified authority required", ErrUnsafe)
	}
	binding := authority.Binding()
	if binding.Validate() != nil || binding.ID == bootstrap.ProfileDevelopment {
		return fmt.Errorf("%w: stable verified authority required", ErrUnsafe)
	}
	return nil
}

// Entry is one inventoried state file.
type Entry struct {
	Scope          string `json:"scope"`
	Path           string `json:"path"`
	Classification string `json:"classification"`
	Owner          string `json:"owner"`
	WireVersion    string `json:"wireVersion,omitempty"`
	Kind           string `json:"kind"`
	Mode           uint32 `json:"mode"`
	SHA256         string `json:"sha256"`
	Retention      string `json:"retention"`
	Exists         bool   `json:"exists"`
	Target         string `json:"target,omitempty"`
}

// Snapshot is a deterministic, sorted inventory.
type Snapshot struct {
	APIVersion string  `json:"apiVersion"`
	Entries    []Entry `json:"entries"`
	// Transactions is the global new-transaction inventory (home scope only).
	Transactions []newtransaction.TransactionStatus `json:"-"`
	// ProjectTransactionCandidates are namespace observations only; they do not
	// authenticate a phase or replace the transaction guards.
	ProjectTransactionCandidates []inventory.Candidate `json:"-"`
}

// Report is the sealed outcome of a planned or applied ledger migration.
type Report struct {
	APIVersion   string           `json:"apiVersion"`
	ProjectID    string           `json:"projectID"`
	PlanSHA256   string           `json:"planSHA256"`
	Receipt      ProtectedReceipt `json:"receipt"`
	Entries      []ReportEntry    `json:"entries"`
	TestOutcomes []TestOutcome    `json:"testOutcomes"`
	Result       string           `json:"result"`
	ReportSHA256 string           `json:"reportSHA256"`
}

// ReportEntry records one mutated ledger.
type ReportEntry struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"beforeSHA256"`
	AfterSHA256  string `json:"afterSHA256"`
	Action       string `json:"action"`
	Retention    string `json:"retention"`
}

// TestOutcome records one verification run attached to a report.
type TestOutcome struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

// Seal computes the report's domain-separated self hash.
func (r Report) Seal() (Report, error) {
	if err := validReceipt(r.Receipt); err != nil {
		return r, err
	}
	r.ReportSHA256 = ""
	h, e := SelfHashDomain(r, "reportSHA256", StateReportV1+"\x00")
	r.ReportSHA256 = h
	return r, e
}

// Inventory has no write operation. It lists the project state directory
// and, when HomeRoot is set, the home directory (except the rebuildable
// repository clone cache). Every home file is classified by the secret
// provider before it is opened; classified credentials are never read.
func Inventory(projectRoot string, opts Options) (*Snapshot, error) {
	return InventoryContext(context.Background(), projectRoot, opts)
}

// InventoryContext is Inventory with a caller context passed to the secret
// provider.
func InventoryContext(ctx context.Context, projectRoot string, opts Options) (*Snapshot, error) {
	p, h, err := validateRoots(projectRoot, opts.HomeRoot)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{APIVersion: StatePlanV1, Entries: []Entry{}}
	stateDir := filepath.Join(p, StateDir)
	if info, statErr := os.Lstat(stateDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: %s is not a real directory", ErrUnsafe, StateDir)
		}
		if err = inventoryRoot(ctx, s, "project", stateDir, StateDir+"/", nil); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nil, statErr
	}
	if h != "" {
		if opts.SecretProvider == nil {
			return nil, fmt.Errorf("%w: home secret provider required", ErrUnsafe)
		}
		if err = inventoryRoot(ctx, s, "home", h, "", opts.SecretProvider); err != nil {
			return nil, err
		}
		if s.Transactions, err = newtransaction.Inventory(h); err != nil {
			return nil, err
		}
	}
	if s.ProjectTransactionCandidates, err = inventory.Discover(ctx, p, h); err != nil {
		return nil, err
	}
	if opts.ProtectedReceipt != nil {
		if err = validReceipt(*opts.ProtectedReceipt); err != nil {
			return nil, err
		}
		b, e := canonicaljson.Canonical(opts.ProtectedReceipt)
		if e != nil {
			return nil, e
		}
		s.Entries = append(s.Entries, Entry{Scope: "protected", Path: "receipt", Classification: "protected-receipt", Owner: "platform-security", WireVersion: "v1", Kind: "external", SHA256: sha(b), Retention: "external", Exists: true})
	}
	sortEntries(s.Entries)
	return s, nil
}

func inventoryRoot(ctx context.Context, s *Snapshot, scope, root, prefix string, provider SecretDigestProvider) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return fmt.Errorf("%w: relative path", ErrUnsafe)
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// The clone cache is rebuildable and can be large; it is not a ledger.
			if scope == "home" && rel == "repos" {
				return filepath.SkipDir
			}
			return nil
		}
		if !safeRelative(rel) {
			return fmt.Errorf("%w: path escape", ErrUnsafe)
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		kind := "file"
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		var class ledgerpath.Class
		if scope == "project" {
			if observed, reserved := ledgerpath.ProjectTransactionImage(rel); reserved {
				class = observed
			} else {
				class = ledgerpath.Project(rel)
			}
		} else {
			if observed, reserved := ledgerpath.HomeProjectTransaction(rel); reserved {
				class = observed
			} else {
				class = ledgerpath.Home(rel)
			}
		}
		digest := ""
		if scope == "home" {
			result, e := provider.DigestSecret(ctx, SecretLocator{RootID: "home", RelativePath: rel, Mode: uint32(info.Mode().Perm())})
			if e != nil {
				return e
			}
			if result.Classified {
				if !validDigest(result.Digest) {
					return fmt.Errorf("%w: secret digest", ErrUnsafe)
				}
				class = ledgerpath.Class{Classification: "secret", Owner: "credential-store", Retention: "opaque"}
				digest = result.Digest
			}
		}
		if digest == "" {
			b, e := readEntry(path, kind)
			if e != nil {
				return e
			}
			digest = sha(b)
		}
		entry := Entry{Scope: scope, Path: prefix + rel, Classification: class.Classification, Owner: class.Owner, WireVersion: class.WireVersion, Kind: kind, Mode: uint32(info.Mode().Perm()), SHA256: digest, Retention: class.Retention, Exists: true}
		if kind == "symlink" {
			entry.Target, e = os.Readlink(path)
			if e != nil {
				return e
			}
		}
		s.Entries = append(s.Entries, entry)
		return nil
	})
}

func readEntry(path, kind string) ([]byte, error) {
	if kind == "symlink" {
		s, e := os.Readlink(path)
		return []byte(s), e
	}
	return stableRead(path)
}

func validateRoots(project, home string) (string, string, error) {
	p, e := realRoot(project)
	if e != nil {
		return "", "", e
	}
	if home == "" {
		return p, "", nil
	}
	h, e := realRoot(home)
	if e != nil {
		return "", "", e
	}
	if overlaps(p, h) {
		return "", "", fmt.Errorf("%w: project and home roots overlap", ErrUnsafe)
	}
	return p, h, nil
}

func realRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: root must be absolute", ErrUnsafe)
	}
	clean := filepath.Clean(root)
	i, e := os.Lstat(clean)
	if e != nil {
		return "", e
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: root must be real directory", ErrUnsafe)
	}
	resolved, e := filepath.EvalSymlinks(clean)
	if e != nil {
		return "", e
	}
	// macOS exposes /var through /private/var. Compare identity rather than
	// lexical spelling, while still rejecting a final symlink above.
	realInfo, e := os.Stat(resolved)
	if e != nil || !os.SameFile(i, realInfo) {
		return "", fmt.Errorf("%w: root alias", ErrUnsafe)
	}
	return clean, nil
}

func overlaps(a, b string) bool {
	inside := func(parent, child string) bool {
		r, e := filepath.Rel(parent, child)
		return e == nil && (r == "." || (r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))))
	}
	return inside(a, b) || inside(b, a)
}

func safeRelative(p string) bool {
	return p != "" && p != "." && !filepath.IsAbs(p) && p != ".." && !strings.HasPrefix(p, "../")
}

func sha(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validDigest(v string) bool { return digestRE.MatchString(v) }

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Scope != es[j].Scope {
			return es[i].Scope < es[j].Scope
		}
		return es[i].Path < es[j].Path
	})
}

// ProjectV2 is the ledger-backed project marker.
type ProjectV2 struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	ID         string            `yaml:"id" json:"id"`
	Template   TemplateIdentity  `yaml:"template" json:"template"`
	Project    map[string]any    `yaml:"project" json:"project"`
	Answers    map[string]Answer `yaml:"answers" json:"answers"`
	Runtime    map[string]any    `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	Ownership  map[string]any    `yaml:"ownership,omitempty" json:"ownership,omitempty"`
	State      StatePointers     `yaml:"state" json:"state"`
}

// TemplateIdentity pins the template a project was rendered from.
type TemplateIdentity struct {
	Repo           string `yaml:"repo" json:"repo"`
	Name           string `yaml:"name" json:"name"`
	RequestedRef   string `yaml:"requestedRef" json:"requestedRef"`
	ResolvedCommit string `yaml:"resolvedCommit" json:"resolvedCommit"`
}

// Answer is one recorded settings answer and where it came from.
type Answer struct {
	Value  any    `yaml:"value" json:"value"`
	Source string `yaml:"source" json:"source"`
}

// StatePointers names every ledger file. The values are fixed (see
// StandardPointers); they are recorded so a reader can refuse a marker that
// points anywhere else.
type StatePointers struct {
	RootLock         string `yaml:"rootLock" json:"rootLock"`
	DependencyLock   string `yaml:"dependencyLock" json:"dependencyLock"`
	Baseline         string `yaml:"baseline" json:"baseline"`
	Ownership        string `yaml:"ownership" json:"ownership"`
	Resources        string `yaml:"resources" json:"resources"`
	AIManaged        string `yaml:"aiManaged" json:"aiManaged"`
	GeneratorTargets string `yaml:"generatorTargets" json:"generatorTargets"`
	ManagedBlocks    string `yaml:"managedBlocks" json:"managedBlocks"`
	Migrations       string `yaml:"migrations" json:"migrations"`
}

func (p StatePointers) all() []string {
	return []string{p.RootLock, p.DependencyLock, p.Baseline, p.Ownership, p.Resources, p.AIManaged, p.GeneratorTargets, p.ManagedBlocks, p.Migrations}
}

// StandardPointers returns the only accepted state pointer set.
func StandardPointers() StatePointers {
	at := func(name string) string { return StateDir + "/" + name }
	return StatePointers{
		RootLock: at(RootLockFile), DependencyLock: at(DependencyLockFile), Baseline: at("baseline.json"),
		Ownership: at("ownership.json"), Resources: at("resources.lock.json"), AIManaged: at("ai-managed.json"),
		GeneratorTargets: at("generator-targets.lock.json"), ManagedBlocks: at("managed-blocks.json"), Migrations: at("migrations.json"),
	}
}

// Lock file names inside StateDir.
const (
	RootLockFile       = "root-template.lock.json"
	DependencyLockFile = "template.lock.json"
)

// MigrationPlan is a sealed, pure description of a marker migration. The
// byte images it carries are applied only by ApplyPlan.
type MigrationPlan struct {
	APIVersion         string     `json:"apiVersion"`
	ProjectID          string     `json:"projectID"`
	From               string     `json:"from"`
	To                 string     `json:"to"`
	Entries            []Entry    `json:"entries"`
	Mutations          []Mutation `json:"mutations"`
	PlanSHA256         string     `json:"planSHA256"`
	ProjectYAML        []byte     `json:"-"`
	DependencyLockJSON []byte     `json:"-"`
}

// Mutation is one planned ledger change.
type Mutation struct {
	Path         string `json:"path"`
	Action       string `json:"action"`
	BeforeSHA256 string `json:"beforeSHA256,omitempty"`
	AfterSHA256  string `json:"afterSHA256,omitempty"`
}

// Plan builds the migration plan to the current marker version.
func Plan(projectRoot string, opts Options) (*MigrationPlan, error) {
	return PlanContext(context.Background(), projectRoot, opts)
}

// PlanContext builds a migration plan with cancellation propagated through
// inventory and concrete evidence verification.
func PlanContext(ctx context.Context, projectRoot string, opts Options) (*MigrationPlan, error) {
	return PlanTargetContext(ctx, projectRoot, opts, ProjectV2APIVersion)
}

// PlanTarget builds a migration plan to target. Only the current marker
// version is a valid target: downgrades are refused.
func PlanTarget(projectRoot string, opts Options, target string) (*MigrationPlan, error) {
	return PlanTargetContext(context.Background(), projectRoot, opts, target)
}

// PlanTargetContext is the cancellable form of PlanTarget.
func PlanTargetContext(ctx context.Context, projectRoot string, opts Options, target string) (*MigrationPlan, error) {
	if ctx == nil {
		return nil, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if target != ProjectV2APIVersion {
		return nil, ErrDowngrade
	}
	projectRoot, _, e := validateRoots(projectRoot, opts.HomeRoot)
	if e != nil {
		return nil, e
	}
	data, e := stableRead(filepath.Join(projectRoot, StateDir, "project.yaml"))
	if e != nil {
		return nil, e
	}
	version, e := yamlVersion(data)
	if e != nil {
		return nil, e
	}
	inv, e := InventoryContext(ctx, projectRoot, opts)
	if e != nil {
		return nil, e
	}
	if e = validateJournalState(inv.Entries, opts.HomeRoot); e != nil {
		return nil, e
	}
	if version == ProjectV2APIVersion {
		var v ProjectV2
		if e = decodeYAMLStrict(data, &v); e != nil {
			return nil, fmt.Errorf("%w: v2 marker: %w", ErrUnsafe, e)
		}
		if e = validateV2(v); e != nil {
			return nil, e
		}
		if _, _, e = readLockPair(projectRoot); e != nil {
			return nil, e
		}
		return sealPlan(&MigrationPlan{APIVersion: StatePlanV1, ProjectID: v.ID, From: ProjectV2APIVersion, To: ProjectV2APIVersion, Entries: inv.Entries, Mutations: []Mutation{}})
	}
	if version != ProjectV1 {
		return nil, ErrFutureVersion
	}
	var old legacyProject
	if e = decodeYAMLStrict(data, &old); e != nil {
		return nil, fmt.Errorf("%w: v1 marker: %w", ErrUnsafe, e)
	}
	if old.Kind != "Project" || old.ID == "" {
		return nil, fmt.Errorf("%w: invalid v1 project", ErrUnsafe)
	}
	if opts.RootVerifier == nil {
		return nil, fmt.Errorf("%w: root verifier required", ErrUnsafe)
	}
	evidence, e := opts.RootVerifier.VerifyRoot(ctx, projectRoot)
	if e != nil {
		return nil, fmt.Errorf("%w: root verification: %w", ErrUnsafe, e)
	}
	if e = validRootEvidence(evidence); e != nil {
		return nil, e
	}
	rootLock, e := verifyRootLock(filepath.Join(projectRoot, StateDir, RootLockFile), evidence)
	if e != nil {
		return nil, e
	}
	v2 := ProjectV2{APIVersion: ProjectV2APIVersion, Kind: "Project", ID: old.ID, Template: TemplateIdentity{Repo: old.Template.Repo, Name: old.Template.Name, RequestedRef: evidence.RequestedRef, ResolvedCommit: evidence.Commit}, Project: nonNil(old.Project), Runtime: old.Runtime, Answers: map[string]Answer{}, State: StandardPointers()}
	for k, v := range old.Settings {
		v2.Answers[k] = Answer{Value: v, Source: "legacy"}
	}
	after, e := yaml.Marshal(v2)
	if e != nil {
		return nil, e
	}
	plan := &MigrationPlan{APIVersion: StatePlanV1, ProjectID: old.ID, From: ProjectV1, To: ProjectV2APIVersion, Entries: inv.Entries, ProjectYAML: after, Mutations: []Mutation{{Path: StateDir + "/project.yaml", Action: "migrate", BeforeSHA256: sha(data), AfterSHA256: sha(after)}}}
	dep := filepath.Join(projectRoot, StateDir, DependencyLockFile)
	if _, e = os.Lstat(dep); errors.Is(e, fs.ErrNotExist) {
		if opts.ManifestVerifier == nil {
			return nil, fmt.Errorf("%w: manifest verifier required", ErrUnsafe)
		}
		proof, e := opts.ManifestVerifier.VerifyDependencyFree(ctx, projectRoot, evidence)
		if e != nil {
			return nil, fmt.Errorf("%w: manifest verification: %w", ErrUnsafe, e)
		}
		lock, e := synthesizeEmptyDependencyLock(rootLock, evidence, proof)
		if e != nil {
			return nil, e
		}
		plan.DependencyLockJSON = lock
		plan.Mutations = append(plan.Mutations, Mutation{Path: StateDir + "/" + DependencyLockFile, Action: "synthesize", AfterSHA256: sha(lock)})
	} else if e != nil {
		return nil, e
	} else if _, _, e = readLockPair(projectRoot); e != nil {
		return nil, e
	}
	return sealPlan(plan)
}

// legacyProject is the closed v1alpha1 marker as written by `new`.
type legacyProject struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	ID         string `yaml:"id"`
	Template   struct {
		Repo    string `yaml:"repo"`
		Name    string `yaml:"name"`
		Version string `yaml:"version"`
	} `yaml:"template"`
	Settings  map[string]any `yaml:"settings"`
	Project   map[string]any `yaml:"project"`
	Runtime   map[string]any `yaml:"runtime"`
	Baseline  string         `yaml:"baseline"`
	Ownership map[string]any `yaml:"ownership"`
}

func nonNil(v map[string]any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	return v
}

// stableRead reads a regular, non-symlink ledger and fails if it changed
// while it was open.
func stableRead(path string) ([]byte, error) {
	raw, _, err := stableReadWithMode(path)
	return raw, err
}

// stableReadWithMode captures bytes and mode from the same held regular file.
func stableReadWithMode(path string) ([]byte, uint32, error) {
	a, e := os.Lstat(path)
	if e != nil {
		return nil, 0, e
	}
	if a.Mode()&os.ModeSymlink != 0 || !a.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%w: symlink/non-file ledger", ErrUnsafe)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, 0, e
	}
	defer func() { _ = f.Close() }()
	opened, e := f.Stat()
	if e != nil {
		return nil, 0, e
	}
	if !os.SameFile(a, opened) || opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%w: ledger changed while open", ErrUnsafe)
	}
	b, e := io.ReadAll(f)
	if e != nil {
		return nil, 0, e
	}
	closed, e := f.Stat()
	if e != nil {
		return nil, 0, e
	}
	if !os.SameFile(opened, closed) || opened.Size() != closed.Size() || opened.ModTime() != closed.ModTime() || opened.Mode() != closed.Mode() || int64(len(b)) != opened.Size() {
		return nil, 0, fmt.Errorf("%w: ledger changed while read", ErrUnsafe)
	}
	return b, uint32(opened.Mode()), nil
}

func yamlVersion(data []byte) (string, error) {
	var raw struct {
		APIVersion string `yaml:"apiVersion"`
	}
	// Version peeking must not apply the v1/v2 closed field set before we know
	// which one applies. Still reject duplicate keys and nulls first.
	var n yaml.Node
	if e := yaml.Unmarshal(data, &n); e != nil {
		return "", fmt.Errorf("%w: marker: %w", ErrUnsafe, e)
	}
	if e := rejectYAMLNode(&n); e != nil {
		return "", fmt.Errorf("%w: marker: %w", ErrUnsafe, e)
	}
	if e := yaml.Unmarshal(data, &raw); e != nil {
		return "", fmt.Errorf("%w: marker: %w", ErrUnsafe, e)
	}
	if raw.APIVersion == "" {
		return "", fmt.Errorf("%w: missing apiVersion", ErrUnsafe)
	}
	return raw.APIVersion, nil
}

func decodeYAMLStrict(data []byte, dst any) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	var n yaml.Node
	if e := d.Decode(&n); e != nil {
		return e
	}
	if e := rejectYAMLNode(&n); e != nil {
		return e
	}
	b, e := yaml.Marshal(&n)
	if e != nil {
		return e
	}
	d = yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(dst); e != nil {
		return e
	}
	var extra any
	if e = d.Decode(&extra); !errors.Is(e, io.EOF) {
		return errors.New("multiple YAML documents")
	}
	return nil
}

func rejectYAMLNode(n *yaml.Node) error {
	if n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			if e := rejectYAMLNode(c); e != nil {
				return e
			}
		}
		return nil
	}
	if n.Tag == "!!null" {
		return errors.New("null is forbidden")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || seen[k.Value] {
				return errors.New("duplicate/non-scalar YAML key")
			}
			seen[k.Value] = true
			if e := rejectYAMLNode(n.Content[i+1]); e != nil {
				return e
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if e := rejectYAMLNode(c); e != nil {
			return e
		}
	}
	return nil
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func validateV2(p ProjectV2) error {
	if p.APIVersion != ProjectV2APIVersion || p.Kind != "Project" || p.ID == "" || p.Template.Repo == "" || p.Template.Name == "" || p.Template.RequestedRef == "" || !commitRE.MatchString(p.Template.ResolvedCommit) || p.Project == nil || p.Answers == nil || p.State != StandardPointers() {
		return fmt.Errorf("%w: incomplete/noncanonical v2 marker", ErrUnsafe)
	}
	for _, a := range p.Answers {
		switch a.Source {
		case "legacy", "user", "default", "migration":
		default:
			return fmt.Errorf("%w: answer source", ErrUnsafe)
		}
	}
	return nil
}

func validRootEvidence(e RootEvidence) error {
	if e.Origin == "" || e.TemplatePath == "" || e.RequestedRef == "" || !commitRE.MatchString(e.Commit) || !validDigest(e.RootLockSHA256) {
		return fmt.Errorf("%w: incomplete root evidence", ErrUnsafe)
	}
	return nil
}

// verifyRootLock reads the sealed root lock and requires it to match the
// verifier's evidence exactly.
func verifyRootLock(path string, evidence RootEvidence) (*provenance.RootTemplateLock, error) {
	lock, err := readVerifiedRootLock(path)
	if err != nil {
		return nil, err
	}
	if lock.RootLockSHA256 != evidence.RootLockSHA256 || lock.Root.Origin != evidence.Origin || lock.Root.TemplatePath != evidence.TemplatePath || lock.Root.RequestedRef != evidence.RequestedRef || lock.Root.Commit != evidence.Commit {
		return nil, fmt.Errorf("%w: root lock does not match verified evidence", ErrUnsafe)
	}
	return lock, nil
}

// readVerifiedRootLock strictly decodes and self-hash-validates a v2 root
// lock through the canonical provenance model.
func readVerifiedRootLock(path string) (*provenance.RootTemplateLock, error) {
	b, err := stableRead(path)
	if err != nil {
		return nil, fmt.Errorf("%w: root lock: %w", ErrUnsafe, err)
	}
	lock, err := provenance.DecodeRootTemplateLock(b)
	if errors.Is(err, provenance.ErrLegacyUnbound) {
		return nil, fmt.Errorf("%w: %w", ErrUnsafe, ErrLegacyLock)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w: root lock: %w", ErrUnsafe, ErrDigest, err)
	}
	return lock, nil
}

func readDependencyLock(path string) (*provenance.TemplateLock, error) {
	b, err := stableRead(path)
	if err != nil {
		return nil, fmt.Errorf("%w: dependency lock: %w", ErrUnsafe, err)
	}
	lock, err := provenance.DecodeTemplateLock(b)
	if errors.Is(err, provenance.ErrLegacyUnbound) {
		return nil, fmt.Errorf("%w: %w", ErrUnsafe, ErrLegacyLock)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w: dependency lock: %w", ErrUnsafe, ErrDigest, err)
	}
	return lock, nil
}

// readLockPair reads both project locks and validates their binding.
func readLockPair(projectRoot string) (*provenance.RootTemplateLock, *provenance.TemplateLock, error) {
	root, err := readVerifiedRootLock(filepath.Join(projectRoot, StateDir, RootLockFile))
	if err != nil {
		return nil, nil, err
	}
	dependencies, err := readDependencyLock(filepath.Join(projectRoot, StateDir, DependencyLockFile))
	if err != nil {
		return nil, nil, err
	}
	if err := provenance.ValidateLockPair(*root, *dependencies); err != nil {
		return nil, nil, fmt.Errorf("%w: %w: %w", ErrUnsafe, ErrDigest, err)
	}
	return root, dependencies, nil
}

// synthesizeEmptyDependencyLock creates the dependency lock of a verified
// dependency-free root. It is the only path that invents a dependency lock,
// and it always writes an explicit, empty dependencies array.
func synthesizeEmptyDependencyLock(root *provenance.RootTemplateLock, evidence RootEvidence, proof ManifestEvidence) ([]byte, error) {
	if e := validRootEvidence(evidence); e != nil {
		return nil, e
	}
	if !validDigest(proof.ManifestSHA256) || proof.RootLockSHA256 != evidence.RootLockSHA256 || proof.RootLockSHA256 != root.RootLockSHA256 || proof.RootCommit != evidence.Commit || !proof.NoDependencies || !proof.NoExtends || !proof.NoBlocks {
		return nil, fmt.Errorf("%w: dependency-free manifest evidence", ErrEvidence)
	}
	lock, err := NewDependencyLock(*root, nil)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonical(lock)
}

// verifyLockEvidence requires every content-addressed evidence object named
// by the lock pair to be present in the read-only CAS.
func verifyLockEvidence(ctx context.Context, cas evidencecas.Reader, root *provenance.RootTemplateLock, dependencies *provenance.TemplateLock) error {
	subjects := make([]provenance.DependencySubject, 0, 1+len(dependencies.Dependencies))
	subjects = append(subjects, provenance.DependencySubject(root.Root))
	subjects = append(subjects, dependencies.Dependencies...)
	for _, s := range subjects {
		for _, digest := range []string{s.StatementCAS, s.SignatureCAS, s.CheckpointCAS, s.InclusionProofCAS} {
			if _, err := cas.Read(ctx, digest); err != nil {
				return fmt.Errorf("%w: %w: %s: %w", ErrUnsafe, ErrEvidence, digest, err)
			}
		}
	}
	return nil
}

// validateJournalState refuses state with unfinished transactions: an update
// journal, a new-transaction pending marker in the project, or any global
// journal that is not terminal. Journal-less orphans carry no recovery
// authority and are only reported.
func validateJournalState(entries []Entry, home string) error {
	for _, e := range entries {
		if e.Scope != "project" {
			continue
		}
		switch e.Classification {
		case "update-journal":
			return fmt.Errorf("%w: active project update journal", ErrUnsafe)
		case "new-pending-marker":
			return fmt.Errorf("%w: unfinished new transaction marker", ErrUnsafe)
		}
	}
	if home == "" {
		return nil
	}
	items, err := newtransaction.Inventory(home)
	if err != nil {
		return err
	}
	for _, item := range items {
		switch item.Status {
		case newtransaction.StatusComplete, newtransaction.StatusAborted, newtransaction.StatusOrphan:
		case newtransaction.StatusFuture:
			return fmt.Errorf("%w: global journal tx-%s", ErrFutureVersion, item.ID)
		case newtransaction.StatusActive:
			return fmt.Errorf("%w: active global journal tx-%s", ErrUnsafe, item.ID)
		default:
			return fmt.Errorf("%w: %s global journal tx-%s", ErrUnsafe, item.Status, item.ID)
		}
	}
	return nil
}

func validReceipt(r ProtectedReceipt) error {
	if r.AuthorityID == "" || r.HighestAcceptedSequence == 0 || !validDigest(r.EnvelopePayloadSHA256) || !validDigest(r.CheckpointDigest) || r.TreeSize == 0 || !r.BackendProtected || r.JournalStatus != "complete" || !validDigest(r.JournalDigest) || r.Backend == "" || r.Protection == "" {
		return fmt.Errorf("%w: protected receipt", ErrUnsafe)
	}
	return nil
}

func sealPlan(p *MigrationPlan) (*MigrationPlan, error) {
	b, e := canonicaljson.Canonical(struct {
		APIVersion string     `json:"apiVersion"`
		ProjectID  string     `json:"projectID"`
		From       string     `json:"from"`
		To         string     `json:"to"`
		Entries    []Entry    `json:"entries"`
		Mutations  []Mutation `json:"mutations"`
	}{p.APIVersion, p.ProjectID, p.From, p.To, p.Entries, p.Mutations})
	if e != nil {
		return nil, e
	}
	p.PlanSHA256 = domainHash(StatePlanV1+"\x00", b)
	return p, nil
}

func domainHash(d string, b []byte) string {
	s := sha256.Sum256(append([]byte(d), b...))
	return "sha256:" + hex.EncodeToString(s[:])
}

// DecodeStrict decodes closed JSON: unknown fields, duplicates and nulls fail.
func DecodeStrict(data []byte, dst any) error { return canonicaljson.DecodeStrict(data, dst) }

// SelfHash is SelfHashDomain without a domain separator.
func SelfHash(v any, field string) (string, error) { return SelfHashDomain(v, field, "") }

// SelfHashDomain hashes the canonical JSON of v with field removed.
func SelfHashDomain(v any, field, domain string) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	var m map[string]any
	if e = json.Unmarshal(raw, &m); e != nil {
		return "", e
	}
	delete(m, field)
	b, e := canonicaljson.Canonical(m)
	if e != nil {
		return "", e
	}
	if domain != "" {
		return domainHash(domain, b), nil
	}
	return sha(b), nil
}

// Paths returns the pointer values in a fixed order.
func (p StatePointers) Paths() []string { return p.all() }

func checkProjectIdentity(ctx context.Context, authority BindingAuthority, root, observedID string) error {
	checker, ok := authority.(ProjectIdentityAuthority)
	if !ok {
		return fmt.Errorf("%w: %w", ErrUnsafe, ErrProjectIdentity)
	}
	if err := checker.CheckProjectIdentity(ctx, root, observedID); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrUnsafe, ErrProjectIdentity, err)
	}
	return nil
}

// checkMarkerInventory ties the identity-checked bytes/mode to the returned
// snapshot's marker entry. This is marker coherence, not whole-tree atomicity.
func checkMarkerInventory(snapshot *Snapshot, raw []byte, mode uint32) error {
	count := 0
	for _, entry := range snapshot.Entries {
		if entry.Scope != "project" || entry.Path != StateDir+"/project.yaml" {
			continue
		}
		count++
		if !entry.Exists || entry.Kind != "file" || entry.Target != "" || entry.Mode != mode || entry.SHA256 != sha(raw) {
			return fmt.Errorf("%w: project marker disagrees with inventory", ErrUnsafe)
		}
	}
	if count != 1 {
		return fmt.Errorf("%w: project marker missing or ambiguous in inventory", ErrUnsafe)
	}
	return nil
}
