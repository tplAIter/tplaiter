package stateledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

func TestLegacyFixturePlanMatchesGoldens(t *testing.T) {
	root := legacyProjectRoot(t)
	p, err := Plan(root, migrationOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	if p.From != ProjectV1 || p.To != ProjectV2APIVersion || len(p.Mutations) != 2 || len(p.ProjectYAML) == 0 || len(p.DependencyLockJSON) == 0 {
		t.Fatalf("plan=%+v", p)
	}
	pb, err := canonicaljson.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "migration-plan.v1.json", append(pb, '\n'))
	assertGolden(t, "empty-template-lock.v2.json", append(append([]byte{}, p.DependencyLockJSON...), '\n'))
	assertGolden(t, "project.v2.yaml", p.ProjectYAML)
	rb, err := canonicaljson.Canonical(mustSealedReport(t))
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "state-ledger-report.v1.json", append(rb, '\n'))
	// The synthesized lock is a valid provenance v2 lock bound to the root.
	lock, err := provenance.DecodeTemplateLock(p.DependencyLockJSON)
	if err != nil {
		t.Fatal(err)
	}
	if lock.Dependencies == nil || len(lock.Dependencies) != 0 || !bytes.Contains(p.DependencyLockJSON, []byte(`"dependencies":[]`)) {
		t.Fatalf("empty dependency lock is not explicit: %s", p.DependencyLockJSON)
	}
	if err := provenance.ValidateLockPair(fixtureRoot(t), *lock); err != nil {
		t.Fatal(err)
	}
}

// assertGolden compares byte-exact output with a reviewed golden file.
// Goldens are never rewritten by the test.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(fixtureDir("golden", name))
	if err != nil {
		t.Fatalf("golden %s: %v\ngot:\n%s", name, err, got)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden %s mismatch\n got=%s\nwant=%s", name, got, want)
	}
}

func TestPortableFixtureInventoryClassifiesEveryLedger(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(fixtureDir("project"))); err != nil {
		t.Fatal(err)
	}
	lock := fixtureRoot(t)
	writeRootLock(t, root, lock)
	dep, err := NewDependencyLock(lock, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := canonicaljson.Canonical(dep)
	if err := os.WriteFile(filepath.Join(root, StateDir, DependencyLockFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.CopyFS(home, os.DirFS(fixtureDir("home"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "tplater.db"), []byte("must not be read"), 0o600); err != nil {
		t.Fatal(err)
	}
	statuses := seedJournals(t, home)
	protectedRaw, err := os.ReadFile(fixtureDir("protected-tuple.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt ProtectedReceipt
	if err = json.Unmarshal(protectedRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	s, err := Inventory(root, Options{HomeRoot: home, SecretProvider: &testSecrets{}, ProtectedReceipt: &receipt})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range s.Entries {
		if e.Scope == "home" && strings.HasPrefix(e.Path, "transactions/new/tx-") {
			// Journal internals are covered by the status assertions below.
			rest := e.Path[strings.Index(e.Path[len("transactions/new/"):], "/")+len("transactions/new/")+1:]
			if strings.HasPrefix(rest, "blobs/") {
				rest = "blobs/*"
			}
			got["transactions/new/tx-*/"+rest] = e.Classification + ":" + e.Retention
			continue
		}
		got[e.Path] = e.Classification + ":" + e.Retention
	}
	want := map[string]string{
		".tplaiter/ai-managed.json": "ai-managed:permanent", ".tplaiter/baseline.json": "baseline:permanent",
		".tplaiter/generator-targets.lock.json": "generator-targets:permanent", ".tplaiter/graph-cache/graph.json": "graph-cache:rebuildable",
		".tplaiter/managed-blocks.json": "managed-blocks:permanent", ".tplaiter/migrations.json": "migrations:permanent",
		".tplaiter/ownership.json": "ownership:permanent", ".tplaiter/project.yaml": "project-marker:permanent",
		".tplaiter/resources.lock.json": "resources-lock:permanent", ".tplaiter/root-template.lock.json": "root-lock:permanent",
		".tplaiter/template.lock.json": "dependency-lock:permanent", ".tplaiter/unknown.opaque": "opaque:preserve",
		".tplaiter/update.lock": "update-lock:stable", ".tplaiter/update/tx-complete/before": "update-cas:until-terminal",
		"config.yaml": "config:preserve", "index.yaml": "index:rebuildable", "projects.yaml": "registry:rebuildable",
		"state.yaml": "run-state:rebuildable", "trust-roots.json": "trust-cache:preserve", "tplater.db": "secret:opaque",
		"transactions/new.lock": "new-lock:stable", "transactions/new/tx-*/active.json": "new-journal:until-terminal",
		"transactions/new/tx-*/blobs/*": "new-cas:30d-and-newest100", "receipt": "protected-receipt:external",
	}
	keys := func(m map[string]string) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if strings.Join(keys(got), "\n") != strings.Join(keys(want), "\n") {
		t.Fatalf("inventory paths:\n got=%v\nwant=%v", keys(got), keys(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("inventory[%s]=%q want %q", k, got[k], v)
		}
	}
	gotStatus := map[string]string{}
	for _, item := range s.Transactions {
		gotStatus[item.ID] = item.Status
	}
	for id, status := range statuses {
		if gotStatus[id] != status {
			t.Fatalf("journal %s status=%q want %q (all=%+v)", id, gotStatus[id], status, s.Transactions)
		}
	}
	for _, e := range s.Entries {
		if e.Path == "tplater.db" && e.SHA256 != d('d') {
			t.Fatalf("secret was read: %+v", e)
		}
	}
}

// seedJournals creates active, unsafe, future and missing-CAS global
// journals with the real transaction engine and returns their statuses.
func seedJournals(t *testing.T, home string) map[string]string {
	t.Helper()
	statuses := map[string]string{}
	begin := func() *newtransaction.Transaction {
		t.Helper()
		target := filepath.Join(t.TempDir(), "project")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		tx, err := newtransaction.Begin(home, target)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	release := func(tx *newtransaction.Transaction) {
		// Simulate process exit: the flock is released, the journal stays.
		tx.Release()
	}
	active := begin()
	release(active)
	statuses[active.ID()] = newtransaction.StatusActive

	unsafe := begin()
	release(unsafe)
	if err := os.WriteFile(filepath.Join(home, "transactions", "new", "tx-"+unsafe.ID(), "active.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	statuses[unsafe.ID()] = newtransaction.StatusUnsafe

	future := begin()
	release(future)
	journal := filepath.Join(home, "transactions", "new", "tx-"+future.ID(), "active.json")
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, bytes.Replace(raw, []byte(newtransaction.APIVersion), []byte("tplaiter.dev/new-transaction/v2"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	statuses[future.ID()] = newtransaction.StatusFuture

	missing := begin()
	release(missing)
	blob := filepath.Join(home, "transactions", "new", "tx-"+missing.ID(), "blobs", "sha256", strings.TrimPrefix(missing.Journal().TargetAfterSHA, "sha256:"))
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	statuses[missing.ID()] = newtransaction.StatusMissingCAS
	return statuses
}

func TestInventoryDoesNotFollowSymlinkOrReadSecrets(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, StateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, StateDir, "project.yaml"), []byte("apiVersion: tplater.dev/v1alpha1\nkind: Project\nid: "+fixtureID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, StateDir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "tplater.db"), []byte("must not read"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, "tplater.db"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(home, "tplater.db"), 0o600) })
	s := &testSecrets{}
	i, err := Inventory(root, Options{HomeRoot: home, SecretProvider: s})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.seen) != 1 || s.seen[0].RootID != "home" || filepath.IsAbs(s.seen[0].RelativePath) {
		t.Fatalf("bad secret locator: %+v", s.seen)
	}
	for _, e := range i.Entries {
		if e.Path == StateDir+"/link" && (e.Kind != "symlink" || e.SHA256 != sha([]byte(target))) {
			t.Fatalf("followed symlink: %+v", e)
		}
		if e.Scope == "home" && e.Path == "tplater.db" && e.SHA256 != d('d') {
			t.Fatalf("secret opened or wrong digest: %+v", e)
		}
	}
	if _, err := Inventory(root, Options{HomeRoot: home}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("home inventory without a secret provider: %v", err)
	}
	if _, err := Inventory(root, Options{HomeRoot: filepath.Join(root, StateDir), SecretProvider: s}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("overlapping home accepted: %v", err)
	}
}

func TestPlanRequiresVerifiersAndSynthesizesOnlyProvenEmptyLock(t *testing.T) {
	root := legacyProjectRoot(t)
	if _, err := Plan(root, Options{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing verifier err=%v", err)
	}
	if _, err := Plan(root, Options{RootVerifier: testRootVerifier{fixtureRoot(t)}}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing manifest verifier err=%v", err)
	}
	other := fixtureRoot(t)
	other.Root.RequestedRef = "refs/tags/v2"
	if _, err := Plan(root, Options{RootVerifier: testRootVerifier{other}, ManifestVerifier: testManifestVerifier{}}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("mismatched root evidence err=%v", err)
	}
	if _, err := Plan(root, Options{RootVerifier: testRootVerifier{fixtureRoot(t)}, ManifestVerifier: dependentManifest{}}); !errors.Is(err, ErrEvidence) {
		t.Fatalf("dependency-bearing manifest synthesized an empty lock: %v", err)
	}
}

type dependentManifest struct{}

func (dependentManifest) VerifyDependencyFree(_ context.Context, _ string, r RootEvidence) (ManifestEvidence, error) {
	return ManifestEvidence{ManifestSHA256: d('c'), RootLockSHA256: r.RootLockSHA256, RootCommit: r.Commit, NoExtends: true, NoBlocks: true}, nil
}

func TestV2IsNoopAndDowngradeIsRefused(t *testing.T) {
	root := stableProject(t)
	plan, err := Plan(root, Options{})
	if err != nil || plan.From != ProjectV2APIVersion || len(plan.Mutations) != 0 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err = PlanTarget(root, Options{}, ProjectV1); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade=%v", err)
	}
	var marker ProjectV2
	raw, err := os.ReadFile(filepath.Join(root, StateDir, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.Template.ResolvedCommit != strings.Repeat("a", 40) || marker.State != StandardPointers() || marker.Runtime["port"] != 8080 {
		t.Fatalf("migrated marker=%+v", marker)
	}
}

func TestApplyPlanRequiresReviewedDigestAndCommitsMarkerLast(t *testing.T) {
	root := legacyProjectRoot(t)
	opts := migrationOptions(t)
	plan, err := Plan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPlan(root, opts, d('0')); !errors.Is(err, ErrDigest) {
		t.Fatalf("unreviewed digest accepted: %v", err)
	}
	crash := errors.New("injected crash")
	writeFailpoint = func(stage, name string) error {
		if stage == "before-rename" && name == "project.yaml" {
			return crash
		}
		return nil
	}
	_, err = ApplyPlan(root, opts, plan.PlanSHA256)
	writeFailpoint = nil
	if !errors.Is(err, crash) {
		t.Fatalf("apply error=%v", err)
	}
	// The dependency lock is durable, the marker is still v1: the next plan is
	// a fresh migrate-only plan with a different digest.
	marker, _ := os.ReadFile(filepath.Join(root, StateDir, "project.yaml"))
	if !bytes.Contains(marker, []byte(ProjectV1)) {
		t.Fatalf("marker switched before the commit point: %s", marker)
	}
	if _, err := ApplyPlan(root, opts, plan.PlanSHA256); !errors.Is(err, ErrDigest) {
		t.Fatalf("stale plan applied after a partial write: %v", err)
	}
	fresh, err := Plan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Mutations) != 1 || fresh.Mutations[0].Action != "migrate" {
		t.Fatalf("resumed plan=%+v", fresh.Mutations)
	}
	if _, err := ApplyPlan(root, opts, fresh.PlanSHA256); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, StateDir))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestWriteLockPairCrashLeavesAMismatchThatReadersRefuse(t *testing.T) {
	root := t.TempDir()
	a := fixtureRoot(t)
	depA, err := NewDependencyLock(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteLockPair(root, a, depA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLockPair(root); err != nil {
		t.Fatal(err)
	}
	b := a
	b.Root.RequestedRef = "refs/tags/v2"
	if b, err = SealRootLock(b); err != nil {
		t.Fatal(err)
	}
	depB, err := NewDependencyLock(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	crash := errors.New("injected crash")
	writeFailpoint = func(stage, name string) error {
		if stage == "before-rename" && name == RootLockFile {
			return crash
		}
		return nil
	}
	_, _, err = WriteLockPair(root, b, depB)
	writeFailpoint = nil
	if !errors.Is(err, crash) {
		t.Fatalf("write error=%v", err)
	}
	if _, _, err := readLockPair(root); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("half-written lock pair accepted: %v", err)
	}
	if _, _, err := WriteLockPair(root, b, depB); err != nil {
		t.Fatal(err)
	}
	got, _, err := readLockPair(root)
	if err != nil || got.RootLockSHA256 != b.RootLockSHA256 {
		t.Fatalf("repaired pair=%v err=%v", got, err)
	}
	depB.Dependencies = nil
	if _, _, err := WriteLockPair(root, b, depB); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("implicit dependencies accepted: %v", err)
	}
}

func TestVerifyStableMatrix(t *testing.T) {
	stable := fakeAuthority{fixtureProfile()}
	root := stableProject(t)
	if _, err := VerifyStable(context.Background(), root, stable, StableVerifyOptions{CAS: fullCAS()}); err != nil {
		t.Fatalf("valid project rejected: %v", err)
	}
	if err := VerifyDependencyLocks(context.Background(), root, stable, fullCAS()); err != nil {
		t.Fatalf("valid lock pair rejected: %v", err)
	}
	dev := fixtureProfile()
	dev.ID, dev.Assurance = bootstrap.ProfileDevelopment, bootstrap.DevelopmentUnverified
	other := fixtureProfile()
	other.ConfigSHA256 = d('e')
	cases := map[string]struct {
		authority BindingAuthority
		cas       mapCAS
		mutate    func(t *testing.T, root string)
		want      error
	}{
		"nil authority":         {authority: nil, want: ErrUnsafe},
		"development authority": {authority: fakeAuthority{dev}, want: ErrUnsafe},
		"other profile":         {authority: fakeAuthority{other}, want: ErrPolicyOrigin},
		"missing evidence":      {authority: stable, cas: mapCAS{d('3'): {1}}, want: ErrEvidence},
		"missing ledger": {authority: stable, want: ErrUnsafe, mutate: func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, StateDir, "ai-managed.json")); err != nil {
				t.Fatal(err)
			}
		}},
		"tampered root lock": {authority: stable, want: ErrDigest, mutate: func(t *testing.T, root string) {
			path := filepath.Join(root, StateDir, RootLockFile)
			raw, _ := os.ReadFile(path)
			if err := os.WriteFile(path, bytes.Replace(raw, []byte("refs/tags/v1"), []byte("refs/tags/v9"), 1), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"legacy v1 root lock": {authority: stable, want: ErrLegacyLock, mutate: func(t *testing.T, root string) {
			legacy := `{"apiVersion":"tplater.dev/root-template-lock/v1","kind":"RootTemplateLock","policy":{},"root":{},"renderer":{},"rootLockSHA256":"` + d('1') + `"}`
			if err := os.WriteFile(filepath.Join(root, StateDir, RootLockFile), []byte(legacy), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		"symlinked ledger": {authority: stable, want: ErrUnsafe, mutate: func(t *testing.T, root string) {
			path := filepath.Join(root, StateDir, "baseline.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("ownership.json", path); err != nil {
				t.Fatal(err)
			}
		}},
		"unfinished update journal": {authority: stable, want: ErrUnsafe, mutate: func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, StateDir, "update"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, StateDir, "update", "active.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		"unfinished new marker": {authority: stable, want: ErrUnsafe, mutate: func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, StateDir, "new-transaction.pending"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := stableProject(t)
			if tc.mutate != nil {
				tc.mutate(t, root)
			}
			cas := tc.cas
			if cas == nil {
				cas = fullCAS()
			}
			if _, err := VerifyStable(context.Background(), root, tc.authority, StableVerifyOptions{CAS: cas}); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyStable error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyStableRefusesUnfinishedGlobalJournals(t *testing.T) {
	root := stableProject(t)
	home := t.TempDir()
	statuses := seedJournals(t, home)
	opts := StableVerifyOptions{HomeRoot: home, CAS: fullCAS(), SecretProvider: &testSecrets{}}
	if _, err := VerifyStable(context.Background(), root, fakeAuthority{fixtureProfile()}, opts); !errors.Is(err, ErrUnsafe) && !errors.Is(err, ErrFutureVersion) {
		t.Fatalf("unfinished journals accepted: %v", err)
	}
	// Once every unfinished journal is resolved, verification succeeds.
	for id, status := range statuses {
		_ = status
		if err := os.RemoveAll(filepath.Join(home, "transactions", "new", "tx-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := VerifyStable(context.Background(), root, fakeAuthority{fixtureProfile()}, opts); err != nil {
		t.Fatalf("terminal journals refused: %v", err)
	}
}

func TestStrictYAMLRejectsDuplicateNullAndFuture(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, StateDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for marker, want := range map[string]error{
		"apiVersion: tplater.dev/v1alpha1\napiVersion: tplater.dev/v1alpha1\nkind: Project\nid: x\n": ErrUnsafe,
		"apiVersion: null\nkind: Project\nid: x\n":                                                   ErrUnsafe,
		"apiVersion: tplaiter.dev/project/v3\nkind: Project\nid: x\n":                                ErrFutureVersion,
	} {
		if err := os.WriteFile(filepath.Join(root, StateDir, "project.yaml"), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Plan(root, Options{}); !errors.Is(err, want) {
			t.Fatalf("marker %q error=%v want %v", marker, err, want)
		}
	}
}

func TestStrictWireRejectsUnknownAndNull(t *testing.T) {
	type wire struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	for _, raw := range []string{`{"apiVersion":"x","kind":"y","extra":1}`, `{"apiVersion":null,"kind":"y"}`} {
		var w wire
		if err := DecodeStrict([]byte(raw), &w); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func mustSealedReport(t *testing.T) Report {
	t.Helper()
	r, err := (Report{APIVersion: StateReportV1, ProjectID: "fixture", PlanSHA256: d('a'), Result: "planned", Receipt: ProtectedReceipt{AuthorityID: "platform", HighestAcceptedSequence: 1, EnvelopePayloadSHA256: d('b'), CheckpointDigest: d('c'), TreeSize: 1, JournalStatus: "complete", JournalDigest: d('d'), Backend: "fixture", Protection: "test", BackendProtected: true}, Entries: []ReportEntry{}, TestOutcomes: []TestOutcome{}}).Seal()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportSealIsDeterministicAndRequiresProtectedReceipt(t *testing.T) {
	a, b := mustSealedReport(t), mustSealedReport(t)
	if a.ReportSHA256 != b.ReportSHA256 || !validDigest(a.ReportSHA256) {
		t.Fatal("non-deterministic report seal")
	}
	bad := a
	bad.Receipt.BackendProtected = false
	if _, err := bad.Seal(); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unprotected receipt sealed: %v", err)
	}
}
