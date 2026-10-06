package formatproof

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/blockformatter"
	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/testfixture"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func managedFixture(t *testing.T) (*testfixture.Fixture, *trustload.Runtime, func() *Prepared) {
	t.Helper()
	f := testfixture.NewGofmtFixture(t)
	r, res := f.Open(t)
	t.Cleanup(func() { _ = r.Close() })
	ctx := context.Background()
	toolInfo, err := buildinfo.Read(bytes.NewReader(f.Tool()))
	if err != nil {
		t.Fatal(err)
	}
	options, _ := trustverify.ComputeToolOptionsSHA256([]string{})
	tool := trustverify.Tool{ID: "gofmt", Version: strings.TrimPrefix(toolInfo.GoVersion, "go"), BinarySHA256: evidencecas.Digest(f.Tool()), OptionsSHA256: options}
	input := []byte("package fixture\n// tplater:managed-begin id=body provider=root\nfunc f(){ }\n// tplater:managed-end id=body\n")
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, "z.go", input)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := blockformatter.BuildPlan(blockformatter.PlanInput{Path: "z.go", Language: "go", Adapter: "gofmt-stdin-v1", Tool: tool, Options: []string{}, InputMode: "100644", Markers: markers, TimeoutMillis: 5000, OutputLimitBytes: 16 << 20, Input: input})
	if err != nil {
		t.Fatal(err)
	}
	d := evidencecas.Digest([]byte("fixture"))
	contextJSON, err := canonicaljson.Canonical(operationtrust.ManagedFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v1", Role: "clean-target", SourceRootLockSHA256: d, TargetRootLockSHA256: d, ReplacementDeclarationsSHA256: d, DecisionsSHA256: d, ObservedProjectSHA256: d, ObservedRegistrySHA256: d, RendererAnswersSHA256: d})
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	s := res.Subject()
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: binding, ProjectID: r.ProjectContext().ProjectID, Scope: "run", PreimageSHA256: d, AnswersSHA256: d, Subjects: []trustverify.Provider{{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}, Actions: []trustverify.ActionMaterial{}}
	makePrepared := func() *Prepared {
		t.Helper()
		var managed operationtrust.ManagedFormatterContext
		if canonicaljson.DecodeStrict(contextJSON, &managed) != nil {
			t.Fatal("invalid context fixture")
		}
		p, err := PrepareRootGoFile(ctx, r, res, res, "z.go", input, managed, op)
		if err != nil {
			t.Fatal(err)
		}
		originalPlan, _ := canonicaljson.Canonical(plan)
		if !bytes.Equal(p.frame.Plan, originalPlan) {
			t.Fatal("native record-derived plan changed fixed tool/input binding")
		}
		return p
	}
	return f, r, makePrepared
}

func TestManagedFormatterEvidenceRetainedPair(t *testing.T) {
	f, _, prepare := managedFixture(t)
	ctx := context.Background()
	p := prepare()
	if _, err := OpenPair(ctx, p, p.Reference()); err == nil {
		t.Fatal("absent evidence accepted")
	}
	if entries, err := os.ReadDir(f.Scratch()); err != nil || len(entries) != 0 {
		t.Fatal("readonly created authority or directories", err, entries)
	}
	requests := p.Requests()
	refs := []trustverify.ApprovalRefs{f.Approval(t, requests[0]), f.Approval(t, requests[1])}
	pair, err := Stage(ctx, p, refs)
	if err != nil {
		t.Fatal(err)
	}
	output, err := pair.FormattedFor(ctx, p)
	if err != nil || bytes.Equal(output, p.frame.Input) {
		t.Fatal("real formatting missing", err)
	}
	if err := RevalidatePublication(ctx, p, pair); err != nil {
		t.Fatal(err)
	}
	cold := prepare()
	reopened, err := OpenPair(ctx, cold, cold.Reference())
	if err != nil {
		t.Fatal(err)
	}
	again, err := reopened.FormattedFor(ctx, cold)
	if err != nil || !bytes.Equal(output, again) {
		t.Fatal("cold projection differs", err)
	}
	// No approval refs: this succeeds only by retaining completed effects. It
	// cannot authorize a new formatter process through the real runner.
	if _, err := Stage(ctx, prepare(), nil); err != nil {
		t.Fatal("completed pair reran", err)
	}
	bad := cold.Reference()
	bad.FrameSHA256 = evidencecas.Digest([]byte("different-frame"))
	if _, err := OpenPair(ctx, cold, bad); err == nil {
		t.Fatal("stale frame admitted")
	}
	name := filepath.Join(f.Scratch(), "formatter-evidence", strings.TrimPrefix(cold.digest, "sha256:"), "pass-1-completed.json")
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPair(ctx, cold, cold.Reference()); err == nil {
		t.Fatal("tampered owner record admitted")
	}
}

func TestManagedFormatterColdCompletedFirstAndInDoubt(t *testing.T) {
	t.Run("completed-first", func(t *testing.T) {
		f, r, prepare := managedFixture(t)
		ctx := context.Background()
		p := prepare()
		reqs := p.Requests()
		refs := []trustverify.ApprovalRefs{f.Approval(t, reqs[0]), f.Approval(t, reqs[1])}
		store, err := engine.BeginFormatterEvidence(ctx, r, p.frame)
		if err != nil {
			t.Fatal(err)
		}
		authorized, err := p.adapter.AuthorizePasses(ctx, p.bound, refs)
		if err != nil {
			t.Fatal(err)
		}
		start, err := store.Start(1)
		if err != nil {
			t.Fatal(err)
		}
		pass, err := p.adapter.RunPass(ctx, authorized, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Complete(start, pass); err != nil {
			t.Fatal(err)
		}
		store.Release()
		name := filepath.Join(f.Scratch(), "formatter-evidence", strings.TrimPrefix(p.digest, "sha256:"), "pass-1-completed.json")
		before, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		cold := prepare()
		pending, err := cold.PendingRequests(ctx)
		if err != nil || len(pending) != 1 || pending[0].RequestSHA256 != reqs[1].RequestSHA256 {
			t.Fatalf("actual pending ordinal: %v %+v", err, pending)
		}
		refs[0] = trustverify.ApprovalRefs{} // Completed pass requires no new spawn grant.
		if _, err := Stage(ctx, cold, refs); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		again, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(raw, again) || !os.SameFile(before, after) {
			t.Fatal("completed first pass replaced", err)
		}
		if _, err := OpenPair(ctx, prepare(), cold.Reference()); err != nil {
			t.Fatal(err)
		}
		if pending, err := prepare().PendingRequests(ctx); err != nil || len(pending) != 0 {
			t.Fatalf("completed requests resurrected: %v %+v", err, pending)
		}
		keyPath := filepath.Join(f.Scratch(), "project-transaction-authority", "seal.key")
		heldKey := filepath.Join(f.Scratch(), "held-test-authority")
		if err := os.Rename(keyPath, heldKey); err != nil {
			t.Fatal(err)
		}
		if _, err := prepare().PendingRequests(ctx); err == nil || os.IsNotExist(err) {
			t.Fatal("existing completed frame without authority became pending", err)
		}
		if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
			t.Fatal("readonly probe recreated authority", err)
		}
		if err := os.Rename(heldKey, keyPath); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("started-only", func(t *testing.T) {
		f, r, prepare := managedFixture(t)
		ctx := context.Background()
		p := prepare()
		store, err := engine.BeginFormatterEvidence(ctx, r, p.frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Start(1); err != nil {
			t.Fatal(err)
		}
		store.Release()
		reqs := p.Requests()
		refs := []trustverify.ApprovalRefs{f.Approval(t, reqs[0]), f.Approval(t, reqs[1])}
		if _, err := Stage(ctx, prepare(), refs); err != ErrInDoubt {
			t.Fatalf("in-doubt admission: %v", err)
		}
		name := filepath.Join(f.Scratch(), "formatter-evidence", strings.TrimPrefix(p.digest, "sha256:"), "pass-1-completed.json")
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("in-doubt effect completed or reran", err)
		}
	})
}
