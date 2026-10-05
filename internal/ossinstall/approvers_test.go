package ossinstall

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecutionEnrollmentFreshOnlyAndChunkIntegrity(t *testing.T) {
	o := enrollmentOptions(t)
	o.Approvers = []trustverify.Approver{}
	o.ExecutionEvidence = []ExecutionEvidence{{SHA256: evidencecas.Digest([]byte("synthetic")), DataBase64: base64.StdEncoding.EncodeToString([]byte("synthetic"))}}
	if _, e := executionContext(context.Background(), o); e != nil {
		t.Fatal(e)
	}
	o.ExecutionEvidence[0].SHA256 = evidencecas.Digest([]byte("tampered"))
	if _, e := executionContext(context.Background(), o); e == nil {
		t.Fatal("tampered chunk accepted")
	}
	o.ExecutionEvidence = nil
	o.Root = filepath.Dir(o.Root)
	if _, e := executionContext(context.Background(), o); e == nil {
		t.Fatal("existing installation root accepted")
	}
}

func TestApprovalImportMalformedRefusesBeforeLoadOrWrite(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "synthetic-sentinel")
	if e := os.WriteFile(sentinel, []byte("preserved"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{[]byte("not JSON"), []byte(`{"approval":{},"signature":"synthetic invalid"}`), []byte(`{"approval":{},"signature":"","unknown":true}`)} {
		refs, err := ImportApproval(context.Background(), trustload.LaunchSelection{}, trustverify.ExecutionRequest{}, raw, time.Now())
		var typed *resultdto.LifecycleError
		if !errors.As(err, &typed) || typed.Code != "TRUST_APPROVAL_MISMATCH" || typed.ExitCode() != resultdto.ExitTrust || refs.ApprovalCAS != "" {
			t.Fatalf("unsafe refusal: %v %+v", err, refs)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ImportApproval(ctx, trustload.LaunchSelection{}, trustverify.ExecutionRequest{}, []byte("not JSON"), time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	entries, err := os.ReadDir(root)
	b, readErr := os.ReadFile(sentinel)
	if err != nil || readErr != nil || len(entries) != 1 || string(b) != "preserved" {
		t.Fatal("refused import changed fixture")
	}
}

// This focused installed-CAS check needs no compiler/toolchain stage. The full
// installed CLI fixture independently proves preparation and actual execution.
func TestApprovalImportStaleBindingNoPersistentEffects(t *testing.T) {
	ctx := context.Background()
	o := enrollmentOptions(t)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	pub := key.Public().(ed25519.PublicKey)
	now := time.Now()
	validity := trustverify.Validity{NotBefore: now.Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: now.Add(time.Hour).UTC().Format(time.RFC3339)}
	o.Approvers = []trustverify.Approver{{ID: "synthetic-import-operator", PrincipalID: "principal:synthetic-import-operator", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(pub), PublicKeyBase64: base64.StdEncoding.EncodeToString(pub), Validity: validity, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-a", OperationScope: "run", ActionKind: "command", Origin: o.Publishers[0].SourceOrigin, TemplatePath: "."}}}}
	result, err := GenerateWithContext(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	reg := loadRegistration(t, result)
	loaded, err := trustload.Load(ctx, reg.Selection())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	req := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: digest("1"), OperationInputsSHA256: digest("2"), ProjectID: "project-a", Scope: "run", Provider: trustverify.Provider{Origin: o.Publishers[0].SourceOrigin, TemplatePath: ".", Commit: strings.Repeat("a", 40), TreeSHA256: digest("3"), ContractSHA256: digest("4")}, Action: trustverify.Action{ID: "synthetic-import-only", Kind: "command", Phase: "standalone", Argv: []string{"go", "build"}, ContentClosureSHA256: digest("5")}, Tool: trustverify.Tool{ID: "go", Version: "go1.27.1", BinarySHA256: digest("6"), OptionsSHA256: digest("7")}, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: digest("8"), TimeoutMillis: 100, Migration: trustverify.Migration{Kind: "none"}}
	req.RequestSHA256, err = req.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	approval := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: req.RequestSHA256, ProfileBindingSHA256: req.ProfileBindingSHA256, OperationInputsSHA256: req.OperationInputsSHA256, ProjectID: req.ProjectID, Scope: req.Scope, ApproverID: o.Approvers[0].ID, IdentityClass: "operator", ExecutionPolicySHA256: policy.PolicySHA256, Validity: validity, KeyFingerprint: o.Approvers[0].KeyFingerprint}
	approval.GrantSHA256, err = approval.ComputeGrantSHA256()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := hex.DecodeString(strings.TrimPrefix(approval.GrantSHA256, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	sig := bootstrap.EncodeSignature(ed25519.Sign(key, msg))
	approval.SignatureCAS = evidencecas.Digest([]byte(sig))
	rawApproval, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ApprovalImport{Approval: rawApproval, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	stale := req
	stale.Action.ContentClosureSHA256 = digest("9")
	stale.RequestSHA256, err = stale.ComputeRequestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := ImportApproval(ctx, reg.Selection(), stale, raw, now)
	var typed *resultdto.LifecycleError
	if !errors.As(err, &typed) || typed.Code != "TRUST_APPROVAL_MISMATCH" || typed.ExitCode() != resultdto.ExitTrust || refs.ApprovalCAS != "" {
		t.Fatalf("stale binding not safely refused: %v %+v", err, refs)
	}
	for _, ref := range []string{evidencecas.Digest(rawApproval), approval.SignatureCAS} {
		h := strings.TrimPrefix(ref, "sha256:")
		if _, err := os.Lstat(filepath.Join(loaded.Install.EvidenceRoot, "sha256", h[:2], h[2:])); !os.IsNotExist(err) {
			t.Fatalf("refused import persisted public object: %v", err)
		}
	}
	refs, err = ImportApproval(ctx, reg.Selection(), req, raw, now)
	if err != nil || refs.ApprovalCAS != evidencecas.Digest(rawApproval) {
		t.Fatalf("exact signed approval did not persist: %v %+v", err, refs)
	}
	reader, err := evidencecas.NewFSReader(loaded.Install.EvidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := trustverify.VerifyPersistentApproval(ctx, reader, policy, &req, req.OperationInputsSHA256, req.ProfileBindingSHA256, now, refs.ApprovalCAS); err != nil {
		t.Fatal(err)
	}
	t.Log("stale changed-input grant: typed TRUST_APPROVAL_MISMATCH, neither object persisted; exact external synthetic signature: installed persistent CAS reverified")
}
