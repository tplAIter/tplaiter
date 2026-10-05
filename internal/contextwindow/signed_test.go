package contextwindow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/knowledge"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/testfixture"
)

func image(t *testing.T, root string) string {
	t.Helper()
	hash := sha256.New()
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(hash, "%s:%s\n", strings.TrimPrefix(path, root), info.Mode()); err != nil {
			return err
		}
		if !info.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err = hash.Write(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func TestActualSignedSelectionWholeEnvelopeZeroWritesAndFreshFinish(t *testing.T) {
	f := testfixture.NewGofmtFixture(t)
	runtime, resolution := f.Open(t)
	raw, err := os.ReadFile("../../testdata/knowledge/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := knowledge.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	subject, refs := resolution.Subject(), resolution.Evidence()
	d.Sources[0].Anchor = provenance.RootSubject{Origin: subject.Origin, TemplatePath: subject.TemplatePath, RequestedRef: subject.RequestedRef, Commit: subject.Commit, TreeSHA256: subject.TreeSHA256, ContractSHA256: subject.ContractSHA256, StatementCAS: refs.StatementCAS, SignatureCAS: refs.SignatureCAS, KeyFingerprint: refs.KeyFingerprint, CheckpointCAS: refs.CheckpointCAS, InclusionProofCAS: refs.InclusionProofCAS}
	pin := &d.Sources[0].Pin
	pin.Origin = subject.Origin
	pin.TemplatePath = subject.TemplatePath
	pin.RequestedRef = subject.RequestedRef
	pin.Commit = subject.Commit
	pin.TreeDigest = subject.TreeSHA256
	pin.ContractDigest = subject.ContractSHA256
	if len(subject.Commit) == 64 {
		pin.CommitAlgorithm = "sha256"
	}
	snapshot, err := runtime.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		t.Fatal(err)
	}
	d.Items = d.Items[2:]
	d.Items[0].Requires = []string{}
	d.Items[0].Produces = []string{}
	d.Edges = []knowledge.Edge{}
	for _, entry := range snapshot.Entries() {
		if entry.Path == "formatter/tool.json" {
			d.Items[0].SourcePath = entry.Path
			d.Items[0].ContentSHA256 = entry.ContentSHA256
			d.Items[0].Mode = entry.Mode
		}
	}
	if d.Items[0].SourcePath != "formatter/tool.json" {
		t.Fatal("signed source fixture absent")
	}
	index, err := contextindex.New(encoded(t, d), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := contextindex.Request{Query: contextindex.Query{Kind: "resource", One: true}, MaxBytes: 32768, IncludeExcerpts: true, MaxExcerptBytes: 2048}
	bindings := []contextindex.Binding{{SourceID: d.Sources[0].ID, Runtime: runtime.TrustRuntime(), Resolution: resolution}}
	root := filepath.Dir(f.Project())
	before := image(t, root)
	selected, err := Select(context.Background(), index, request, bindings)
	if err != nil {
		t.Fatal(err)
	}
	// No numeric token/window claim comes from the signed source. Host and source
	// evidence are different domains; only the private synthetic host counts here.
	h := syntheticHost(t, baseEnvelope(), 1000000)
	o := observation(t, h)
	held, p, err := h.Reserve(context.Background(), o, Request{ID: "actual-source", Selection: selected, OutputReserve: 512, ReasoningReserve: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.Envelope), refs.StatementCAS) || !strings.Contains(string(p.Envelope), "sourceEvidence") || !strings.Contains(string(p.Envelope), "requiredFloor") {
		t.Fatal("signed selected source evidence/floor/pins lost")
	}
	if image(t, root) != before {
		t.Fatal("select/reserve wrote source/project bytes/modes")
	}
	scratch, err := os.ReadDir(f.Scratch())
	if err != nil || len(scratch) != 0 {
		t.Fatalf("hook/tool executed: %v", err)
	}
	// Untrusted raw metadata cannot elevate source bytes to an observation.
	bad := d
	bad.Items = append([]knowledge.Item{}, d.Items...)
	bad.Items[0].ContentSHA256 = "sha256:" + strings.Repeat("2", 64)
	badIndex, err := contextindex.New(encoded(t, bad), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Select(context.Background(), badIndex, request, bindings)
	if err == nil {
		t.Fatal("caller-supplied pins minted source admission")
	}
	var kd *knowledge.Error
	if !errors.As(err, &kd) || kd.Code != knowledge.SourceStale {
		t.Fatalf("forged source digest outcome: %v", err)
	}
	if err = h.Finish(context.Background(), held, syntheticResponse(t, h, held, "first answer")); err != nil {
		t.Fatal(err)
	}
	if image(t, root) != before {
		t.Fatal("successful finish wrote source/project")
	}
	o = observation(t, h)
	held, _, err = h.Reserve(context.Background(), o, Request{ID: "second-page", Selection: selected, OutputReserve: 512, ReasoningReserve: 100})
	if err != nil {
		t.Fatal(err)
	}
	beforeSpend := h.Spending()
	f.CorruptSignedToolRecord(t)
	afterTamper := image(t, root)
	received := syntheticResponse(t, h, held, "answer")
	observedSpend := h.Spending()
	if observedSpend.InputTokens <= beforeSpend.InputTokens {
		t.Fatal("observed transport usage not separated from window publication")
	}
	err = h.Finish(context.Background(), held, received)
	if err == nil || len(h.retained) != 1 || len(h.reservations) != 1 || h.Spending() != observedSpend {
		t.Fatal("fresh-source failure published/spent")
	}
	if image(t, root) != afterTamper {
		t.Fatal("failed finish wrote source/project")
	}
	_, _, err = h.Reserve(context.Background(), o, Request{ID: "tampered", Selection: selected})
	if err == nil {
		t.Fatal("retained source observation bypassed fresh pins")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = h.Finish(ctx, held, received)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	t.Log("genuine signed source; synthetic host accounting only; select/reserve/failed finish zero writes")
}
