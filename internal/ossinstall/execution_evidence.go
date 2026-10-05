package ossinstall

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"time"
)

type ApprovalImport struct {
	Approval  json.RawMessage `json:"approval"`
	Signature string          `json:"signature"`
}
type approvalReader map[string][]byte

func (r approvalReader) Read(ctx context.Context, s string) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	b, ok := r[s]
	if !ok {
		return nil, errors.New("approval missing")
	}
	return append([]byte(nil), b...), nil
}

// ImportApproval verifies the actual persistent signature against the fixed
// installed policy before persisting public objects. No signer/key is accepted.
func ImportApproval(ctx context.Context, selection trustload.LaunchSelection, request trustverify.ExecutionRequest, raw []byte, now time.Time) (trustverify.ApprovalRefs, error) {
	if ctx == nil || len(raw) > 1<<20 {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(nil)
	}
	if e := ctx.Err(); e != nil {
		return trustverify.ApprovalRefs{}, e
	}
	var v ApprovalImport
	if canonicaljson.DecodeStrict(raw, &v) != nil {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(nil)
	}
	a, e := trustverify.DecodeExecutionApproval(v.Approval)
	if e != nil {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(e)
	}
	if _, e := bootstrap.DecodeSignature([]byte(v.Signature)); e != nil {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(e)
	}
	signature := []byte(v.Signature)
	if evidencecas.Digest(signature) != a.SignatureCAS {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(nil)
	}
	loaded, e := trustload.Load(ctx, selection)
	if e != nil {
		return trustverify.ApprovalRefs{}, e
	}
	policy, e := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if e != nil {
		return trustverify.ApprovalRefs{}, e
	}
	ref := evidencecas.Digest(v.Approval)
	store := approvalReader{ref: v.Approval, a.SignatureCAS: signature}
	if e := trustverify.VerifyPersistentApproval(ctx, store, policy, &request, request.OperationInputsSHA256, request.ProfileBindingSHA256, now, ref); e != nil {
		return trustverify.ApprovalRefs{}, approvalImportRefusal(e)
	}
	for _, item := range []struct {
		ref string
		b   []byte
	}{{a.SignatureCAS, signature}, {ref, v.Approval}} {
		if e := writeExecutionCAS(ctx, loaded.Install.EvidenceRoot, item.ref, item.b); e != nil {
			return trustverify.ApprovalRefs{}, approvalImportRefusal(e)
		}
	}
	return trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: ref}, nil
}

// Verification backend text is not a public diagnostic and can contain untrusted
// details. Preserve cancellation, but expose only a typed approval refusal.
func approvalImportRefusal(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return resultdto.NewError("TRUST_APPROVAL_MISMATCH", resultdto.ExitTrust, nil)
}
