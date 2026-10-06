package cmd

import (
	"context"
	"errors"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/ossinstall"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/formatproof"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const FormatInputAPIVersion = "tplaiter.dev/format-input/v1"

var (
	ErrFormatControls = errors.New("MANAGED_FORMAT_CONTROLS_INVALID")
	formatRefPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// FormatInput is public signed-document selection transport. It does not carry
// executable paths, environment overrides, permits or reported effect receipts.
type FormatInput struct {
	APIVersion string                         `json:"apiVersion"`
	ToolSource operationtrust.SourceSelection `json:"toolSource"`
	Approvals  []FormatApproval               `json:"approvals"`
}
type FormatApproval struct {
	RequestSHA256 string `json:"requestSHA256"`
	ApprovalCAS   string `json:"approvalCAS,omitempty"`
	ApprovalInput string `json:"approvalInput,omitempty"`
}

// ParseFormatInput is closed and bounded before any import or writer action.
func ParseFormatInput(raw []byte) (FormatInput, error) {
	var input FormatInput
	if len(raw) == 0 || len(raw) > 1<<20 || canonicaljson.DecodeStrict(raw, &input) != nil || input.APIVersion != FormatInputAPIVersion || input.Approvals == nil || len(input.Approvals) > 4096 {
		return FormatInput{}, ErrFormatControls
	}
	source, err := canonicaljson.Canonical(input.ToolSource)
	if err != nil {
		return FormatInput{}, ErrFormatControls
	}
	if _, err = operationtrust.DecodeSourceSelection(source); err != nil {
		return FormatInput{}, ErrFormatControls
	}
	seen := map[string]bool{}
	for _, a := range input.Approvals {
		if !formatRefPattern.MatchString(a.RequestSHA256) || seen[a.RequestSHA256] || (a.ApprovalCAS == "") == (a.ApprovalInput == "") || (a.ApprovalCAS != "" && !formatRefPattern.MatchString(a.ApprovalCAS)) || len(a.ApprovalInput) > 4096 {
			return FormatInput{}, ErrFormatControls
		}
		seen[a.RequestSHA256] = true
	}
	return input, nil
}

func validateFormatControls(prepare, stage, dryRun bool, raw []byte) error {
	if stage && (prepare || dryRun || len(raw) == 0) {
		return ErrFormatControls
	}
	if len(raw) > 0 {
		_, err := ParseFormatInput(raw)
		return err
	}
	return nil
}

// ExactFormatApprovalCAS matches finite existing CAS references to the actual
// selected requests. File imports are performed by the installed CLI owner
// before this step; this helper cannot turn a locator into an execution permit.
func ExactFormatApprovalCAS(input FormatInput, requests []trustverify.ExecutionRequest) ([]trustverify.ApprovalRefs, error) {
	if len(input.Approvals) != len(requests) {
		return nil, ErrFormatControls
	}
	byRequest := map[string]FormatApproval{}
	for _, a := range input.Approvals {
		if _, exists := byRequest[a.RequestSHA256]; exists {
			return nil, ErrFormatControls
		}
		byRequest[a.RequestSHA256] = a
	}
	refs := make([]trustverify.ApprovalRefs, len(requests))
	for i, q := range requests {
		a, ok := byRequest[q.RequestSHA256]
		if !ok || q.VerifyRequestSHA256() != nil || !formatRefPattern.MatchString(a.ApprovalCAS) || a.ApprovalInput != "" {
			return nil, ErrFormatControls
		}
		refs[i] = trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: a.ApprovalCAS}
		delete(byRequest, q.RequestSHA256)
	}
	if len(byRequest) != 0 {
		return nil, ErrFormatControls
	}
	return refs, nil
}

// RetainedFormatPair only reads owner-authenticated effects. It neither creates
// a scratch directory nor imports approvals or repeats a formatter process.
func RetainedFormatPair(ctx context.Context, prepared *formatproof.Prepared) (*formatproof.VerifiedPair, error) {
	if prepared == nil {
		return nil, ErrFormatControls
	}
	return formatproof.OpenPair(ctx, prepared, prepared.Reference())
}

// importExactFormatApprovals derives imports from the actual prepared requests.
// User filenames remain transport only; permits are still issued by runtime.
func importExactFormatApprovals(cmd *cobra.Command, input FormatInput, requests []trustverify.ExecutionRequest) (map[string]trustverify.ApprovalRefs, error) {
	if len(input.Approvals) != len(requests) {
		return nil, ErrFormatControls
	}
	byRequest := map[string]FormatApproval{}
	for _, a := range input.Approvals {
		if _, exists := byRequest[a.RequestSHA256]; exists {
			return nil, ErrFormatControls
		}
		byRequest[a.RequestSHA256] = a
	}
	refs := map[string]trustverify.ApprovalRefs{}
	for _, request := range requests {
		a, ok := byRequest[request.RequestSHA256]
		if !ok || request.VerifyRequestSHA256() != nil {
			return nil, ErrFormatControls
		}
		ref := trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: a.ApprovalCAS}
		if a.ApprovalInput != "" {
			raw, err := readUntrustedDocument(cmd.Context(), a.ApprovalInput)
			if err != nil {
				return nil, err
			}
			invocation, err := commandInvocation(cmd.Context())
			if err != nil {
				return nil, err
			}
			ref, err = ossinstall.ImportApproval(cmd.Context(), invocation.Selection, request, raw, invocation.Clock.Now())
			if err != nil {
				return nil, err
			}
		}
		if !formatRefPattern.MatchString(ref.ApprovalCAS) {
			return nil, ErrFormatControls
		}
		refs[request.RequestSHA256] = ref
		delete(byRequest, request.RequestSHA256)
	}
	if len(byRequest) != 0 {
		return nil, ErrFormatControls
	}
	return refs, nil
}
