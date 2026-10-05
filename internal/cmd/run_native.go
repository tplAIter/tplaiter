package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

type nativeRunControls struct {
	key, dir, approvalCAS, approvalInput string
	prepare                              bool
}

func addNativeRunFlags(c *cobra.Command, v *nativeRunControls) {
	c.Flags().StringVar(&v.key, "project-context", "", "authenticated installed project key")
	c.Flags().StringVar(&v.dir, "dir", "", "must equal the authenticated project root")
	c.Flags().BoolVar(&v.prepare, "prepare", false, "prepare exact signed project build request without execution")
	c.Flags().StringVar(&v.approvalCAS, "approval-cas", "", "persistent signed approval digest in installed CAS")
	c.Flags().StringVar(&v.approvalInput, "approval-input", "", "public signed grant/signature JSON to verify and import")
}
func projectBuildSource(ctx context.Context, r *trustload.Runtime) (*trustverify.VerifiedResolution, error) {
	raw, e := readRegisteredLock(ctx, r.ProjectContext().RootPath, "root-template.lock.json")
	if e != nil {
		return nil, e
	}
	lock, e := provenance.DecodeRootTemplateLock(raw)
	if e != nil {
		return nil, e
	}
	s := lock.Root
	return r.TrustRuntime().VerifySubject(ctx, trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS})
}
func runNativeBuild(c *cobra.Command, args []string, v nativeRunControls) error {
	if len(args) != 1 || args[0] != "build" {
		return actionUnavailable()
	}
	if v.prepare && (v.approvalCAS != "" || v.approvalInput != "") {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	if v.approvalCAS != "" && v.approvalInput != "" {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	// Native builds own their process group. Cancellation reaches the approved
	// runner rather than leaving a compiler behind after CLI interruption.
	ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prior := c.Context()
	c.SetContext(ctx)
	defer c.SetContext(prior)
	r, e := composeRuntimeForProject(c.Context(), v.key)
	if e != nil {
		return e
	}
	defer r.Close()
	p := r.ProjectContext()
	if v.dir != "" {
		abs, e := filepath.Abs(v.dir)
		if e != nil || abs != p.RootPath {
			return resultdto.NewError("TRUST_PROJECT_CONTEXT_MISMATCH", resultdto.ExitTrust, nil)
		}
	}
	_, values, e := nativeGenCatalog(c.Context(), r)
	if e != nil {
		return e
	}
	source, e := projectBuildSource(c.Context(), r)
	if e != nil {
		return e
	}
	selection, e := operationtrust.PrepareProjectBuild(c.Context(), r, source, "build", values)
	if e != nil {
		return e
	}
	request := selection.Request()
	project := &resultdto.Project{ID: p.ProjectID, Root: p.RootPath}
	if v.prepare {
		return emitData(c, resultdto.OperationProjectRun, project, resultdto.ProjectRunData{Command: "build", PreparedRequest: &request})
	}
	refs := trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: v.approvalCAS}
	if v.approvalInput != "" {
		raw, e := readUntrustedDocument(c.Context(), v.approvalInput)
		if e != nil {
			return e
		}
		in, e := commandInvocation(c.Context())
		if e != nil {
			return e
		}
		refs, e = ossinstall.ImportApproval(c.Context(), in.Selection, request, raw, in.Clock.Now())
		if e != nil {
			return e
		}
	}
	permits, e := operationtrust.AuthorizeActions(c.Context(), r.TrustRuntime(), source, selection.Operation(), []trustverify.ExecutionRequest{request}, []trustverify.ApprovalRefs{refs})
	if e != nil {
		return e
	}
	material, e := operationtrust.BindProjectBuildMaterial(c.Context(), r, selection)
	if e != nil {
		return e
	}
	// Authentication/answers are checked again after persistent approval and before spawn.
	if _, _, e := nativeGenCatalog(c.Context(), r); e != nil {
		return e
	}
	runner, e := execx.NewApprovedRunner(r)
	if e != nil {
		return e
	}
	receipt, e := runner.ExecuteProjectBuild(c.Context(), permits[0], request, material)
	if e != nil {
		return e
	}
	result, e := receipt.ResultFor(runner, request)
	if e != nil {
		return e
	}
	if !jsonMode(c) {
		fmt.Fprint(c.OutOrStdout(), result.Stdout)
		fmt.Fprint(c.ErrOrStderr(), result.Stderr)
		if result.ExitCode != 0 {
			return &ExitError{Code: result.ExitCode, Err: errors.New("project build failed")}
		}
		return nil
	}
	env := newResult(resultdto.OperationProjectRun)
	env.Project = project
	data := resultdto.ProjectRunData{Command: "build", ChildExitCode: result.ExitCode, ProcessReceipt: &result}
	if e := env.SetData(data); e != nil {
		return e
	}
	exit := resultdto.ExitSuccess
	if result.ExitCode != 0 {
		exit = resultdto.ExitChild
		env.Status = resultdto.StatusFailed
	}
	return emitResult(c, env, exit, nil)
}
