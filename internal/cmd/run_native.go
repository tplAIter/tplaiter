package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/actioncmd"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type nativeRunControls struct {
	key, dir, approvalCAS, approvalInput, parameters, deliveryToken string
	prepare                                                         bool
}

func addNativeRunFlags(c *cobra.Command, v *nativeRunControls) {
	c.Flags().StringVar(&v.deliveryToken, "action-delivery-token", "", "private action delivery correlation")
	_ = c.Flags().MarkHidden("action-delivery-token")
	c.Flags().StringVar(&v.parameters, "parameters", "{}", "finite typed parameters for the authenticated native action")
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
	if len(args) != 1 || args[0] != "build" || c.Flags().Changed("parameters") || v.deliveryToken != "" {
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

func runNativeAction(c *cobra.Command, args []string, v nativeRunControls) error {
	if v.deliveryToken != "" && !validRootDeliveryToken(v.deliveryToken) {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	if len(args) != 1 || args[0] == "" || v.prepare && (v.approvalCAS != "" || v.approvalInput != "") || v.approvalCAS != "" && v.approvalInput != "" {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, e := composeRuntimeForProject(ctx, v.key)
	if e != nil {
		return e
	}
	defer r.Close()
	project := r.ProjectContext()
	if v.dir != "" {
		abs, e := filepath.Abs(v.dir)
		if e != nil || abs != project.RootPath {
			return errors.New("TRUST_PROJECT_CONTEXT_MISMATCH")
		}
	}
	source, e := projectBuildSource(ctx, r)
	if e != nil {
		return e
	}
	session, e := actioncmd.Prepare(ctx, r, source, operationtrust.ActionInput{Name: args[0], ParametersJSON: []byte(v.parameters)})
	if e != nil {
		return e
	}
	defer session.Close()
	request, e := session.Request()
	if e != nil {
		return e
	}
	data := resultdto.ProjectRunData{Command: args[0]}
	var runError error
	if v.prepare {
		data.PreparedRequest = &request
	} else {
		refs := trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: v.approvalCAS}
		if v.approvalInput != "" {
			raw, e := readUntrustedDocument(ctx, v.approvalInput)
			if e != nil {
				return e
			}
			in, e := commandInvocation(ctx)
			if e != nil {
				return e
			}
			refs, e = ossinstall.ImportApproval(ctx, in.Selection, request, raw, in.Clock.Now())
			if e != nil {
				return e
			}
		}
		data.ActionReceipt, runError = session.Execute(ctx, refs)
		if data.ActionReceipt == nil {
			return runError
		}
		if data.ActionReceipt.ChildExitCode != nil {
			data.ChildExitCode = *data.ActionReceipt.ChildExitCode
		}
	}
	check := session.Recheck(ctx)
	if check != nil && data.ActionReceipt == nil {
		return check
	}
	runError = errors.Join(runError, check)
	env := newResult(resultdto.OperationProjectRun)
	env.Project = &resultdto.Project{ID: project.ProjectID, Root: project.RootPath}
	exit := resultdto.ExitSuccess
	if runError != nil {
		exit = resultdto.ExitOperational
		env.Status = resultdto.StatusFailed
		env.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_ACTION_EXECUTION_INCOMPLETE", Severity: "error", Message: "the action outcome requires recovery", Details: map[string]any{}}}
	}
	if runError == nil && data.ActionReceipt != nil && (data.ActionReceipt.ChildExitCode == nil || *data.ActionReceipt.ChildExitCode != 0 || data.ActionReceipt.Signal != 0) {
		exit = resultdto.ExitChild
		env.Status = resultdto.StatusFailed
	}
	if e = env.SetData(data); e != nil {
		return e
	}
	if e = env.ValidateExit(exit); e != nil {
		return e
	}
	raw, e := resultdto.MarshalCanonical(env)
	if e != nil {
		return e
	}
	if len(raw)+1 > execx.MaxActionFrame {
		return errors.New("TRUST_ACTION_FRAME_OVERFLOW")
	}
	// Hold the same source/lease until the complete single result write finishes.
	// Mark before writing: a partial broken-pipe frame must not trigger a second.
	emittedResult = true
	e = writeRootFrameContext(ctx, c.OutOrStdout(), append(raw, '\n'))
	if e == nil && v.deliveryToken != "" {
		e = serveActionDelivery(ctx, session, v.deliveryToken, evidencecas.Digest(append(raw, '\n')))
	}
	var final error
	if v.deliveryToken == "" {
		final = session.Recheck(ctx)
	}
	if e != nil || final != nil {
		return &resultExitError{code: resultdto.ExitOperational, err: errors.Join(e, final, runError)}
	}
	if exit != resultdto.ExitSuccess {
		return &resultExitError{code: exit, err: errResultReported}
	}
	return nil
}

const actionDeliveryVersion = "tplaiter.dev/action-delivery/v1"

// Correlation messages carry no admission authority; the original Session owns it.
func serveActionDelivery(ctx context.Context, session *actioncmd.Session, token, digest string) error {
	control, replies := os.NewFile(3, "action-delivery-control"), os.NewFile(4, "action-delivery-replies")
	if control == nil || replies == nil {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	defer control.Close()
	defer replies.Close()
	for _, f := range []*os.File{control, replies} {
		i, e := f.Stat()
		if e != nil || i.Mode()&os.ModeNamedPipe == 0 {
			return errors.New("TRUST_REQUEST_INVALID")
		}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); control.Close(); replies.Close() })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	reader := bufio.NewReaderSize(control, 1025)
	for sequence, action := range []string{"recheck", "complete"} {
		line, e := reader.ReadSlice('\n')
		if e != nil || len(line) > 1024 {
			return errors.New("TRUST_ACTION_DELIVERY_INVALID")
		}
		var msg rootDeliveryMessage
		if canonicaljson.DecodeStrict(line, &msg) != nil || msg != (rootDeliveryMessage{actionDeliveryVersion, token, sequence + 1, action, digest}) {
			return errors.New("TRUST_ACTION_DELIVERY_INVALID")
		}
		if e = session.Recheck(ctx); e != nil {
			return e
		}
		replyAction := "ready"
		if action == "complete" {
			session.Close()
			replyAction = "closed"
		}
		reply, e := json.Marshal(rootDeliveryMessage{actionDeliveryVersion, token, sequence + 1, replyAction, digest})
		if e != nil {
			return e
		}
		if e = writeRootFrame(replies, append(reply, '\n')); e != nil {
			return e
		}
	}
	return nil
}
