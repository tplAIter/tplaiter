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
	"time"

	"golang.org/x/sys/unix"

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
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type nativeRunControls struct {
	key, dir, approvalCAS, approvalInput, parameters, deliveryToken                      string
	batchInput, batchApprovals, batchApprovalInput, batchDeliveryToken, batchFrameLayout string
	prepare                                                                              bool
}

func addNativeRunFlags(c *cobra.Command, v *nativeRunControls) {
	c.Flags().StringVar(&v.batchInput, "batch-input", "", "closed ordered run-batch-input/v1 JSON")
	c.Flags().StringVar(&v.batchApprovals, "batch-approvals", "", "ordered persistent signed approval CAS digest array")
	c.Flags().StringVar(&v.batchApprovalInput, "batch-approval-input", "", "public signed approval document array path")
	c.Flags().StringVar(&v.batchDeliveryToken, "batch-delivery-token", "", "private batch delivery correlation")
	c.Flags().StringVar(&v.batchFrameLayout, "batch-frame-layout", "", "private exact SDK normalized-ID frame layout")
	_ = c.Flags().MarkHidden("batch-delivery-token")
	_ = c.Flags().MarkHidden("batch-frame-layout")

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

func runNativeBatch(c *cobra.Command, args []string, v nativeRunControls) error {
	if len(args) != 0 || v.batchInput == "" || v.parameters != "{}" || c.Flags().Changed("parameters") || v.approvalCAS != "" || v.approvalInput != "" || v.deliveryToken != "" || (v.prepare && (v.batchApprovals != "" || v.batchApprovalInput != "")) || (v.batchApprovals != "" && v.batchApprovalInput != "") {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	if (v.batchDeliveryToken != "" && !validRootDeliveryToken(v.batchDeliveryToken)) || (v.batchFrameLayout != "" && v.batchDeliveryToken == "") || (v.batchDeliveryToken != "" && v.batchFrameLayout == "") {
		return errors.New("TRUST_REQUEST_INVALID")
	}
	input, e := operationtrust.DecodeRunBatchInput([]byte(v.batchInput))
	if e != nil {
		return e
	}
	var layout *resultwire.BatchFrameLayout
	if v.batchFrameLayout != "" {
		layout = &resultwire.BatchFrameLayout{}
		if len(v.batchFrameLayout) > 8192 || canonicaljson.DecodeStrict([]byte(v.batchFrameLayout), layout) != nil {
			return errors.New("TRUST_REQUEST_INVALID")
		}
	}
	ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	owner, e := composeRuntimeForProject(ctx, v.key)
	if e != nil {
		return e
	}
	defer owner.Close()
	project := owner.ProjectContext()
	if v.dir != "" {
		absolute, e := filepath.Abs(v.dir)
		if e != nil || absolute != project.RootPath {
			return errors.New("TRUST_PROJECT_CONTEXT_MISMATCH")
		}
	}
	source, e := projectBuildSource(ctx, owner)
	if e != nil {
		return e
	}
	session, e := actioncmd.PrepareRunBatch(ctx, owner, source, input)
	if e != nil {
		return e
	}
	defer session.Close()
	requests, e := session.Requests()
	if e != nil {
		return e
	}
	prepared := newResult(resultdto.OperationProjectRunBatch)
	prepared.Project = &resultdto.Project{ID: project.ProjectID, Root: project.RootPath}
	if e = prepared.SetData(resultdto.BatchRunData{Phase: "prepared", PreparedRequests: requests}); e != nil {
		return e
	}
	// The actual complete CLI/SDK wrapper planner runs BEFORE import, authority
	// validation or spawn. Its private presentation plan is never a permit.
	framePlan, e := resultwire.PlanBatchFrame(prepared, layout)
	if e != nil {
		return e
	}
	placeholders := make([]trustverify.ApprovalRefs, len(requests))
	for i := range placeholders {
		placeholders[i] = trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: evidencecas.Digest(nil)}
	}
	if e = execx.PreflightActionBatchControls(project.Key, input, requests, placeholders); e != nil {
		return e
	}
	actual := prepared
	exit := resultdto.ExitSuccess
	var runError error
	if !v.prepare {
		refs := make([]trustverify.ApprovalRefs, len(requests))
		if v.batchApprovalInput != "" {
			raw, e := readUntrustedDocument(ctx, v.batchApprovalInput)
			if e != nil {
				return e
			}
			var documents []json.RawMessage
			if canonicaljson.DecodeStrict(raw, &documents) != nil || len(documents) != len(requests) {
				return errors.New("TRUST_REQUEST_INVALID")
			}
			// Check the complete vector and actual control size before any CAS import.
			placeholders := make([]trustverify.ApprovalRefs, len(requests))
			for i := range placeholders {
				placeholders[i] = trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: evidencecas.Digest(nil)}
			}
			if e = execx.PreflightActionBatchControls(project.Key, input, requests, placeholders); e != nil {
				return e
			}
			in, e := commandInvocation(ctx)
			if e != nil {
				return e
			}
			for i, document := range documents {
				refs[i], e = ossinstall.ImportApproval(ctx, in.Selection, requests[i], document, in.Clock.Now())
				if e != nil {
					return e
				}
			}
		} else {
			var digests []string
			if len(v.batchApprovals) > 8192 || canonicaljson.DecodeStrict([]byte(v.batchApprovals), &digests) != nil || len(digests) != len(requests) {
				return errors.New("TRUST_REQUEST_INVALID")
			}
			for i, digest := range digests {
				refs[i] = trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: digest}
			}
		}
		if e = execx.PreflightActionBatchControls(project.Key, input, requests, refs); e != nil {
			return e
		}
		outcome, executionError := session.Execute(ctx, refs)
		runError = executionError
		if outcome == nil {
			return runError
		}
		actual = newResult(resultdto.OperationProjectRunBatch)
		actual.Project = prepared.Project
		if runError != nil {
			exit = resultdto.ExitOperational
			actual.Status = resultdto.StatusFailed
			actual.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_ACTION_BATCH_EXECUTION_INCOMPLETE", Severity: "error", Message: "the batch outcome requires recovery", Details: map[string]any{}}}
		} else if outcome.Disposition == "stopped" {
			exit = resultdto.ExitChild
			actual.Status = resultdto.StatusFailed
		}
		projected, projectErr := batchDTO(outcome)
		if projectErr != nil {
			return projectErr
		}
		if e = actual.SetData(resultdto.BatchRunData{Phase: "executed", BatchReceipt: projected}); e != nil {
			return e
		}
	}
	check := session.Recheck(ctx)
	if check != nil {
		if v.prepare {
			return check
		}
		runError = errors.Join(runError, check)
		exit = resultdto.ExitOperational
		actual.Status = resultdto.StatusFailed
		actual.Diagnostics = []resultdto.Diagnostic{{Code: "TRUST_ACTION_BATCH_EXECUTION_INCOMPLETE", Severity: "error", Message: "the batch outcome requires recovery", Details: map[string]any{}}}
		outcome := session.Outcome()
		if outcome == nil {
			return runError
		}
		outcome.Disposition = "recovery-required"
		projected, projectErr := batchDTO(outcome)
		if projectErr != nil {
			return projectErr
		}
		if e = actual.SetData(resultdto.BatchRunData{Phase: "executed", BatchReceipt: projected}); e != nil {
			return e
		}
	}
	if e = actual.ValidateExit(exit); e != nil {
		return e
	}
	raw, _, e := resultwire.EncodeBatchFrame(framePlan, actual)
	if e != nil {
		return e
	}
	if len(raw) > resultdto.MaxBatchFrame {
		return errors.New("TRUST_ACTION_FRAME_OVERFLOW")
	}
	emittedResult = true
	e = writeRootFrameContext(ctx, c.OutOrStdout(), raw)
	if e == nil && v.batchDeliveryToken != "" {
		e = serveRunBatchDelivery(ctx, session, v.batchDeliveryToken, evidencecas.Digest(raw))
	}
	var final error
	if v.batchDeliveryToken == "" {
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

func batchDTO(outcome *actioncmd.BatchResult) (*resultdto.BatchReceipt, error) {
	if outcome == nil {
		return nil, nil
	}
	out := &resultdto.BatchReceipt{APIVersion: outcome.APIVersion, OperationInputsSHA256: outcome.OperationInputsSHA256, Disposition: outcome.Disposition, Steps: make([]resultdto.BatchStepReceipt, len(outcome.Steps))}
	for i, step := range outcome.Steps {
		out.Steps[i] = resultdto.BatchStepReceipt{Ordinal: step.Ordinal, Name: step.Name, RequestSHA256: step.RequestSHA256, State: step.State}
		if step.Receipt != nil {
			raw, err := json.Marshal(step.Receipt)
			if err != nil {
				return nil, err
			}
			receipt, err := resultdto.DecodeBatchProcessReceipt(raw)
			if err != nil {
				return nil, err
			}
			out.Steps[i].Receipt = &receipt
		}
	}
	return out, nil
}

const batchDeliveryVersion = "tplaiter.dev/run-batch-delivery/v1"

func serveRunBatchDelivery(parent context.Context, session *actioncmd.BatchSession, token, digest string) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	// These private inherited channels are type-checked before altering flags.
	// Nonblocking before NewFile enables deadlines and Close cancellation; no
	// abandoned read goroutine is used for a pipe without a responding peer.
	var files [2]*os.File
	var flags [2]int
	defer func() {
		for i, f := range files {
			if f != nil {
				if raw, e := f.SyscallConn(); e == nil {
					_ = raw.Control(func(fd uintptr) { _ = syscall.SetNonblock(int(fd), flags[i]&syscall.O_NONBLOCK != 0) })
				}
				_ = f.Close()
			}
		}
	}()
	for i, fd := range []int{3, 4} {
		var st syscall.Stat_t
		if e := syscall.Fstat(fd, &st); e != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
			for _, f := range files {
				if f != nil {
					f.Close()
				}
			}
			return errors.New("TRUST_REQUEST_INVALID")
		}
		original, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if e != nil {
			return e
		}
		flags[i] = original
		if e = syscall.SetNonblock(fd, true); e != nil {
			return e
		}
		files[i] = os.NewFile(uintptr(fd), "batch-delivery-pipe")
		if files[i] == nil {
			return errors.New("TRUST_REQUEST_INVALID")
		}
	}
	control, replies := files[0], files[1]
	deadline, _ := ctx.Deadline()
	if e := control.SetReadDeadline(deadline); e != nil {
		return e
	}
	if e := replies.SetWriteDeadline(deadline); e != nil {
		return e
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
			return errors.New("TRUST_ACTION_BATCH_DELIVERY_INVALID")
		}
		var message rootDeliveryMessage
		if canonicaljson.DecodeStrict(line, &message) != nil || message != (rootDeliveryMessage{batchDeliveryVersion, token, sequence + 1, action, digest}) {
			return errors.New("TRUST_ACTION_BATCH_DELIVERY_INVALID")
		}
		if e = session.Recheck(ctx); e != nil {
			return e
		}
		reply := "ready"
		if action == "complete" {
			session.Close()
			reply = "closed"
		}
		raw, e := json.Marshal(rootDeliveryMessage{batchDeliveryVersion, token, sequence + 1, reply, digest})
		if e != nil {
			return e
		}
		if e = writeRootFrameContext(ctx, replies, append(raw, '\n')); e != nil {
			return e
		}
	}
	return nil
}
