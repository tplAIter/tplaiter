package execx

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	ActionBootstrapToken = "--tplaiter-action-bootstrap=v1"
	MaxActionFrame       = 320 << 10
	actionStdoutLimit    = 128 << 10
	actionStderrLimit    = 16 << 10
)

// All fields are factual projection. Only ExecuteAction can create its opaque
// receipt; unmarshaling this body never grants execution or another launch.
type ActionProcessResult struct {
	APIVersion            string `json:"apiVersion"`
	RequestSHA256         string `json:"requestSHA256"`
	OperationInputsSHA256 string `json:"operationInputsSHA256"`
	InputClosureSHA256    string `json:"inputClosureSHA256"`
	ToolSHA256            string `json:"toolSHA256"`
	Profile               string `json:"profile"`
	ProfileSHA256         string `json:"profileSHA256"`
	ImplementationSHA256  string `json:"implementationSHA256"`
	Launched              string `json:"launched"`
	Disposition           string `json:"disposition"`
	ChildExitCode         *int   `json:"childExitCode,omitempty"`
	Signal                int    `json:"signal"`
	Stdout                []byte `json:"stdout"`
	Stderr                []byte `json:"stderr"`
	StdoutSHA256          string `json:"stdoutSHA256"`
	StderrSHA256          string `json:"stderrSHA256"`
	StdoutBytes           int    `json:"stdoutBytes"`
	StderrBytes           int    `json:"stderrBytes"`
	OutputComplete        bool   `json:"outputComplete"`
	TimedOut              bool   `json:"timedOut"`
	Cancelled             bool   `json:"cancelled"`
	Overflow              bool   `json:"overflow"`
	Cleanup               string `json:"cleanup"`
	PersistentWrites      *int   `json:"persistentWrites,omitempty"`
}
type (
	ActionProcessReceipt struct {
		runner  *ApprovedRunner
		request trustverify.ExecutionRequest
		result  ActionProcessResult
	}
	ActionBootstrapControl struct {
		APIVersion     string          `json:"apiVersion"`
		ProjectContext string          `json:"projectContext"`
		ActionID       string          `json:"actionID"`
		Parameters     json.RawMessage `json:"parameters"`
		ApprovalCAS    string          `json:"approvalCAS"`
		RequestSHA256  string          `json:"requestSHA256"`
		SessionSHA256  string          `json:"sessionSHA256"`
	}
)

type (
	actionDescriptor struct {
		APIVersion string                 `json:"apiVersion"`
		Files      []actionDescriptorFile `json:"files"`
	}
	actionDescriptorFile struct {
		FD     int    `json:"fd"`
		Root   string `json:"root"`
		Path   string `json:"path"`
		Mode   string `json:"mode"`
		Size   int    `json:"size"`
		SHA256 string `json:"sha256"`
	}
	actionLaunch struct {
		staged        trustverify.StagedMaterial
		projection    operationtrust.ActionProjection
		control       ActionBootstrapControl
		descriptor    []byte
		profileDigest string
	}
	actionFDTable struct {
		last    int
		pollers []int
	}
)

func ActionBootstrapHandled(args []string) bool {
	return len(args) > 0 && bytes.HasPrefix([]byte(args[0]), []byte("--tplaiter-action-bootstrap"))
}

func ReadActionBootstrapControl() (ActionBootstrapControl, error) {
	var c ActionBootstrapControl
	if err := actionControlNonblock(); err != nil {
		return c, err
	}
	f := os.NewFile(3, "action-control")
	if f == nil {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || i.Mode()&os.ModeNamedPipe == 0 {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	if e = f.SetReadDeadline(time.Now().Add(time.Second)); e != nil {
		return c, e
	}
	b, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(b) == 0 || len(b) > 64<<10 {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	canonical, e := canonicaljson.Canonicalize(b)
	if e != nil || !bytes.Equal(canonical, b) || canonicaljson.DecodeStrict(b, &c) != nil {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || len(fields) != 7 {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	var parameters map[string]json.RawMessage
	if canonicaljson.DecodeStrict(c.Parameters, &parameters) != nil || parameters == nil || len(parameters) > 16 || c.APIVersion != "tplaiter.dev/action-bootstrap/v1" || c.ProjectContext == "" || c.ActionID == "" || !actionDigest(c.ApprovalCAS) || !actionDigest(c.RequestSHA256) || !actionDigest(c.SessionSHA256) {
		return c, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	return c, nil
}

func actionDigest(s string) bool {
	if len(s) != 71 || s[:7] != "sha256:" {
		return false
	}
	for _, c := range s[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r *ApprovedRunner) ExecuteAction(ctx context.Context, permit *trustverify.ExecutionPermit, request trustverify.ExecutionRequest, material *operationtrust.ExecutionMaterial) (*ActionProcessReceipt, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.runtime == nil || permit == nil || material == nil || request.VerifyRequestSHA256() != nil {
		return nil, &ExecutionError{"TRUST_APPROVAL_MISMATCH"}
	}
	m, p, e := material.ActionFor(ctx, r.runtime, request)
	if e != nil {
		return nil, e
	}
	if e = operationtrust.RecheckAction(ctx, r.runtime.TrustRuntime(), permit, request, stagedReader{m}); e != nil {
		return nil, e
	}
	ref, e := r.runtime.TrustRuntime().PersistentApprovalReference(permit)
	if e != nil {
		return nil, e
	}
	input, e := material.ActionInputFor(r.runtime, request)
	if e != nil {
		return nil, e
	}
	params, e := canonicaljson.Canonicalize(input.ParametersJSON)
	if e != nil {
		return nil, e
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	control := ActionBootstrapControl{APIVersion: "tplaiter.dev/action-bootstrap/v1", ProjectContext: r.runtime.ProjectContext().Key, ActionID: input.Name, Parameters: params, ApprovalCAS: ref.ApprovalCAS, RequestSHA256: request.RequestSHA256, SessionSHA256: evidencecas.Digest(nonce[:])}
	l, e := makeActionLaunch(m, p, control)
	if e != nil {
		return nil, e
	}
	result, e := executeReadonlyAction(ctx, r.runtime.ScratchRoot(), l)
	if result.APIVersion == "" {
		return nil, e
	}
	receipt := &ActionProcessReceipt{runner: r, request: request, result: result}
	// A final stale/cancel error does not destroy an already observed outcome.
	if _, _, check := material.ActionFor(ctx, r.runtime, request); check != nil {
		receipt.result.Disposition = "recovery-required"
		e = errors.Join(e, check)
	}
	return receipt, e
}

func (p *ActionProcessReceipt) ResultFor(r *ApprovedRunner, request trustverify.ExecutionRequest) (ActionProcessResult, error) {
	if p == nil || r == nil || p.runner != r || request.VerifyRequestSHA256() != nil || !reflect.DeepEqual(p.request, request) {
		return ActionProcessResult{}, &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	x := p.result
	x.Stdout = append([]byte{}, x.Stdout...)
	x.Stderr = append([]byte{}, x.Stderr...)
	if x.ChildExitCode != nil {
		n := *x.ChildExitCode
		x.ChildExitCode = &n
	}
	if x.PersistentWrites != nil {
		n := *x.PersistentWrites
		x.PersistentWrites = &n
	}
	return x, nil
}

// EnterActionBootstrap is reachable only after the installed command layer
// reconstructs and authorizes actual source/tool/approval with installed pins.
func (r *ApprovedRunner) EnterActionBootstrap(ctx context.Context, permit *trustverify.ExecutionPermit, request trustverify.ExecutionRequest, material *operationtrust.ExecutionMaterial, control ActionBootstrapControl) error {
	if ctx == nil || r == nil || r.runtime == nil || permit == nil || material == nil || control.RequestSHA256 != request.RequestSHA256 {
		return &ExecutionError{"TRUST_APPROVAL_MISMATCH"}
	}
	m, p, e := material.ActionFor(ctx, r.runtime, request)
	if e != nil {
		return e
	}
	if e = operationtrust.RecheckAction(ctx, r.runtime.TrustRuntime(), permit, request, stagedReader{m}); e != nil {
		return e
	}
	l, e := makeActionLaunch(m, p, control)
	if e != nil {
		return e
	}
	if e = verifyActionInherited(l); e != nil {
		return e
	}
	// All allocations/authentication/retained observations are completed before
	// confinement. Parent retains original lifetime; child releases its readers.
	material.CloseAction(r.runtime)
	if e = r.runtime.Close(); e != nil {
		return e
	}
	return enterReadonlyAction(ctx, l)
}

func makeActionLaunch(m trustverify.StagedMaterial, p operationtrust.ActionProjection, c ActionBootstrapControl) (actionLaunch, error) {
	if len(p.Files) > 128 || len(p.Stdin) > 1<<20 || m.Request.Scope != "run" || m.Request.Action.Shell || m.Request.Action.Kind != "command" || m.Request.Action.Phase != "standalone" || m.Request.TimeoutMillis > 5000 {
		return actionLaunch{}, &ExecutionError{"TRUST_EXECUTION_MATERIAL_UNAVAILABLE"}
	}
	d := actionDescriptor{APIVersion: "tplaiter.dev/action-descriptors/v1", Files: []actionDescriptorFile{}}
	var total int
	for i, f := range p.Files {
		total += len(f.Bytes)
		if f.Mode != "100644" || evidencecas.Digest(f.Bytes) != f.SHA256 || total > 16<<20 {
			return actionLaunch{}, &ExecutionError{"TRUST_EXECUTION_MATERIAL_UNAVAILABLE"}
		}
		d.Files = append(d.Files, actionDescriptorFile{FD: 7 + i, Root: f.Root, Path: f.Path, Mode: f.Mode, Size: len(f.Bytes), SHA256: f.SHA256})
	}
	descriptor, e := canonicaljson.Canonical(d)
	if e != nil || len(descriptor) > 64<<10 {
		return actionLaunch{}, &ExecutionError{"TRUST_EXECUTION_MATERIAL_UNAVAILABLE"}
	}
	profile, e := ActionProfileDigest(p.Profile)
	if e != nil {
		return actionLaunch{}, e
	}
	return actionLaunch{staged: m, projection: p, control: c, descriptor: descriptor, profileDigest: profile}, nil
}

func ActionProfileDigest(profile string) (string, error) {
	return operationtrust.ActionProfileDigest(profile)
}

// Common flat staging is a projection helper on the same ApprovedRunner. It
// cannot select source, binaries, paths or grants from external callbacks.
type actionStage struct {
	root                 *os.Root
	dir                  *os.Root
	dirFile              *os.File
	rootInfo, dirInfo    os.FileInfo
	rootPath, name, path string
	files                []*os.File
	names                []string
	created              []string
	createdInfos         []os.FileInfo
	infos                []os.FileInfo
	hashes               []string
}

func newActionStage(root string, l actionLaunch) (*actionStage, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	for p := root; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return nil, &ExecutionError{"TRUST_STAGE_FAILED"}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	s := &actionStage{root: r, rootPath: root}
	s.rootInfo, e = r.Stat(".")
	if e != nil {
		r.Close()
		return nil, e
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		r.Close()
		return nil, e
	}
	s.name = ".tplaiter-action-" + hex.EncodeToString(nonce[:])
	s.path = filepath.Join(root, s.name)
	if e = r.Mkdir(s.name, 0o700); e != nil {
		r.Close()
		return nil, e
	}
	fail := func(e error) (*actionStage, error) { s.close(); return nil, e }
	s.dir, e = r.OpenRoot(s.name)
	if e != nil {
		return fail(e)
	}
	s.dirInfo, e = r.Lstat(s.name)
	if e != nil || s.dirInfo.Mode().Perm() != 0o700 {
		return fail(&ExecutionError{"TRUST_STAGE_FAILED"})
	}
	s.dirFile, e = r.Open(s.name)
	if e != nil {
		return fail(e)
	}
	if e = s.add("tool", l.staged.ToolBytes, 0o500); e != nil {
		return fail(e)
	}
	if e = s.add("descriptors", l.descriptor, 0o400); e != nil {
		return fail(e)
	}
	for i, f := range l.projection.Files {
		if e = s.add(fmtActionInput(i), f.Bytes, 0o400); e != nil {
			return fail(e)
		}
	}
	if len(l.projection.Stdin) > 1<<20 {
		return fail(&ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"})
	}
	if e = s.add("stdin", l.projection.Stdin, 0o400); e != nil {
		return fail(e)
	}
	return s, nil
}

func fmtActionInput(i int) string {
	const digits = "0123456789"
	return "input-" + string([]byte{digits[i/100], digits[i/10%10], digits[i%10]})
}

func (s *actionStage) add(name string, b []byte, mode os.FileMode) error {
	f, e := s.dir.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	owned, statError := f.Stat()
	s.created = append(s.created, name)
	s.createdInfos = append(s.createdInfos, owned)
	if statError != nil {
		return errors.Join(statError, f.Close())
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	f, e = s.dir.OpenFile(name, actionReadFlags(), 0)
	if e != nil {
		return e
	}
	i, e := f.Stat()
	if e != nil || !actionStageFile(i, mode) {
		f.Close()
		return &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	s.files = append(s.files, f)
	s.names = append(s.names, name)
	s.infos = append(s.infos, i)
	s.hashes = append(s.hashes, evidencecas.Digest(b))
	return nil
}

func (s *actionStage) check() error {
	if s == nil || s.root == nil || s.dir == nil {
		return &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	root, e := os.Lstat(s.rootPath)
	dir, de := s.root.Lstat(s.name)
	held, he := s.dirFile.Stat()
	if e != nil || de != nil || he != nil || !os.SameFile(root, s.rootInfo) || !os.SameFile(dir, s.dirInfo) || !os.SameFile(held, s.dirInfo) || dir.Mode() != s.dirInfo.Mode() {
		return &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	for i, f := range s.files {
		before, e := f.Stat()
		current, ce := s.dir.Lstat(s.names[i])
		if e != nil || ce != nil || !os.SameFile(s.infos[i], before) || !os.SameFile(before, current) || before.Mode() != s.infos[i].Mode() || before.Size() != s.infos[i].Size() || !actionOriginalStat(s.infos[i], before) || current.Mode() != before.Mode() || !actionStageFile(before, s.infos[i].Mode().Perm()) || !actionStageFile(current, s.infos[i].Mode().Perm()) {
			return &ExecutionError{"TRUST_STAGE_FAILED"}
		}
		b := make([]byte, before.Size()+1)
		n, e := f.ReadAt(b, 0)
		if e != io.EOF || int64(n) != before.Size() || evidencecas.Digest(b[:n]) != s.hashes[i] {
			return &ExecutionError{"TRUST_STAGE_FAILED"}
		}
		after, e := f.Stat()
		end, ce := s.dir.Lstat(s.names[i])
		if e != nil || ce != nil || !actionOriginalStat(before, after) || !actionOriginalStat(after, end) {
			return &ExecutionError{"TRUST_STAGE_FAILED"}
		}
	}
	return nil
}

func (s *actionStage) close() error {
	if s == nil {
		return nil
	}
	var e error
	for _, f := range s.files {
		e = errors.Join(e, f.Close())
	}
	s.files = nil
	if s.dir != nil {
		for i, name := range s.created {
			current, err := s.dir.Lstat(name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || s.createdInfos[i] == nil || !os.SameFile(current, s.createdInfos[i]) {
				e = errors.Join(e, &ExecutionError{"TRUST_STAGE_FAILED"})
				continue
			}
			e = errors.Join(e, s.dir.Remove(name))
		}
		e = errors.Join(e, s.dir.Close())
		s.dir = nil
	}
	if s.dirFile != nil {
		e = errors.Join(e, s.dirFile.Close())
		s.dirFile = nil
	}
	if s.root != nil {
		i, x := s.root.Lstat(s.name)
		if x == nil && s.dirInfo != nil && os.SameFile(i, s.dirInfo) {
			e = errors.Join(e, s.root.Remove(s.name))
		} else if x != nil && !errors.Is(x, os.ErrNotExist) {
			e = errors.Join(e, x)
		} else if x == nil {
			e = errors.Join(e, &ExecutionError{"TRUST_STAGE_FAILED"})
		}
		e = errors.Join(e, s.root.Close())
		s.root = nil
	}
	return e
}

func actionStageFile(i os.FileInfo, mode os.FileMode) bool {
	if i == nil || !i.Mode().IsRegular() || i.Mode() != mode {
		return false
	}
	v := reflect.ValueOf(i.Sys())
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	n := v.Elem().FieldByName("Nlink")
	return n.IsValid() && n.CanUint() && n.Uint() == 1
}

// Reading can update atime. Compare the original identity, mode, size, link
// state and mutation timestamps, excluding only atime from the retained pin.
func actionOriginalStat(original, current os.FileInfo) bool {
	if original == nil || current == nil || !os.SameFile(original, current) {
		return false
	}
	a, b := reflect.ValueOf(original.Sys()), reflect.ValueOf(current.Sys())
	if a.Kind() != reflect.Pointer || b.Kind() != reflect.Pointer || a.IsNil() || b.IsNil() {
		return false
	}
	a, b = a.Elem(), b.Elem()
	if a.Type() != b.Type() || a.Kind() != reflect.Struct {
		return false
	}
	for _, name := range []string{"Dev", "Ino", "Mode", "Nlink", "Size", "Mtim", "Ctim", "Mtimespec", "Ctimespec"} {
		x, y := a.FieldByName(name), b.FieldByName(name)
		if x.IsValid() != y.IsValid() {
			return false
		}
		if x.IsValid() && (!x.CanInterface() || !y.CanInterface() || !reflect.DeepEqual(x.Interface(), y.Interface())) {
			return false
		}
	}
	return true
}

type actionBuffer struct {
	mu     sync.Mutex
	b      []byte
	limit  int
	over   bool
	signal chan<- struct{}
}

func (b *actionBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	room := b.limit - len(b.b)
	if n > room {
		p = p[:room]
		b.over = true
		select {
		case b.signal <- struct{}{}:
		default:
		}
	}
	b.b = append(b.b, p...)
	return n, nil
}

func (b *actionBuffer) result() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte{}, b.b...), b.over
}

func runActionProcess(ctx context.Context, cmd *exec.Cmd, l actionLaunch, afterStart func(), witness func() (bool, error), status func() error) (ActionProcessResult, error) {
	x := ActionProcessResult{APIVersion: "tplaiter.dev/action-receipt/v1", RequestSHA256: l.staged.Request.RequestSHA256, OperationInputsSHA256: l.staged.Request.OperationInputsSHA256, InputClosureSHA256: l.staged.Request.Action.ContentClosureSHA256, ToolSHA256: l.staged.Request.Tool.BinarySHA256, Profile: l.projection.Profile, ProfileSHA256: l.profileDigest, Launched: "no", Disposition: "refused", Cleanup: "pending", Stdout: []byte{}, Stderr: []byte{}, StdoutSHA256: evidencecas.Digest(nil), StderrSHA256: evidencecas.Digest(nil), OutputComplete: true}
	bounded, cancel := context.WithTimeout(ctx, time.Duration(l.staged.Request.TimeoutMillis)*time.Millisecond)
	defer cancel()
	overflow := make(chan struct{}, 1)
	out, errout := &actionBuffer{limit: actionStdoutLimit, signal: overflow}, &actionBuffer{limit: actionStderrLimit, signal: overflow}
	cmd.Stdout, cmd.Stderr = out, errout
	prepareActionChild(cmd)
	if e := cmd.Start(); e != nil {
		return x, e
	}
	if afterStart != nil {
		afterStart()
	}
	x.Launched = "unknown"
	x.Disposition = "indeterminate"
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	observed := false
	var wait, errorFacts error
	watch := time.NewTicker(time.Millisecond)
	defer watch.Stop()
	running := true
	for running {
		select {
		case wait = <-done:
			running = false
		case <-watch.C:
			if witness != nil {
				yes, e := witness()
				observed = observed || yes
				errorFacts = errors.Join(errorFacts, e)
			}
		case <-bounded.Done():
			x.Cancelled = ctx.Err() != nil
			x.TimedOut = !x.Cancelled
			killActionChild(cmd)
			wait = <-done
			running = false
		case <-overflow:
			x.Overflow = true
			killActionChild(cmd)
			wait = <-done
			running = false
		}
	}
	if status != nil {
		errorFacts = errors.Join(errorFacts, status())
	} else {
		observed = wait == nil
	}
	var stdoutOverflow bool
	x.Stdout, stdoutOverflow = out.result()
	x.Overflow = x.Overflow || stdoutOverflow
	var stderrOverflow bool
	x.Stderr, stderrOverflow = errout.result()
	x.Overflow = x.Overflow || stderrOverflow
	x.StdoutBytes, x.StderrBytes = len(x.Stdout), len(x.Stderr)
	x.StdoutSHA256, x.StderrSHA256 = evidencecas.Digest(x.Stdout), evidencecas.Digest(x.Stderr)
	x.OutputComplete = !x.Overflow
	x.Cleanup = "reaped"
	if cmd.ProcessState != nil {
		code := cmd.ProcessState.ExitCode()
		if observed {
			x.Launched = "yes"
			if code >= 0 {
				x.ChildExitCode = &code
			}
			x.Signal = actionProcessSignal(cmd.ProcessState)
			x.Disposition = "completed"
			zero := 0
			x.PersistentWrites = &zero
		}
	}
	if x.Cancelled || x.TimedOut || x.Overflow || errorFacts != nil {
		x.Disposition = "recovery-required"
		return x, errors.Join(errorFacts, &ExecutionError{"TRUST_ACTION_EXECUTION_INCOMPLETE"})
	}
	if !observed {
		return x, errors.Join(wait, &ExecutionError{"TRUST_ACTION_EXECUTION_INDETERMINATE"})
	}
	return x, nil
}

// ValidateActionProcessResult validates a factual wire projection only. It
// never creates an ActionProcessReceipt or execution authority.
func ValidateActionProcessResult(x ActionProcessResult) error {
	if x.APIVersion != "tplaiter.dev/action-receipt/v1" || !actionDigest(x.RequestSHA256) || !actionDigest(x.OperationInputsSHA256) || !actionDigest(x.InputClosureSHA256) || !actionDigest(x.ToolSHA256) || !actionDigest(x.ImplementationSHA256) {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	profile, e := ActionProfileDigest(x.Profile)
	if e != nil || profile != x.ProfileSHA256 {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	if len(x.Stdout) > actionStdoutLimit || len(x.Stderr) > actionStderrLimit || x.Stdout == nil || x.Stderr == nil || x.StdoutBytes != len(x.Stdout) || x.StderrBytes != len(x.Stderr) || x.StdoutSHA256 != evidencecas.Digest(x.Stdout) || x.StderrSHA256 != evidencecas.Digest(x.Stderr) || x.Signal < 0 || x.Signal > 64 || x.Overflow && x.OutputComplete {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	if x.Launched != "yes" && x.Launched != "no" && x.Launched != "unknown" || x.Disposition != "completed" && x.Disposition != "refused" && x.Disposition != "indeterminate" && x.Disposition != "recovery-required" || x.Cleanup != "reaped" && x.Cleanup != "pending" && x.Cleanup != "failed" {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	if x.ChildExitCode != nil && (*x.ChildExitCode < 0 || *x.ChildExitCode > 255 || x.Launched != "yes" || x.Signal != 0) || x.PersistentWrites != nil && (*x.PersistentWrites != 0 || x.Launched != "yes") || x.Signal != 0 && x.Launched != "yes" {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	if x.Disposition == "completed" && (x.Launched != "yes" || x.ChildExitCode == nil && x.Signal == 0 || x.Cancelled || x.TimedOut || x.Overflow || !x.OutputComplete || x.Cleanup != "reaped") {
		return &ExecutionError{"TRUST_EXECUTION_RECEIPT_INVALID"}
	}
	return nil
}
