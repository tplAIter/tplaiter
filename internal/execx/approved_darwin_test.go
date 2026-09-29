//go:build darwin

package execx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestLimitedBuffer(t *testing.T) {
	var b limitedBuffer
	b.n = 1
	_, _ = b.Write([]byte("ab"))
	if !b.over {
		t.Fatal("unbounded")
	}
}

func TestApprovedStageOwnsAndRemovesPrivateFiles(t *testing.T) {
	root := t6BTempDir(t)
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := approvedPathForFD(fd); err != nil {
		t.Fatalf("F_GETPATH: %v", err)
	}
	m := stageFixture([]byte("not executed"))
	s, err := newApprovedStage(root, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(s.cwdPath) == root || s.toolPath == "" {
		t.Fatal("stage bridge was not held")
	}
	toolFD, cwdFD := s.tool, s.cwd
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{toolFD, cwdFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			t.Fatalf("descriptor %d remains open", fd)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("residue after close: %v %v", entries, err)
	}
}

func TestApprovedToolReadbackRejectsSubstitution(t *testing.T) {
	root := t6BTempDir(t)
	m := stageFixture([]byte("expected"))
	s, err := newApprovedStage(root, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := unix.Unlinkat(s.dir, "native-tool", 0); err != nil {
		t.Fatal(err)
	}
	fd, err := writeApprovedFile(s.dir, "native-tool", []byte("substituted"), 0o500)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := verifyApprovedTool(fd, m.ToolBytes, m.Request.Tool.BinarySHA256); err == nil {
		t.Fatal("substituted staged tool accepted")
	}
}

func TestDarwinNativeParserRejectsMalformedAndDependencies(t *testing.T) {
	wrongArch := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(wrongArch[4:], 0x01000007)
	for _, raw := range [][]byte{nil, make([]byte, 32), fatFixture(), wrongArch, machoFixture("/wrong/dyld", "/usr/lib/libSystem.B.dylib", false), machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", true), machoFixture("/usr/lib/dyld", "/tmp/evil.dylib", false), machoDependencyFixture(0x80000018), machoDependencyFixture(0x8000001f), machoDependencyFixture(0x80000023), machoDependencyFixture(0x20), malformedCommandFixture(), overlappingCommandFixture()} {
		if validDarwinNative(raw) {
			t.Fatal("invalid native image accepted")
		}
	}
}

func TestApprovedPrivateLifecycleFailuresHaveNoOutput(t *testing.T) {
	tool := buildApprovedHelper(t, "package main\nimport \"syscall\"\nfunc main(){syscall.Write(1,[]byte(\"ok\"))}\n")
	m := approvedMaterial(tool)
	root := t6BTempDir(t)
	if out, err := executeApproved(withApprovedHooks(context.Background(), approvedHooks{start: func(*exec.Cmd) error { return errors.New("injected start") }}), root, m); err == nil || out != nil {
		t.Fatalf("start = %q, %v", out, err)
	}
	if out, err := executeApproved(withApprovedHooks(context.Background(), approvedHooks{close: func() error { return errors.New("injected close after reaping") }}), root, m); err == nil || out != nil {
		t.Fatalf("cleanup = %q, %v", out, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private residue: %v %v", entries, err)
	}
}

func TestApprovedStderrOverflowFails(t *testing.T) {
	tool := buildApprovedHelper(t, "package main\nimport \"syscall\"\nfunc main(){b:=make([]byte,32768);for i:=0;i<3;i++{syscall.Write(2,b)}}\n")
	if out, err := executeApproved(context.Background(), t6BTempDir(t), approvedMaterial(tool)); err == nil || out != nil {
		t.Fatalf("stderr overflow = %q, %v", out, err)
	}
}

func approvedMaterial(tool []byte) trustverify.StagedMaterial {
	m := stageFixture(tool)
	m.Content = []trustverify.ContentEntry{{Root: "provider", Path: ".tplaiter-execution/stdin", Mode: "100644", ContentSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	m.Request.Action.Argv = []string{"native-snapshot-tool-v1"}
	m.Environment = trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}}
	return m
}

func buildApprovedHelper(t *testing.T, source string) []byte {
	t.Helper()
	d := t6BTempDir(t)
	src, out := filepath.Join(d, "main.go"), filepath.Join(d, "tool")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/opt/homebrew/bin/go", "build", "-trimpath", "-o", out, src)
	c.Env = []string{"HOME=" + filepath.Join(d, "home"), "GOMODCACHE=" + filepath.Join(d, "gomodcache"), "GOCACHE=" + testGOCACHE(t), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GO111MODULE=off", "CGO_ENABLED=0", "GOOS=darwin", "GOARCH=arm64", "PATH=/usr/bin:/bin"}
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testGOCACHE(t *testing.T) string {
	t.Helper()
	if cache, ok := os.LookupEnv("GOCACHE"); ok && cache != "" {
		return cache
	}
	return t6BTempDir(t)
}

func t6BTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve test temp dir: %v", err)
	}
	return resolved
}

func TestDarwinNativeParserAcceptsFiniteEnvelope(t *testing.T) {
	if !validDarwinNative(machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)) {
		t.Fatal("finite loader envelope rejected")
	}
}

func TestGofmtDarwinParserAllowsOnlyReviewedLibresolvClosure(t *testing.T) {
	commands := [][]byte{
		machoStringCommand(0xe, "/usr/lib/dyld"),
		machoStringCommand(0xc, "/usr/lib/libSystem.B.dylib"),
		machoStringCommand(0xc, "/usr/lib/libresolv.9.dylib"),
	}
	size := 0
	for _, command := range commands {
		size += len(command)
	}
	image := make([]byte, 32+size)
	binary.LittleEndian.PutUint32(image, 0xfeedfacf)
	binary.LittleEndian.PutUint32(image[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(image[12:], 2)
	binary.LittleEndian.PutUint32(image[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(image[20:], uint32(size))
	off := 32
	for _, command := range commands {
		copy(image[off:], command)
		off += len(command)
	}
	if !validGofmtDarwinNative(image) {
		t.Fatal("reviewed gofmt closure rejected")
	}
	if validDarwinNative(image) {
		t.Fatal("native-snapshot branch accepted gofmt-only libresolv closure")
	}
	copy(image[off-len(commands[2])+12:], []byte("/usr/lib/libevil__.dylib\x00"))
	if validGofmtDarwinNative(image) {
		t.Fatal("unreviewed dylib accepted")
	}
}

func TestDarwinNativeParserRejectsIncompatibleCPUSubtype(t *testing.T) {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[8:], 2) // arm64e is outside the declared generic arm64 envelope.
	if validDarwinNative(b) {
		t.Fatal("arm64e accepted by arm64-all runner")
	}
}

func stageFixture(tool []byte) trustverify.StagedMaterial {
	h := sha256.Sum256(tool)
	return trustverify.StagedMaterial{ToolBytes: tool, ContentBytes: [][]byte{[]byte("input")}, Request: trustverify.ExecutionRequest{Tool: trustverify.Tool{BinarySHA256: "sha256:" + hex.EncodeToString(h[:])}}}
}

func machoFixture(dyld, lib string, rpath bool) []byte {
	commands := [][]byte{machoStringCommand(0xe, dyld), machoStringCommand(0xc, lib)}
	if rpath {
		commands = append(commands, machoStringCommand(0x8000001c, "/tmp"))
	}
	sz := 0
	for _, c := range commands {
		sz += len(c)
	}
	b := make([]byte, 32+sz)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(b[20:], uint32(sz))
	o := 32
	for _, c := range commands {
		copy(b[o:], c)
		o += len(c)
	}
	return b
}

func machoStringCommand(cmd uint32, value string) []byte {
	n := 12 + len(value) + 1
	if rem := n % 8; rem != 0 {
		n += 8 - rem
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b, cmd)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[8:], 12)
	copy(b[12:], value)
	return b
}

func machoDependencyFixture(cmd uint32) []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	c := machoStringCommand(cmd, "/usr/lib/libBad.dylib")
	binary.LittleEndian.PutUint32(b[16:], 3)
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)-32+len(c)))
	return append(b, c...)
}

func malformedCommandFixture() []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[36:], 4)
	return b
}

func overlappingCommandFixture() []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[36:], uint32(len(b)))
	return b
}

func fatFixture() []byte { b := make([]byte, 32); binary.BigEndian.PutUint32(b, 0xcafebabe); return b }

// This exercises the installed-loader path with raw Git objects, signed
// publisher/transparency evidence, an enrolled store and a persistent permit.
func TestApprovedRunnerExecutesSignedNativeSnapshotMaterial(t *testing.T) {
	p := newT6BPrepared(t, "normal")
	defer p.runtime.Close()
	t.Setenv("T6B_EXEC_CANARY", "must-not-reach-approved-process")
	started, observed := false, false
	ctx := withApprovedHooks(context.Background(), approvedHooks{
		start:  func(cmd *exec.Cmd) error { started = true; return cmd.Start() },
		stdout: func([]byte) { observed = true },
	})
	receipt, err := p.runner.Execute(ctx, p.permit, p.request, p.material)
	if err != nil || receipt == nil {
		t.Fatalf("Execute = %#v, %v (started=%t stdout=%t)", receipt, err, started, observed)
	}
	stdout, err := receipt.StdoutFor(p.runner, p.request)
	if err != nil || string(stdout) != "approved:literal signed stdin\n" {
		t.Fatalf("receipt stdout = %q, %v", stdout, err)
	}
	t6BAssertEmptyScratch(t, p.fixture.scratch)
}

// This is the Go D6 proof: the tool and its version record are inside the
// signed source snapshot, both requests belong to one full operation, and two
// different persistent permits execute F(original), never F(F(original)).
func TestApprovedRunnerExecutesSignedGofmtPair(t *testing.T) {
	f := newT6BFixture(t, "gofmt", "gofmt")
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t6BClock{}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stable := r.TrustRuntime()
	resolution, err := stable.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("package fixture\nfunc f(){ }\n")
	plan, err := canonicaljson.Canonical(map[string]any{"adapter": "gofmt-stdin-v1", "apiVersion": "tplaiter.dev/formatter-plan/v1", "inputSHA256": evidencecas.Digest(input), "path": "z.go"})
	if err != nil {
		t.Fatal(err)
	}
	op, requests := f.formatterInputs(t, stable.Binding(), r.ProjectContext().ProjectID, input, plan)
	permits := make([]*trustverify.ExecutionPermit, len(requests))
	for i, request := range requests {
		permits[i], err = stable.Authorize(context.Background(), resolution, op, request, f.persistentApproval(t, request))
		if err != nil || permits[i] == nil {
			t.Fatalf("Authorize[%d] = %#v, %v", i, permits[i], err)
		}
		if _, err = stable.PersistentApprovalReference(permits[i]); err != nil {
			t.Fatalf("PersistentApprovalReference[%d]: %v", i, err)
		}
	}
	runner, err := NewApprovedRunner(r)
	if err != nil {
		t.Fatal(err)
	}
	outputs := make([][]byte, 2)
	materials := make([]*operationtrust.ExecutionMaterial, 2)
	for i, request := range requests {
		materialInput := operationtrust.FormatterInput{Path: "z.go", Mode: "100644", Bytes: input, PlanJSON: plan}
		selection, err := operationtrust.ResolveFormatterComposition(context.Background(), stable, resolution, resolution, op, op.Actions[i], materialInput)
		if err != nil {
			t.Fatalf("ResolveFormatterComposition[%d]: %v", i, err)
		}
		material, err := operationtrust.BindFormatterMaterial(context.Background(), stable, resolution, resolution, op, op.Actions[i], materialInput, selection)
		if err != nil {
			t.Fatalf("BindFormatterMaterial[%d]: %v", i, err)
		}
		materials[i] = material
		receipt, err := runner.Execute(context.Background(), permits[i], request, material)
		if err != nil || receipt == nil {
			t.Fatalf("Execute[%d] = %#v, %v", i, receipt, err)
		}
		outputs[i], err = receipt.StdoutFor(runner, request)
		if err != nil {
			t.Fatalf("StdoutFor[%d]: %v", i, err)
		}
	}
	if requests[0].Action.ID == requests[1].Action.ID || requests[0].RequestSHA256 == requests[1].RequestSHA256 || !bytes.Equal(outputs[0], outputs[1]) || !bytes.Contains(outputs[0], []byte("func f() {}")) {
		t.Fatalf("paired gofmt proof failed: requests=%#v outputs=%q / %q", requests, outputs[0], outputs[1])
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := false
	ctx = withApprovedHooks(ctx, approvedHooks{start: func(cmd *exec.Cmd) error {
		if err := cmd.Start(); err != nil {
			return err
		}
		started = true
		cancel()
		return nil
	}})
	receipt, err := runner.Execute(ctx, permits[0], requests[0], materials[0])
	cancel()
	if !started || err == nil || receipt != nil {
		t.Fatalf("in-flight gofmt cancellation: started=%t receipt=%#v err=%v", started, receipt, err)
	}
	t6BAssertEmptyScratch(t, f.scratch)
	receipt, err = runner.Execute(withApprovedHooks(context.Background(), approvedHooks{close: func() error { return errors.New("injected gofmt cleanup failure") }}), permits[1], requests[1], materials[1])
	if err == nil || receipt != nil {
		t.Fatalf("gofmt cleanup failure exposed receipt=%#v err=%v", receipt, err)
	}
	t6BAssertEmptyScratch(t, f.scratch)
}

type t6BPrepared struct {
	fixture  *t6BFixture
	runtime  *trustload.Runtime
	runner   *ApprovedRunner
	permit   *trustverify.ExecutionPermit
	request  trustverify.ExecutionRequest
	material *operationtrust.ExecutionMaterial
}

type t6BResolved struct {
	fixture    *t6BFixture
	runtime    *trustload.Runtime
	stable     *trustverify.Runtime
	resolution *trustverify.VerifiedResolution
	op         trustverify.OperationInputs
	request    trustverify.ExecutionRequest
}

func newT6BResolved(t *testing.T, toolMode, sourceVariant string) *t6BResolved {
	t.Helper()
	f := newT6BFixture(t, toolMode, sourceVariant)
	r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t6BClock{}})
	if err != nil {
		t.Fatalf("OpenRuntime: %v", err)
	}
	stable := r.TrustRuntime()
	if stable == nil {
		t.Fatal("missing stable runtime")
	}
	resolution, err := stable.VerifySubject(context.Background(), f.subject, f.refs)
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	timeout := int64(5000)
	if toolMode == "hang" {
		timeout = 1000
	}
	op, request := f.executionInputs(t, stable.Binding(), r.ProjectContext().ProjectID, timeout)
	return &t6BResolved{fixture: f, runtime: r, stable: stable, resolution: resolution, op: op, request: request}
}

func newT6BPrepared(t *testing.T, toolMode string) *t6BPrepared {
	t.Helper()
	b := newT6BResolved(t, toolMode, "normal")
	permits, err := operationtrust.AuthorizeActions(context.Background(), b.stable, b.resolution, b.op, []trustverify.ExecutionRequest{b.request}, []trustverify.ApprovalRefs{b.fixture.persistentApproval(t, b.request)})
	if err != nil || len(permits) != 1 {
		t.Fatalf("AuthorizeActions = %v, %v", permits, err)
	}
	selection, err := operationtrust.ResolveFixedComposition(context.Background(), b.stable, b.resolution, b.op, b.request)
	if err != nil {
		t.Fatalf("ResolveFixedComposition: %v", err)
	}
	material, err := operationtrust.BindExecutionMaterial(context.Background(), b.stable, b.resolution, b.op, b.request, selection)
	if err != nil {
		t.Fatalf("BindExecutionMaterial: %v", err)
	}
	runner, err := NewApprovedRunner(b.runtime)
	if err != nil {
		t.Fatalf("NewApprovedRunner: %v", err)
	}
	return &t6BPrepared{fixture: b.fixture, runtime: b.runtime, runner: runner, permit: permits[0], request: b.request, material: material}
}

func TestApprovedRunnerSignedDescendantGroupTermination(t *testing.T) {
	p := newT6BPrepared(t, "descendant")
	defer p.runtime.Close()
	if !validDarwinNative(p.fixture.tool) {
		t.Fatalf("signed descendant helper rejected by Darwin envelope (bytes=%d)", len(p.fixture.tool))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pidCh := make(chan int, 1)
	var pidLine []byte
	observe := func(b []byte) {
		pidLine = append(pidLine, b...)
		if at := bytes.IndexByte(pidLine, '\n'); at >= 0 {
			pid, e := strconv.Atoi(string(pidLine[:at]))
			if e == nil && pid > 1 {
				select {
				case pidCh <- pid:
				default:
				}
			}
		}
	}
	type res struct {
		r *ExecutionReceipt
		e error
	}
	done := make(chan res, 1)
	go func() {
		r, e := p.runner.Execute(withApprovedHooks(ctx, approvedHooks{stdout: observe}), p.permit, p.request, p.material)
		done <- res{r, e}
	}()
	var pid int
	select {
	case pid = <-pidCh:
	case got := <-done:
		t.Fatalf("Execute completed before descendant readiness: receipt=%#v err=%v", got.r, got.e)
	case <-time.After(30 * time.Second):
		cancel()
		select {
		case got := <-done:
			if got.e == nil || got.r != nil {
				t.Fatalf("readiness timeout cleanup result: receipt=%#v err=%v", got.r, got.e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("descendant readiness timeout cleanup did not finish")
		}
		t.Fatal("descendant readiness timeout")
	}
	cancel()
	got := <-done
	if got.e == nil || got.r != nil {
		t.Fatalf("receipt=%#v err=%v", got.r, got.e)
	}
	until := time.Now().Add(2 * time.Second)
	for {
		e := syscall.Kill(pid, 0)
		if errors.Is(e, syscall.ESRCH) {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("descendant %d survives", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t6BAssertEmptyScratch(t, p.fixture.scratch)
}

func TestApprovedRunnerHooksArePerExecution(t *testing.T) {
	a, b := newT6BPrepared(t, "normal"), newT6BPrepared(t, "normal")
	defer a.runtime.Close()
	defer b.runtime.Close()
	var aN, bN int
	type result struct {
		r *ExecutionReceipt
		e error
	}
	doneA, doneB := make(chan result, 1), make(chan result, 1)
	go func() {
		r, e := a.runner.Execute(withApprovedHooks(context.Background(), approvedHooks{stdout: func([]byte) { aN++ }}), a.permit, a.request, a.material)
		doneA <- result{r, e}
	}()
	go func() {
		r, e := b.runner.Execute(withApprovedHooks(context.Background(), approvedHooks{stdout: func([]byte) { bN++ }}), b.permit, b.request, b.material)
		doneB <- result{r, e}
	}()
	for _, done := range []chan result{doneA, doneB} {
		got := <-done
		if got.e != nil || got.r == nil {
			t.Fatalf("concurrent Execute = %#v, %v", got.r, got.e)
		}
	}
	if aN != 1 || bN != 1 {
		t.Fatalf("cross-execution observers a=%d b=%d", aN, bN)
	}
	t6BAssertEmptyScratch(t, a.fixture.scratch)
	t6BAssertEmptyScratch(t, b.fixture.scratch)
}

func t6BAssertEmptyScratch(t *testing.T, scratch string) {
	t.Helper()
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("scratch residue = %v, %v", entries, err)
	}
}

func TestApprovedRunnerRejectsClosedZeroForeignAndMismatchedMaterialBeforeStage(t *testing.T) {
	t.Run("closed-runtime", func(t *testing.T) {
		p := newT6BPrepared(t, "normal")
		if err := p.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		receipt, err := p.runner.Execute(context.Background(), p.permit, p.request, p.material)
		if err == nil || receipt != nil {
			t.Fatalf("closed Execute = %#v, %v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
	})
	t.Run("zero-material", func(t *testing.T) {
		p := newT6BPrepared(t, "normal")
		defer p.runtime.Close()
		receipt, err := p.runner.Execute(context.Background(), p.permit, p.request, new(operationtrust.ExecutionMaterial))
		if err == nil || receipt != nil {
			t.Fatalf("zero Execute = %#v, %v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
	})
	t.Run("foreign-material", func(t *testing.T) {
		p, foreign := newT6BPrepared(t, "normal"), newT6BPrepared(t, "normal")
		defer p.runtime.Close()
		defer foreign.runtime.Close()
		receipt, err := p.runner.Execute(context.Background(), p.permit, p.request, foreign.material)
		if err == nil || receipt != nil {
			t.Fatalf("foreign Execute = %#v, %v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
		t6BAssertEmptyScratch(t, foreign.fixture.scratch)
	})
	t.Run("request-mismatch", func(t *testing.T) {
		p := newT6BPrepared(t, "normal")
		defer p.runtime.Close()
		other := p.request
		other.TimeoutMillis++
		var err error
		other.RequestSHA256, err = other.ComputeRequestSHA256()
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := p.runner.Execute(context.Background(), p.permit, other, p.material)
		if err == nil || receipt != nil {
			t.Fatalf("mismatch Execute = %#v, %v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
	})
}

func TestSignedSnapshotConventionRejectsBeforeStage(t *testing.T) {
	variants := []string{"absent", "extra", "nested", "alias", "tool-mode", "stdin-mode", "dir-mode", "symlink", "missing-tool", "missing-stdin", "oversize-tool", "oversize-stdin"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			f := newT6BFixture(t, "normal", variant)
			r, err := trustload.OpenRuntime(context.Background(), trustload.RuntimeOptions{Selection: f.selection, ProjectKey: "project", Clock: t6BClock{}})
			if err != nil {
				t.Fatalf("OpenRuntime: %v", err)
			}
			defer r.Close()
			stable := r.TrustRuntime()
			resolution, verifyErr := stable.VerifySubject(context.Background(), f.subject, f.refs)
			if verifyErr == nil {
				op, request := f.executionInputs(t, stable.Binding(), r.ProjectContext().ProjectID, 5000)
				if selection, err := operationtrust.ResolveFixedComposition(context.Background(), stable, resolution, op, request); err == nil || selection != nil {
					t.Fatalf("ResolveFixedComposition accepted %s = %#v, %v", variant, selection, err)
				}
			}
			t6BAssertEmptyScratch(t, f.scratch)
		})
	}
}

func TestApprovedRunnerNoReceiptOnFailureTimeoutCancelOrOverflow(t *testing.T) {
	for _, mode := range []string{"fail", "overflow", "stderr", "hang", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			toolMode := mode
			if mode == "cancel" {
				toolMode = "normal"
			}
			p := newT6BPrepared(t, toolMode)
			defer p.runtime.Close()
			ctx := context.Background()
			if mode == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			receipt, err := p.runner.Execute(ctx, p.permit, p.request, p.material)
			if err == nil || receipt != nil {
				t.Fatalf("%s Execute = %#v, %v", mode, receipt, err)
			}
			t6BAssertEmptyScratch(t, p.fixture.scratch)
		})
	}
}

func TestApprovedRunnerSignedStartAndCleanupFailureHaveNoReceipt(t *testing.T) {
	t.Run("start", func(t *testing.T) {
		p := newT6BPrepared(t, "normal")
		defer p.runtime.Close()
		receipt, err := p.runner.Execute(withApprovedHooks(context.Background(), approvedHooks{start: func(*exec.Cmd) error { return errors.New("injected start after recheck") }}), p.permit, p.request, p.material)
		if err == nil || receipt != nil {
			t.Fatalf("start receipt=%#v err=%v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
	})
	t.Run("cleanup", func(t *testing.T) {
		p := newT6BPrepared(t, "normal")
		defer p.runtime.Close()
		receipt, err := p.runner.Execute(withApprovedHooks(context.Background(), approvedHooks{close: func() error { return errors.New("injected cleanup after direct-child wait") }}), p.permit, p.request, p.material)
		if err == nil || receipt != nil {
			t.Fatalf("cleanup receipt=%#v err=%v", receipt, err)
		}
		t6BAssertEmptyScratch(t, p.fixture.scratch)
	})
}

type t6BClock struct{}

func (t6BClock) Now() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }

type t6BFixture struct {
	dir, scratch, project, evidence string
	selection                       trustload.LaunchSelection
	policy                          trustverify.ExecutionPolicy
	anchor, publisher, approver     ed25519.PrivateKey
	subject                         trustverify.Subject
	refs                            trustverify.EvidenceRefs
	tool, stdin                     []byte
}

func newT6BFixture(t *testing.T, toolMode, sourceVariant string) *t6BFixture {
	t.Helper()
	base := "/private/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "tplaiter-t6-b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &t6BFixture{dir: dir, scratch: filepath.Join(dir, "scratch"), project: filepath.Join(dir, "project"), evidence: filepath.Join(dir, "evidence"), anchor: ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901")), publisher: ed25519.NewKeyFromSeed([]byte("12345678901234567890123456789012")), approver: ed25519.NewKeyFromSeed([]byte("23456789012345678901234567890123")), stdin: []byte("literal signed stdin\n")}
	for _, p := range []string{f.scratch, f.project, f.evidence, filepath.Join(dir, "objects"), filepath.Join(dir, "home")} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.tool = t6BBuildHelper(t, dir, toolMode)
	if sourceVariant == "oversize-tool" {
		f.tool = bytes.Repeat([]byte{'t'}, 16<<20+1)
	}
	if sourceVariant == "oversize-stdin" {
		f.stdin = bytes.Repeat([]byte{'s'}, 1<<20+1)
	}
	f.subject = t6BWriteSource(t, filepath.Join(dir, "objects"), f.tool, f.stdin, sourceVariant)
	evidence := map[string][]byte{}
	put := func(b []byte) string { d := evidencecas.Digest(b); evidence[d] = append([]byte(nil), b...); return d }
	anchorPub, publisherPub := f.anchor.Public().(ed25519.PublicKey), f.publisher.Public().(ed25519.PublicKey)
	rootRef := put([]byte(bootstrap.EncodePublicKey(publisherPub)))
	env := bootstrap.Envelope{APIVersion: bootstrap.TrustRootsAPIVersion, AuthorityID: "t6b-authority", Sequence: 1, Validity: bootstrap.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, AllowedPolicyOrigins: []string{"https://example.test/policy"}, RootKeys: []bootstrap.RootKey{{Fingerprint: bootstrap.Fingerprint(publisherPub), PublicKeyCAS: rootRef, Issuer: "publisher-1", Status: "active"}}, Threshold: 1, RevocationEpoch: 0, Revocations: []bootstrap.Revocation{}}
	if env.PayloadSHA256, err = env.ComputePayloadSHA256(); err != nil {
		t.Fatal(err)
	}
	payload, _ := hex.DecodeString(env.PayloadSHA256[7:])
	env.Signatures = []bootstrap.Signature{{KeyFingerprint: bootstrap.Fingerprint(anchorPub), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(f.anchor, payload))))}}
	envRef := put(t6BJSON(t, env))
	f.refs = t6BPublisherEvidence(t, evidence, f.publisher, f.subject)
	leaf0, leaf1 := bootstrap.HashLeaf([]byte(env.PayloadSHA256)), bootstrap.HashLeaf([]byte(f.refs.StatementCAS))
	root := bootstrap.HashChildren(leaf0, leaf1)
	checkpointRef := put(t6BJSON(t, bootstrap.Checkpoint{APIVersion: bootstrap.CheckpointAPIVersion, AuthorityID: env.AuthorityID, TreeSize: 2, RootHash: "sha256:" + hex.EncodeToString(root[:])}))
	f.refs.CheckpointCAS = checkpointRef
	f.refs.InclusionProofCAS = put(t6BJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 1, TreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(leaf0[:])}}))
	envProof := put(t6BJSON(t, bootstrap.InclusionProof{APIVersion: bootstrap.InclusionAPIVersion, LeafIndex: 0, TreeSize: 2, Hashes: []string{"sha256:" + hex.EncodeToString(leaf1[:])}}))
	receipt := bootstrap.Receipt{APIVersion: bootstrap.TrustReceiptAPIVersion, AuthorityID: env.AuthorityID, HighestAcceptedSequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, TreeSize: 2, CheckpointDigest: checkpointRef}
	if receipt.ReceiptDigest, err = receipt.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	receiptRef := put(t6BJSON(t, receipt))
	desc := bootstrap.DescriptorDocument{APIVersion: bootstrap.DescriptorAPIVersion, Profile: bootstrap.ProfileOSS, AuthorityID: env.AuthorityID, Anchors: []bootstrap.DescriptorAnchor{{Fingerprint: bootstrap.Fingerprint(anchorPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(anchorPub)}}, Threshold: 1, AllowedPolicyOrigins: []string{"https://example.test/policy"}, PublisherScopes: []bootstrap.PublisherScope{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", SourceOrigin: f.subject.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Usage: "template-source"}}}
	desc.DescriptorSHA256 = desc.ComputedSHA256()
	opRecord := trustload.OperatorPinRecord{APIVersion: trustload.OperatorPinRecordAPIVersion, Method: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256}
	opRaw := t6BJSON(t, opRecord)
	prov := bootstrap.ProvisioningRecord{APIVersion: bootstrap.ProvisioningAPIVersion, Mode: "operator-pinned", DescriptorSHA256: desc.DescriptorSHA256, AuthenticationEvidenceSHA256: evidencecas.Digest(opRaw), EvidenceClass: bootstrap.EvidenceSimulated}
	prov.ProvisioningSHA256 = prov.ComputedSHA256()
	state := bootstrap.OSSAcceptedState{APIVersion: bootstrap.OSSAcceptedStateAPIVersion, DescriptorSHA256: desc.DescriptorSHA256, ProvisioningSHA256: prov.ProvisioningSHA256, AuthorityID: env.AuthorityID, Sequence: 1, EnvelopePayloadSHA256: env.PayloadSHA256, RevocationEpoch: 0, ReceiptDigest: receipt.ReceiptDigest, TreeSize: 2, CheckpointDigest: checkpointRef}
	state.StateSHA256 = state.ComputedSHA256()
	approverPub := f.approver.Public().(ed25519.PublicKey)
	f.policy = trustverify.ExecutionPolicy{APIVersion: trustverify.ExecutionPolicyAPIVersion, PolicyID: "t6b-policy", Profile: "oss", MinimumProfile: "oss", Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Principals: []trustverify.Principal{{ID: "principal:approver"}, {ID: "principal:publisher"}, {ID: "principal:submitter"}}, IssuerPrincipals: []trustverify.IssuerPrincipal{{Issuer: "publisher-1", PrincipalID: "principal:publisher"}}, SourceRules: []trustverify.SourceRule{{PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Origin: f.subject.Origin, TemplatePath: ".", Predicate: "https://example.test/predicate", Format: "tplaiter-publisher-statement-v1"}}, Approvers: []trustverify.Approver{{ID: "t6b-approver", PrincipalID: "principal:approver", IdentityClass: "operator", KeyFingerprint: bootstrap.Fingerprint(approverPub), PublicKeyBase64: base64.StdEncoding.EncodeToString(approverPub), Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, Scopes: []trustverify.ApprovalScope{{ProjectID: "project-t6b", OperationScope: "run", ActionKind: "command", Origin: f.subject.Origin, TemplatePath: "."}, {ProjectID: "project-t6b", OperationScope: "run", ActionKind: "formatter", Origin: f.subject.Origin, TemplatePath: "."}}}}, AllowInvocationHuman: false, MaxTimeoutMillis: 5000}
	if f.policy.PolicySHA256, err = f.policy.ComputePolicySHA256(); err != nil {
		t.Fatal(err)
	}
	descRaw, provRaw, policyRaw := t6BJSON(t, desc), t6BJSON(t, prov), t6BJSON(t, f.policy)
	for p, b := range map[string][]byte{filepath.Join(dir, "descriptor.json"): descRaw, filepath.Join(dir, "provisioning.json"): provRaw, filepath.Join(dir, "operator.json"): opRaw, filepath.Join(dir, "policy.json"): policyRaw, filepath.Join(dir, "state.json"): t6BJSON(t, state)} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := trustload.StoredBundle{APIVersion: "tplaiter.dev/stored-bootstrap-bundle/v1", EnvelopeCAS: envRef, ReceiptCAS: receiptRef, Transparency: trustload.StoredTransparency{CheckpointCAS: checkpointRef, InclusionProofCAS: envProof}}
	bundleRaw := t6BJSON(t, bundle)
	bundleDigest, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundleRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	install := trustload.RuntimeInstall{APIVersion: trustload.RuntimeInstallAPIVersion, InstallationID: "t6b-install", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS, Descriptor: t6BPin(filepath.Join(dir, "descriptor.json"), descRaw), Provisioning: t6BPin(filepath.Join(dir, "provisioning.json"), provRaw), OperatorRecord: t6BPin(filepath.Join(dir, "operator.json"), opRaw), ExecutionPolicy: t6BPin(filepath.Join(dir, "policy.json"), policyRaw), ProjectContexts: []trustload.ProjectContext{{Key: "project", ProjectID: "project-t6b", SubmitterPrincipalID: "principal:submitter", MinimumProfile: bootstrap.ProfileOSS, RootPath: f.project}}, ObjectOrigins: []trustload.ObjectOrigin{{Origin: f.subject.Origin, RootPath: filepath.Join(dir, "objects")}}, EvidenceRoot: f.evidence, ScratchRoot: f.scratch, OSS: &trustload.OSSInstall{StorePath: filepath.Join(dir, "store"), InitialStatePath: filepath.Join(dir, "state.json"), InitialStateSHA256: state.StateSHA256, InitialBundlePath: filepath.Join(dir, "bundle.json"), InitialBundleSHA256: bundleDigest}}
	installRaw := t6BJSON(t, install)
	installPath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(installPath, installRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	installDigest, err := install.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f.selection = trustload.LaunchSelection{Profile: bootstrap.ProfileOSS, RuntimeConfig: trustload.FilePin{Path: installPath, SHA256: installDigest}, OperatorRecord: install.OperatorRecord, InstallationID: install.InstallationID}
	factory := func(r evidencecas.Reader) (*bootstrap.Verifier, error) {
		return bootstrap.NewVerifier(r, t6BClock{}, nil, 0)
	}
	if err := trustload.Enroll(context.Background(), f.selection, factory, t6BJSON(t, state), bundleRaw, evidence); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return f
}

func t6BBuildHelper(t *testing.T, dir, mode string) []byte {
	t.Helper()
	src, out := filepath.Join(dir, "native-helper.go"), filepath.Join(dir, "native-tool")
	var raw []byte
	switch mode {
	case "gofmt":
		raw = []byte("package main\n")
	case "normal":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){if _,ok:=syscall.Getenv(\"T6B_EXEC_CANARY\");ok{syscall.Write(1,[]byte(\"inherited-env\"));return};b:=make([]byte,1024);n,_:=syscall.Read(0,b);syscall.Write(1,append([]byte(\"approved:\"),b[:n]...))}\n")
	case "fail":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){syscall.Exit(3)}\n")
	case "overflow":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){b:=make([]byte,32768);for i:=0;i<64;i++{syscall.Write(1,b)}}\n")
	case "stderr":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){b:=make([]byte,32768);for i:=0;i<3;i++{syscall.Write(2,b)}}\n")
	case "hang":
		raw = []byte("package main\nfunc main(){for {}}\n")
	case "descendant":
		raw = []byte("package main\nimport \"syscall\"\nfunc main(){p,e:=syscall.ForkExec(\"/bin/sleep\",[]string{\"sleep\",\"30\"},&syscall.ProcAttr{Files:[]uintptr{0,1,2}});if e==nil{var b [24]byte;i:=len(b)-1;b[i]='\\n';for p>0{i--;b[i]=byte('0'+p%10);p/=10};syscall.Write(1,b[i:])};for {}}\n")
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"build", "-trimpath", "-o", out, src}
	if mode == "gofmt" {
		args = []string{"build", "-trimpath", "-o", out, "cmd/gofmt"}
	}
	cmd := exec.Command("/opt/homebrew/bin/go", args...)
	cmd.Env = []string{"HOME=" + filepath.Join(dir, "home"), "GOMODCACHE=" + filepath.Join(dir, "gomodcache"), "GOCACHE=" + testGOCACHE(t), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GO111MODULE=off", "CGO_ENABLED=0", "GOOS=darwin", "GOARCH=arm64", "PATH=/usr/bin:/bin"}
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper build: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func t6BWriteSource(t *testing.T, root string, tool, stdin []byte, variant string) trustverify.Subject {
	t.Helper()
	manifest := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata:\n  name: t6b\n  version: 1.0.0\n  description: fixture\nengine:\n  type: gotemplate\n  root: files\nsettings:\n  - group: label\n    title: Label\n    type: string\n    default: ok\n")
	h := sha256.Sum256(manifest)
	contract := []byte(`{"apiVersion":"tplaiter.dev/native-template-contract/v1","kind":"NativeTemplate","manifestPath":"template.manifest.yaml","manifestSHA256":"sha256:` + hex.EncodeToString(h[:]) + `","dependencies":[]}`)
	objects := map[string][]byte{}
	add := func(kind string, data []byte) string {
		raw := append([]byte(kind+" "+t6BItoa(len(data))+"\x00"), data...)
		sum := sha1.Sum(raw)
		id := hex.EncodeToString(sum[:])
		objects[id] = raw
		return id
	}
	blob := func(b []byte) string { return add("blob", b) }
	files := t6BTree(add, []t6BTreeEntry{{"100644", "hello.txt.tmpl", blob([]byte("hello\n"))}})
	execTree := []t6BTreeEntry{{"100755", "native-tool", blob(tool)}, {"100644", "stdin", blob(stdin)}}
	execEntries := []trustverify.SourceEntry{{Path: ".tplaiter-execution", Kind: "directory", Mode: "40000"}, {Path: ".tplaiter-execution/native-tool", Kind: "file", Mode: "100755", ContentSHA256: evidencecas.Digest(tool)}, {Path: ".tplaiter-execution/stdin", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(stdin)}}
	var formatterTree string
	var formatterEntries []trustverify.SourceEntry
	if variant == "gofmt" {
		info, err := buildinfo.Read(bytes.NewReader(tool))
		if err != nil {
			t.Fatal(err)
		}
		record, err := canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(tool), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": "darwin-arm64-dyld-libsystem-libresolv-v1"})
		if err != nil {
			t.Fatal(err)
		}
		formatterTree = t6BTree(add, []t6BTreeEntry{{"100755", "native-tool", blob(tool)}, {"100644", "tool.json", blob(record)}})
		formatterEntries = []trustverify.SourceEntry{{Path: "formatter", Kind: "directory", Mode: "40000"}, {Path: "formatter/native-tool", Kind: "file", Mode: "100755", ContentSHA256: evidencecas.Digest(tool)}, {Path: "formatter/tool.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(record)}}
	}
	includeExec := true
	switch variant {
	case "normal", "oversize-tool", "oversize-stdin", "gofmt":
	case "absent":
		includeExec, execTree, execEntries = false, nil, nil
	case "extra":
		execTree = append(execTree, t6BTreeEntry{"100644", "extra", blob([]byte("extra"))})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/extra", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("extra"))})
	case "nested":
		nested := t6BTree(add, []t6BTreeEntry{{"100644", "child", blob([]byte("child"))}})
		execTree = append(execTree, t6BTreeEntry{"40000", "nested", nested})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/nested", Kind: "directory", Mode: "40000"}, trustverify.SourceEntry{Path: ".tplaiter-execution/nested/child", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("child"))})
	case "alias":
		execTree = append(execTree, t6BTreeEntry{"100644", "native_tool", blob([]byte("alias"))})
		execEntries = append(execEntries, trustverify.SourceEntry{Path: ".tplaiter-execution/native_tool", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("alias"))})
	case "tool-mode":
		execTree[0].mode, execEntries[1].Mode = "100644", "100644"
	case "stdin-mode":
		execTree[1].mode, execEntries[2].Mode = "100755", "100755"
	case "dir-mode":
		execEntries[0].Mode = "40755"
	case "missing-tool":
		execTree, execEntries = execTree[1:], []trustverify.SourceEntry{execEntries[0], execEntries[2]}
	case "missing-stdin":
		execTree, execEntries = execTree[:1], execEntries[:2]
	case "symlink":
		execTree[0].mode, execEntries[1].Mode = "120000", "120000"
	default:
		t.Fatalf("unknown source variant %q", variant)
	}
	rootEntries := []t6BTreeEntry{{"40000", "files", files}, {"100644", "template.contract.json", blob(contract)}, {"100644", "template.manifest.yaml", blob(manifest)}}
	if formatterTree != "" {
		rootEntries = append(rootEntries, t6BTreeEntry{"40000", "formatter", formatterTree})
	}
	if includeExec {
		execDir := t6BTree(add, execTree)
		rootEntries = append(rootEntries, t6BTreeEntry{"40000", ".tplaiter-execution", execDir})
	}
	rootID := t6BTree(add, rootEntries)
	commit := add("commit", []byte("tree "+rootID+"\n\nauthor t6b <t6b@example.test> 0 +0000\n"))
	for id, raw := range objects {
		if err := os.WriteFile(filepath.Join(root, id), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries := append(execEntries, formatterEntries...)
	entries = append(entries, trustverify.SourceEntry{Path: "files", Kind: "directory", Mode: "40000"}, trustverify.SourceEntry{Path: "files/hello.txt.tmpl", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest([]byte("hello\n"))}, trustverify.SourceEntry{Path: "template.contract.json", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(contract)}, trustverify.SourceEntry{Path: "template.manifest.yaml", Kind: "file", Mode: "100644", ContentSHA256: evidencecas.Digest(manifest)})
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-content-tree/v1", struct {
		APIVersion string                    `json:"apiVersion"`
		Entries    []trustverify.SourceEntry `json:"entries"`
	}{"tplaiter.dev/source-content-tree/v1", entries})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest, err := bootstrap.DomainDigest("tplaiter.dev/source-contract/v1", struct {
		APIVersion    string `json:"apiVersion"`
		Path          string `json:"path"`
		ContentSHA256 string `json:"contentSHA256"`
	}{"tplaiter.dev/source-contract/v1", "template.contract.json", evidencecas.Digest(contract)})
	if err != nil {
		t.Fatal(err)
	}
	return trustverify.Subject{Origin: "https://example.test/source", TemplatePath: ".", RequestedRef: commit, Commit: commit, TreeSHA256: treeDigest, ContractSHA256: contractDigest}
}

func (f *t6BFixture) executionInputs(t *testing.T, b bootstrap.ProfileBinding, project string, timeout int64) (trustverify.OperationInputs, trustverify.ExecutionRequest) {
	t.Helper()
	bd, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, b)
	if err != nil {
		t.Fatal(err)
	}
	content := []trustverify.ContentEntry{{Root: "provider", Path: ".tplaiter-execution/stdin", Mode: "100644", ContentSHA256: evidencecas.Digest(f.stdin)}}
	closure, err := trustverify.ComputeContentClosureSHA256(content)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := trustverify.ComputeToolOptionsSHA256([]string{})
	if err != nil {
		t.Fatal(err)
	}
	env := trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Inherit: false, Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}, Capabilities: []string{}}
	envD, err := trustverify.ComputeEnvironmentPolicySHA256(env)
	if err != nil {
		t.Fatal(err)
	}
	p := trustverify.Provider{Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath, Commit: f.subject.Commit, TreeSHA256: f.subject.TreeSHA256, ContractSHA256: f.subject.ContractSHA256}
	a := trustverify.Action{ID: "native-action", Kind: "command", Phase: "standalone", Shell: false, Argv: []string{"native-snapshot-tool-v1"}, ContentClosureSHA256: closure}
	tool := trustverify.Tool{ID: "native-snapshot-tool-v1", Version: "1", BinarySHA256: evidencecas.Digest(f.tool), OptionsSHA256: opts}
	m := trustverify.ActionMaterial{Provider: p, Action: a, Tool: tool, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "provider", Path: ".tplaiter-execution"}, EnvironmentPolicySHA256: envD, TimeoutMillis: timeout, Migration: trustverify.Migration{Kind: "none"}}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: project, Scope: "run", PreimageSHA256: evidencecas.Digest([]byte("preimage")), AnswersSHA256: evidencecas.Digest([]byte("{}")), Subjects: []trustverify.Provider{p}, Actions: []trustverify.ActionMaterial{m}}
	od, err := trustverify.ComputeOperationInputsSHA256(op)
	if err != nil {
		t.Fatal(err)
	}
	r := trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: od, ProjectID: project, Scope: "run", Provider: p, Action: a, Tool: tool, WorkingDirectoryScope: m.WorkingDirectoryScope, EnvironmentPolicySHA256: envD, TimeoutMillis: m.TimeoutMillis, Migration: m.Migration}
	if r.RequestSHA256, err = r.ComputeRequestSHA256(); err != nil {
		t.Fatal(err)
	}
	return op, r
}

func (f *t6BFixture) formatterInputs(t *testing.T, b bootstrap.ProfileBinding, project string, input, plan []byte) (trustverify.OperationInputs, []trustverify.ExecutionRequest) {
	t.Helper()
	bd, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, b)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := f.formatterRecord()
	if !ok {
		t.Fatal("missing formatter record")
	}
	entries := []trustverify.ContentEntry{{Root: "project", Path: "z.go", Mode: "100644", ContentSHA256: evidencecas.Digest(input)}, {Root: "project", Path: "formatter/plan.json", Mode: "100644", ContentSHA256: evidencecas.Digest(plan)}, {Root: "project", Path: "formatter/tool.json", Mode: "100644", ContentSHA256: evidencecas.Digest(record)}}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Root+"\x00"+entries[i].Path < entries[j].Root+"\x00"+entries[j].Path
	})
	closure, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := trustverify.ComputeToolOptionsSHA256([]string{})
	if err != nil {
		t.Fatal(err)
	}
	env, err := trustverify.ComputeEnvironmentPolicySHA256(trustverify.EnvironmentPolicy{APIVersion: "tplaiter.dev/execution-environment/v1", Variables: []trustverify.EnvironmentVariable{{Name: "LANG", Value: "C"}}, Capabilities: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := buildinfo.Read(bytes.NewReader(f.tool))
	if err != nil {
		t.Fatal(err)
	}
	p := trustverify.Provider{Origin: f.subject.Origin, TemplatePath: f.subject.TemplatePath, Commit: f.subject.Commit, TreeSHA256: f.subject.TreeSHA256, ContractSHA256: f.subject.ContractSHA256}
	actions := make([]trustverify.ActionMaterial, 2)
	for i := range actions {
		actions[i] = trustverify.ActionMaterial{Provider: p, Action: trustverify.Action{ID: "format-" + strings.Repeat("a", 63) + string(rune('1'+i)), Kind: "formatter", Phase: "standalone", Argv: []string{"gofmt"}, ContentClosureSHA256: closure}, Tool: trustverify.Tool{ID: "gofmt", Version: strings.TrimPrefix(info.GoVersion, "go"), BinarySHA256: evidencecas.Digest(f.tool), OptionsSHA256: opts}, WorkingDirectoryScope: trustverify.WorkingDirectoryScope{Root: "project", Path: "."}, EnvironmentPolicySHA256: env, TimeoutMillis: 5000, Migration: trustverify.Migration{Kind: "none"}}
	}
	op := trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: project, Scope: "run", PreimageSHA256: evidencecas.Digest([]byte("preimage")), AnswersSHA256: evidencecas.Digest([]byte("{}")), Subjects: []trustverify.Provider{p}, Actions: actions}
	od, err := trustverify.ComputeOperationInputsSHA256(op)
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]trustverify.ExecutionRequest, 2)
	for i, action := range actions {
		requests[i] = trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: od, ProjectID: project, Scope: "run", Provider: p, Action: action.Action, Tool: action.Tool, WorkingDirectoryScope: action.WorkingDirectoryScope, EnvironmentPolicySHA256: action.EnvironmentPolicySHA256, TimeoutMillis: action.TimeoutMillis, Migration: action.Migration}
		requests[i].RequestSHA256, err = requests[i].ComputeRequestSHA256()
		if err != nil {
			t.Fatal(err)
		}
	}
	return op, requests
}

func (f *t6BFixture) formatterRecord() ([]byte, bool) {
	info, err := buildinfo.Read(bytes.NewReader(f.tool))
	if err != nil {
		return nil, false
	}
	record, err := canonicaljson.Canonical(map[string]any{"apiVersion": "tplaiter.dev/formatter-tool/v1", "adapter": "gofmt-stdin-v1", "toolID": "gofmt", "toolVersion": strings.TrimPrefix(info.GoVersion, "go"), "binarySHA256": evidencecas.Digest(f.tool), "versionEvidence": map[string]any{"kind": "go-buildinfo", "identity": info.GoVersion}, "nativeEnvelope": "darwin-arm64-dyld-libsystem-libresolv-v1"})
	return record, err == nil
}

func (f *t6BFixture) persistentApproval(t *testing.T, r trustverify.ExecutionRequest) trustverify.ApprovalRefs {
	t.Helper()
	a := trustverify.ExecutionApproval{APIVersion: trustverify.ExecutionApprovalAPIVersion, Kind: "persistent-signed", RequestSHA256: r.RequestSHA256, ProfileBindingSHA256: r.ProfileBindingSHA256, OperationInputsSHA256: r.OperationInputsSHA256, ProjectID: r.ProjectID, Scope: r.Scope, ApproverID: f.policy.Approvers[0].ID, IdentityClass: f.policy.Approvers[0].IdentityClass, ExecutionPolicySHA256: f.policy.PolicySHA256, Validity: trustverify.Validity{NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}, KeyFingerprint: f.policy.Approvers[0].KeyFingerprint}
	var err error
	if a.GrantSHA256, err = a.ComputeGrantSHA256(); err != nil {
		t.Fatal(err)
	}
	grant, _ := hex.DecodeString(a.GrantSHA256[7:])
	sig := []byte(bootstrap.EncodeSignature(ed25519.Sign(f.approver, grant)))
	a.SignatureCAS = evidencecas.Digest(sig)
	raw := t6BJSON(t, a)
	t6BWriteCAS(t, f.evidence, a.SignatureCAS, sig)
	approval := evidencecas.Digest(raw)
	t6BWriteCAS(t, f.evidence, approval, raw)
	return trustverify.ApprovalRefs{Kind: "persistent-signed", ApprovalCAS: approval}
}

type t6BTreeEntry struct{ mode, name, oid string }

func t6BTree(add func(string, []byte) string, entries []t6BTreeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	var raw []byte
	for _, e := range entries {
		id, _ := hex.DecodeString(e.oid)
		raw = append(raw, []byte(e.mode+" "+e.name+"\x00")...)
		raw = append(raw, id...)
	}
	return add("tree", raw)
}

func t6BItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func t6BJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func t6BPin(path string, raw []byte) trustload.FilePin {
	return trustload.FilePin{Path: path, SHA256: evidencecas.Digest(raw)}
}

func t6BWriteCAS(t *testing.T, root, digest string, raw []byte) {
	t.Helper()
	x := strings.TrimPrefix(digest, "sha256:")
	dir := filepath.Join(root, "sha256", x[:2])
	if e := os.MkdirAll(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, x[2:]), raw, 0o600); e != nil {
		t.Fatal(e)
	}
}

func t6BPublisherEvidence(t *testing.T, store map[string][]byte, key ed25519.PrivateKey, s trustverify.Subject) trustverify.EvidenceRefs {
	t.Helper()
	put := func(b []byte) string { d := evidencecas.Digest(b); store[d] = append([]byte(nil), b...); return d }
	statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: "https://example.test/policy", Issuer: "publisher-1", Predicate: "https://example.test/predicate", Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}
	raw := t6BJSON(t, statement)
	d, e := bootstrap.DomainDigest(bootstrap.PublisherStatementAPIVersion, statement)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := hex.DecodeString(d[7:])
	return trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: put(raw), SignatureCAS: put([]byte(bootstrap.EncodeSignature(ed25519.Sign(key, hash)))), KeyFingerprint: bootstrap.Fingerprint(key.Public().(ed25519.PublicKey))}
}
