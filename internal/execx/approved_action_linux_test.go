//go:build linux

package execx

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"

	"golang.org/x/sys/unix"
)

// Evaluate actual generated classic BPF; this does not install a kernel
// filter or supply native/runtime authority.
func evalActionBPF(t *testing.T, code []unix.SockFilter, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[:], nr)
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+8*i:], a)
	}
	var a uint32
	for pc, steps := 0, 0; pc < len(code) && steps < 10000; pc, steps = pc+1, steps+1 {
		i := code[pc]
		switch i.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if i.K > 60 {
				t.Fatal("invalid load")
			}
			a = binary.LittleEndian.Uint32(data[i.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == i.K {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JGT | unix.BPF_K:
			if a > i.K {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(i.K)
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			a &= i.K
		case unix.BPF_RET | unix.BPF_K:
			return i.K
		default:
			t.Fatalf("unsupported instruction %#x", i.Code)
		}
	}
	t.Fatal("filter did not terminate")
	return 0
}

func TestActionLinuxClosedSyscallArguments(t *testing.T) {
	filters, e := linuxActionFilters(actionFDTable{last: 8, pollers: []int{100}}, 1234)
	if e != nil {
		t.Fatal(e)
	}
	tests := []struct {
		name  string
		nr    uint32
		args  [6]uint64
		allow bool
	}{
		{"selected-read", unix.SYS_READ, [6]uint64{7}, true},
		{"foreign-read", unix.SYS_READ, [6]uint64{9}, false},
		{"FD-high-word", unix.SYS_READ, [6]uint64{1<<32 | 7}, false},
		{"stdout", unix.SYS_WRITE, [6]uint64{1}, true},
		{"input-write", unix.SYS_WRITE, [6]uint64{7}, false},
		{"openat", unix.SYS_OPENAT, [6]uint64{}, false},
		{"network", unix.SYS_SOCKET, [6]uint64{}, false},
		{"exec-path", unix.SYS_EXECVE, [6]uint64{}, false},
		{"exec-held", unix.SYS_EXECVEAT, [6]uint64{5, 0, 0, 0, unix.AT_EMPTY_PATH}, true},
		{"exec-other-fd", unix.SYS_EXECVEAT, [6]uint64{7, 0, 0, 0, unix.AT_EMPTY_PATH}, false},
		{"process-clone", unix.SYS_CLONE, [6]uint64{17}, false},
		{"thread-clone", unix.SYS_CLONE, [6]uint64{0x50f00}, true},
		{"writable-executable-map", unix.SYS_MPROTECT, [6]uint64{0, 0, unix.PROT_WRITE | unix.PROT_EXEC}, false},
		{"signal-other-process", unix.SYS_TGKILL, [6]uint64{1235, 1, 23}, false},
		{"signal-own-thread", unix.SYS_TGKILL, [6]uint64{1234, 1234, 23}, true},
		{"resource-mutation", unix.SYS_PRLIMIT64, [6]uint64{1234, 0, 1}, false},
		{"dup", unix.SYS_DUP, [6]uint64{}, false},
		{"stdout-query", unix.SYS_FCNTL, [6]uint64{1, unix.F_GETFD}, true},
		{"stdout-mutation", unix.SYS_FCNTL, [6]uint64{1, unix.F_SETFL}, false},
		{"foreign-query", unix.SYS_FCNTL, [6]uint64{9, unix.F_GETFD}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalActionBPF(t, filters, tt.nr, tt.args) == unix.SECCOMP_RET_ALLOW
			if got != tt.allow {
				t.Fatalf("allow %v want %v", got, tt.allow)
			}
		})
	}
}

// Query only the real kernel. No filter, native permit or installed grant is
// fabricated, and kernel or container-policy refusal remains visible.
func TestActionLinuxKernelAdmissionBoundary(t *testing.T) {
	if os.Getenv("TPLAITER_ACTION_KERNEL_COUNTER") != "1" && os.Getenv("TPLAITER_ACTION_TSYNC_COUNTER") != "1" {
		t.Skip("explicit isolated cached-kernel counter only")
	}
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	t.Logf("actual kernel Landlock ABI=%d errno=%d; required ABI8+TSYNC", abi, errno)
	if errno != 0 || abi < 8 {
		t.Fatalf("current kernel cannot admit approved native action profile")
	}
	if os.Getenv("TPLAITER_ACTION_TSYNC_COUNTER") == "1" {
		// Docker entry is a mount of this test image only, not any source carrier.
		f, e := os.Open("/proof")
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		e = applyLinuxActionLandlock(int(f.Fd()))
		if errors.Is(e, unix.EINVAL) {
			t.Log("native boundary: actual ABI8 rejects required Landlock TSYNC flag8 with EINVAL; no weaker fallback")
			return
		}
		if e != nil {
			t.Fatalf("actual Landlock TSYNC refused: %v", e)
		}
		t.Log("native Landlock TSYNC applied successfully; not signed installed action authority")
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, exe, "-test.run=^TestActionLinuxKernelAdmissionBoundary$", "-test.v")
	c.Env = []string{"TPLAITER_ACTION_TSYNC_COUNTER=1"}
	out, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("native TSYNC counter: %v %s", e, out)
	}
	t.Log(string(out))
}

// Only this test executable has these entry tokens. Production CLI never
// enters confinement from this synthetic seam or grants from its result.
func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case "--action-kernel-counter-bootstrap":
		b, e := os.ReadFile("/proof")
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(126)
		}
		l, e := kernelCounterLaunch(b)
		if e == nil {
			e = verifyActionInherited(l)
		}
		if e == nil {
			e = enterReadonlyAction(context.Background(), l)
		}
		fmt.Fprintln(os.Stderr, "actual guard refused:", e)
		os.Exit(126)
	case "--action-kernel-counter-tool":
		unix.Write(1, []byte("tool-entry\n"))
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if e != nil || !bytes.Equal(b, []byte("selected finite stdin\n")) {
			fmt.Fprintln(os.Stderr, "stdin mismatch", e)
			os.Exit(21)
		}
		f := os.NewFile(7, "selected-counter-input")
		input, e := io.ReadAll(io.LimitReader(f, 1025))
		if e != nil || !bytes.Equal(input, []byte("selected finite input\n")) {
			fmt.Fprintln(os.Stderr, "selected input mismatch", e)
			os.Exit(22)
		}
		for _, probe := range []func() error{
			func() error {
				fd, e := unix.Open("/synthetic-counter-outside", unix.O_RDONLY, 0)
				if e == nil {
					unix.Close(fd)
				}
				return e
			},
			func() error {
				fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
				if e == nil {
					unix.Close(fd)
				}
				return e
			},
			func() error {
				fd, e := unix.Dup(7)
				if e == nil {
					unix.Close(fd)
				}
				return e
			},
			func() error { _, e := unix.Write(7, []byte("forbidden")); return e },
			func() error { _, _, e := unix.RawSyscall(unix.SYS_EXECVE, 0, 0, 0); return e },
		} {
			if e = probe(); !errors.Is(e, unix.EPERM) {
				fmt.Fprintln(os.Stderr, "unexpected deny result", e)
				os.Exit(23)
			}
		}
		// A bounded busy interval makes the original tool inode visible to parent.
		until := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(until) {
		}
		fmt.Fprintf(os.Stdout, "useful stdin=%d input=%d; denied foreign-read/network/dup/input-write/path-exec\n", len(b), len(input))
		os.Exit(0)
	}
}

func kernelCounterLaunch(tool []byte) (actionLaunch, error) {
	d := evidencecas.Digest([]byte("synthetic mechanism counter, never authority"))
	req := trustverify.ExecutionRequest{Scope: "run", RequestSHA256: d, OperationInputsSHA256: d, TimeoutMillis: 5000}
	req.Action.Kind = "command"
	req.Action.Phase = "standalone"
	req.Action.Argv = []string{"counter", "--action-kernel-counter-tool"}
	req.Action.ContentClosureSHA256 = d
	req.Tool.BinarySHA256 = evidencecas.Digest(tool)
	data := []byte("selected finite input\n")
	return makeActionLaunch(trustverify.StagedMaterial{Request: req, ToolBytes: tool}, operationtrust.ActionProjection{Profile: "linux-static-fd-go127-poll/v1", Stdin: []byte("selected finite stdin\n"), Files: []operationtrust.ActionInputFile{{Root: "provider", Path: "data.txt", Mode: "100644", SHA256: evidencecas.Digest(data), Bytes: data}}}, ActionBootstrapControl{RequestSHA256: d, SessionSHA256: d})
}

func TestActionLinuxActualKernelUsefulReadonly(t *testing.T) {
	if os.Getenv("TPLAITER_ACTION_KERNEL_COUNTER") != "1" {
		t.Skip("explicit isolated cached-kernel counter only")
	}
	b, e := os.ReadFile("/proof")
	if e != nil {
		t.Fatal(e)
	}
	l, e := kernelCounterLaunch(b)
	if e != nil {
		t.Fatal(e)
	}
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	stage, e := newActionStage(root, l)
	if e != nil {
		t.Fatal(e)
	}
	defer stage.close()
	unused, unusedWriter, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer unused.Close()
	defer unusedWriter.Close()
	reader, status, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	defer status.Close()
	var statusBytes []byte
	statusDone := make(chan struct{})
	go func() { defer close(statusDone); statusBytes, _ = io.ReadAll(io.LimitReader(reader, 4097)) }()
	cmd := exec.Command("/proof", "--action-kernel-counter-bootstrap")
	cmd.Dir = stage.path
	cmd.Env = []string{"LANG=C"}
	cmd.Stdin = stage.files[len(stage.files)-1]
	cmd.ExtraFiles = []*os.File{unused, status, stage.files[0], stage.files[1], stage.files[2]}
	toolInfo := stage.infos[0]
	witness := func() (bool, error) {
		if cmd.Process == nil {
			return false, nil
		}
		f, e := os.Open(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
		if os.IsNotExist(e) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		defer f.Close()
		i, e := f.Stat()
		return e == nil && os.SameFile(i, toolInfo), e
	}
	result, e := runActionProcess(context.Background(), cmd, l, func() { status.Close() }, witness, func() error { <-statusDone; return parseActionStatus(statusBytes, l) })
	result.ImplementationSHA256 = evidencecas.Digest(b)
	if e != nil {
		t.Fatalf("native useful guard failed: %v launched=%s disposition=%s child=%v signal=%v status-bytes=%d stdout=%s stderr=%s", e, result.Launched, result.Disposition, result.ChildExitCode, cmd.ProcessState, len(statusBytes), result.Stdout, result.Stderr)
	}
	if result.Launched != "yes" || result.ChildExitCode == nil || *result.ChildExitCode != 0 || !bytes.Contains(result.Stdout, []byte("useful stdin=")) {
		t.Fatalf("missing actual mapped-tool success: launched=%s child=%v stdout=%q stderr=%q", result.Launched, func() any {
			if result.ChildExitCode == nil {
				return nil
			}
			return *result.ChildExitCode
		}(), result.Stdout, result.Stderr)
	}
	if e = stage.check(); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual native guard: %s; launched=%s cleanup=%s output-complete=%t; mechanism proof, no signed installed authority", result.Stdout, result.Launched, result.Cleanup, result.OutputComplete)
}

func TestActionLinuxPollPredicates(t *testing.T) {
	filters, e := linuxActionFilters(actionFDTable{last: 8, pollers: []int{100}}, 1234, "linux-static-fd-go127-poll/v1")
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name  string
		nr    uint32
		args  [6]uint64
		allow bool
	}{
		{"epoll-cloexec", unix.SYS_EPOLL_CREATE1, [6]uint64{unix.EPOLL_CLOEXEC}, true},
		{"epoll-no-cloexec", unix.SYS_EPOLL_CREATE1, [6]uint64{}, false},
		{"epoll-flags-highword", unix.SYS_EPOLL_CREATE1, [6]uint64{1<<32 | unix.EPOLL_CLOEXEC}, false},
		{"eventfd-closed", unix.SYS_EVENTFD2, [6]uint64{0, unix.EFD_CLOEXEC | unix.EFD_NONBLOCK}, true},
		{"eventfd-nonzero", unix.SYS_EVENTFD2, [6]uint64{1, unix.EFD_CLOEXEC | unix.EFD_NONBLOCK}, false},
		{"eventfd-flags", unix.SYS_EVENTFD2, [6]uint64{0, unix.EFD_CLOEXEC}, false},
		{"register-event", unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_ADD, 4}, true},
		{"register-selected", unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_ADD, 7}, true},
		{"register-foreign", unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_ADD, 9}, false},
		{"register-tool", unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_ADD, 5}, false},
		{"register-mod", unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_MOD, 4}, false},
		{"register-foreign-epfd", unix.SYS_EPOLL_CTL, [6]uint64{9, unix.EPOLL_CTL_ADD, 4}, false},
		{"wait", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 128, 0, 0, 0}, true},
		{"wait-indefinite", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 128, ^uint64(0), 0, 0}, true},
		{"wait-negative2", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 128, ^uint64(1), 0, 0}, false},
		{"wait-zero", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 0, 0, 0, 0}, false},
		{"wait-overflow", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 129, 0, 0, 0}, false},
		{"wait-mask", unix.SYS_EPOLL_PWAIT, [6]uint64{3, 0, 128, 0, 1, 0}, false},
		{"event-read8", unix.SYS_READ, [6]uint64{4, 0, 8}, true},
		{"event-read9", unix.SYS_READ, [6]uint64{4, 0, 9}, false},
		{"epoll-read", unix.SYS_READ, [6]uint64{3, 0, 8}, false},
		{"selected-read", unix.SYS_READ, [6]uint64{7, 0, 8}, true},
		{"event-write8", unix.SYS_WRITE, [6]uint64{4, 0, 8}, true},
		{"status-write111", unix.SYS_WRITE, [6]uint64{4, 0, 111}, true},
		{"event-write9", unix.SYS_WRITE, [6]uint64{4, 0, 9}, false},
		{"event-write-highword", unix.SYS_WRITE, [6]uint64{4, 0, 1<<32 | 8}, false},
		{"event-writev", unix.SYS_WRITEV, [6]uint64{4, 0, 1}, false},
		{"selected-write", unix.SYS_WRITE, [6]uint64{7, 0, 8}, false},
		{"event-mutation", unix.SYS_FCNTL, [6]uint64{4, unix.F_SETFD}, false},
		{"socket", unix.SYS_SOCKET, [6]uint64{}, false},
		{"dup", unix.SYS_DUP, [6]uint64{4}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evalActionBPF(t, filters, c.nr, c.args) == unix.SECCOMP_RET_ALLOW; got != c.allow {
				t.Fatalf("got allow=%v want=%v", got, c.allow)
			}
		})
	}
	old, e := linuxActionFilters(actionFDTable{last: 8}, 1234, "linux-static-fd-go127/v1")
	if e != nil {
		t.Fatal(e)
	}
	if evalActionBPF(t, old, unix.SYS_EPOLL_CREATE1, [6]uint64{unix.EPOLL_CLOEXEC}) == unix.SECCOMP_RET_ALLOW {
		t.Fatal("v1 widened")
	}
}
