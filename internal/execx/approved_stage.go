//go:build darwin || linux

package execx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	maxApprovedStdout = 1 << 20
	maxGofmtStdout    = 16 << 20
	maxApprovedStderr = 64 << 10
)

var errApprovedOverflow = errors.New("approved output limit")

// Test-only package-private seams let the owned platform tests observe failure
// handling after the real material/recheck boundary. They create no exported
// runner, permit, path, or callback capability.
type (
	approvedHookKey struct{}
	approvedHooks   struct {
		start  func(*exec.Cmd) error
		close  func() error
		stdout func([]byte)
	}
)

func withApprovedHooks(ctx context.Context, h approvedHooks) context.Context {
	return context.WithValue(ctx, approvedHookKey{}, h)
}

func approvedHooksFor(ctx context.Context) approvedHooks {
	h, _ := ctx.Value(approvedHookKey{}).(approvedHooks)
	return h
}

func executeApproved(ctx context.Context, scratch string, m trustverify.StagedMaterial) (_ []byte, retErr error) {
	formatter := validGofmtMaterial(m)
	if ctx == nil || (!validApprovedMaterial(m) && !formatter) || (formatter && !validGofmtNative(m.ToolBytes)) || (!formatter && !validNativeTool(m.ToolBytes)) {
		return nil, &ExecutionError{"TRUST_EXECUTION_MATERIAL_UNAVAILABLE"}
	}
	hooks := approvedHooksFor(ctx)
	s, err := newApprovedStage(scratch, m, hooks.close)
	if err != nil {
		return nil, &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	defer func() {
		if err := s.Close(); err != nil && retErr == nil {
			retErr = &ExecutionError{"TRUST_STAGE_FAILED"}
		}
	}()
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Request.TimeoutMillis)*time.Millisecond)
	defer cancel()
	cmd := exec.Command(s.toolPath, m.Request.Action.Argv[1:]...) //nolint:gosec,noctx // tool path and argv come from the verified execution approval; runCtx cancellation kills the process group below
	cmd.Dir = s.cwdPath
	cmd.Env = []string{"LANG=C"}
	inputIndex := 0
	if formatter {
		inputIndex, _ = gofmtInputIndex(m)
	}
	cmd.Stdin = bytes.NewReader(m.ContentBytes[inputIndex])
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, serr limitedBuffer
	out.n, serr.n, out.observe = maxApprovedStdout, maxApprovedStderr, hooks.stdout
	if formatter {
		out.n = maxGofmtStdout
	}
	// Cmd-owned writers make Wait coordinate its internal pipe copy goroutines;
	// external StdoutPipe readers would race Wait's pipe closure.
	cmd.Stdout, cmd.Stderr = &out, &serr
	if hooks.start != nil {
		err = hooks.start(cmd)
	} else {
		err = cmd.Start()
	}
	if err != nil {
		return nil, &ExecutionError{"TRUST_EXECUTION_FAILED"}
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	overflow, stopOverflow := outputOverflow(&out, &serr)
	defer stopOverflow()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-runCtx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-waitDone
	case <-overflow:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		waitErr = <-waitDone
	}
	if runCtx.Err() != nil || waitErr != nil || out.overflowed() || serr.overflowed() {
		return nil, &ExecutionError{"TRUST_EXECUTION_FAILED"}
	}
	return append([]byte(nil), out.b...), nil
}

func validApprovedMaterial(m trustverify.StagedMaterial) bool {
	return len(m.ToolBytes) > 0 && len(m.ToolBytes) <= 16<<20 && len(m.Content) == 1 && len(m.ContentBytes) == 1 && m.Content[0].Root == "provider" && m.Content[0].Path == ".tplaiter-execution/stdin" && m.Content[0].Mode == "100644" && len(m.Request.Action.Argv) == 1 && m.Request.Action.Argv[0] == "native-snapshot-tool-v1" && len(m.ToolOptions) == 0 && !m.Environment.Inherit && len(m.Environment.Variables) == 1 && m.Environment.Variables[0].Name == "LANG" && m.Environment.Variables[0].Value == "C" && len(m.Environment.Capabilities) == 0
}

// validGofmtMaterial is the finite formatter branch of the same opaque
// runner. It is deliberately not a general command capability.
func validGofmtMaterial(m trustverify.StagedMaterial) bool {
	inputIndex, ok := gofmtInputIndex(m)
	return ok && len(m.ToolBytes) > 0 && len(m.ToolBytes) <= 16<<20 && len(m.ContentBytes[inputIndex]) <= maxGofmtStdout && m.Request.Action.Kind == "formatter" && m.Request.Action.Phase == "standalone" && !m.Request.Action.Shell && len(m.Request.Action.Argv) == 1 && m.Request.Action.Argv[0] == "gofmt" && m.Request.Tool.ID == "gofmt" && len(m.ToolOptions) == 0 && m.Request.WorkingDirectoryScope == (trustverify.WorkingDirectoryScope{Root: "project", Path: "."}) && m.Request.TimeoutMillis > 0 && m.Request.TimeoutMillis <= 120000 && !m.Environment.Inherit && len(m.Environment.Variables) == 1 && m.Environment.Variables[0].Name == "LANG" && m.Environment.Variables[0].Value == "C" && len(m.Environment.Capabilities) == 0
}

func gofmtInputIndex(m trustverify.StagedMaterial) (int, bool) {
	if (len(m.Content) != 3 && len(m.Content) != 4) || len(m.ContentBytes) != len(m.Content) {
		return 0, false
	}
	input := -1
	seen := map[string]bool{}
	for i, entry := range m.Content {
		if entry.Root != "project" || entry.Mode != "100644" || seen[entry.Path] {
			return 0, false
		}
		seen[entry.Path] = true
		switch entry.Path {
		case "formatter/plan.json", "formatter/tool.json":
		case "formatter/context.json":
			if len(m.Content) != 4 {
				return 0, false
			}
			if _, err := operationtrust.ParseManagedFormatterContext(m.ContentBytes[i]); err != nil {
				return 0, false
			}
		default:
			folded := strings.ToLower(entry.Path)
			if input >= 0 || entry.Path == "" || folded == "formatter" || strings.HasPrefix(folded, "formatter/") || folded == "native-tool" || folded == ".tplaiter-execution" || strings.HasPrefix(folded, ".tplaiter-execution/") {
				return 0, false
			}
			input = i
		}
	}
	return input, input >= 0 && seen["formatter/plan.json"] && seen["formatter/tool.json"] && (len(m.Content) == 3 || seen["formatter/context.json"])
}

type limitedBuffer struct {
	mu      sync.Mutex
	b       []byte
	n       int
	over    bool
	observe func([]byte)
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n == 0 {
		w.n = maxApprovedStdout
	}
	if len(w.b)+len(p) > w.n {
		r := w.n - len(w.b)
		if r > 0 {
			w.b = append(w.b, p[:r]...)
		}
		w.over = true
		return len(p), errApprovedOverflow
	}
	w.b = append(w.b, p...)
	if w.observe != nil {
		w.observe(append([]byte(nil), p...))
	}
	return len(p), nil
}

func outputOverflow(a, b *limitedBuffer) (<-chan struct{}, func()) {
	ch, stop := make(chan struct{}), make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			if a.overflowed() || b.overflowed() {
				close(ch)
				return
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	var once sync.Once
	return ch, func() { once.Do(func() { close(stop) }) }
}
func (w *limitedBuffer) overflowed() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.over }

type approvedStage struct {
	root, dir, tool, cwd    int
	name, toolPath, cwdPath string
	closeHook               func() error
	projected, projectDirs  []string
}

func newApprovedStage(root string, m trustverify.StagedMaterial, closeHook func() error) (*approvedStage, error) {
	rootFD, e := openApprovedRoot(root)
	if e != nil {
		return nil, e
	}
	s := &approvedStage{root: rootFD, dir: -1, tool: -1, cwd: -1, closeHook: closeHook}
	fail := func(e error) (*approvedStage, error) { _ = s.Close(); return nil, e }
	created := false
	for i := 0; i < 32; i++ {
		var n [16]byte
		if _, e = rand.Read(n[:]); e != nil {
			return fail(e)
		}
		s.name = ".tplaiter-approved-" + hex.EncodeToString(n[:])
		if e = unix.Mkdirat(s.root, s.name, 0o700); errors.Is(e, unix.EEXIST) {
			continue
		}
		if e != nil {
			return fail(e)
		}
		created = true
		break
	}
	if !created {
		return fail(errors.New("stage exhausted"))
	}
	if s.dir < 0 {
		s.dir, e = unix.Openat(s.root, s.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return fail(fmt.Errorf("stage open: %w", e))
		}
	}
	var st unix.Stat_t
	if e = unix.Fstat(s.dir, &st); e != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o077 != 0 {
		return fail(errors.New("unsafe stage"))
	}
	s.tool, e = writeApprovedFile(s.dir, "native-tool", m.ToolBytes, 0o500)
	if e != nil {
		return fail(fmt.Errorf("stage tool: %w", e))
	}
	if e = unix.Close(s.tool); e != nil {
		return fail(fmt.Errorf("stage tool close: %w", e))
	}
	s.tool = -1
	s.tool, e = unix.Openat(s.dir, "native-tool", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail(fmt.Errorf("stage tool verify open: %w", e))
	}
	if e = verifyApprovedTool(s.tool, m.ToolBytes, m.Request.Tool.BinarySHA256); e != nil {
		return fail(fmt.Errorf("stage tool verify: %w", e))
	}
	if m.Request.Action.Kind == "formatter" {
		for i, entry := range m.Content {
			if e = s.project(entry.Path, m.ContentBytes[i], entry.Mode); e != nil {
				return fail(fmt.Errorf("stage formatter content: %w", e))
			}
		}
	}
	if e = unix.Mkdirat(s.dir, ".tplaiter-execution", 0o700); e != nil {
		return fail(fmt.Errorf("stage cwd mkdir: %w", e))
	}
	s.cwd, e = unix.Openat(s.dir, ".tplaiter-execution", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return fail(fmt.Errorf("stage cwd open: %w", e))
	}
	inputIndex := 0
	if m.Request.Action.Kind == "formatter" {
		var ok bool
		if inputIndex, ok = gofmtInputIndex(m); !ok {
			return fail(errors.New("invalid formatter content"))
		}
	}
	stdinFD, e := writeApprovedFile(s.cwd, "stdin", m.ContentBytes[inputIndex], 0o400)
	if e != nil {
		return fail(fmt.Errorf("stage stdin: %w", e))
	}
	if e = unix.Close(stdinFD); e != nil {
		return fail(fmt.Errorf("stage stdin close: %w", e))
	}
	stagePath, e := approvedPathForFD(s.dir)
	if e != nil {
		return fail(fmt.Errorf("stage dir path: %w", e))
	}
	s.toolPath = stagePath + "/native-tool"
	s.cwdPath, e = approvedPathForFD(s.cwd)
	if e != nil {
		return fail(fmt.Errorf("stage cwd path: %w", e))
	}
	if m.Request.Action.Kind == "formatter" {
		s.cwdPath = stagePath
	}
	return s, nil
}

func (s *approvedStage) project(path string, data []byte, mode string) error {
	parts := strings.Split(path, "/")
	if len(parts) == 0 || len(parts) > 64 {
		return errors.New("invalid projection path")
	}
	dir := s.dir
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("invalid projection path")
		}
		if i == len(parts)-1 {
			perm := uint32(0o400)
			if mode == "100755" {
				perm = 0o500
			}
			fd, err := writeApprovedFile(dir, part, data, perm)
			if dir != s.dir {
				_ = unix.Close(dir)
			}
			if err != nil {
				return err
			}
			if err = unix.Close(fd); err != nil {
				return err
			}
			s.projected = append(s.projected, path)
			return nil
		}
		if err := unix.Mkdirat(dir, part, 0o700); err != nil && err != unix.EEXIST {
			if dir != s.dir {
				_ = unix.Close(dir)
			}
			return err
		}
		next, err := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if dir != s.dir {
			_ = unix.Close(dir)
		}
		if err != nil {
			return err
		}
		dir = next
		prefix := strings.Join(parts[:i+1], "/")
		seen := false
		for _, old := range s.projectDirs {
			if old == prefix {
				seen = true
				break
			}
		}
		if !seen {
			s.projectDirs = append(s.projectDirs, prefix)
		}
	}
	return errors.New("invalid projection path")
}

func openApprovedRoot(root string) (int, error) {
	if root == "" || root[0] != '/' {
		return -1, errors.New("invalid root")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(canonical) {
		return -1, errors.New("invalid root")
	}
	root = canonical
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, p := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if p == "" || p == "." || p == ".." {
			_ = unix.Close(fd)
			return -1, errors.New("invalid root")
		}
		next, x := unix.Openat(fd, p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if x != nil {
			return -1, x
		}
		fd = next
	}
	return fd, nil
}

func writeApprovedFile(dir int, name string, data []byte, mode uint32) (int, error) {
	fd, e := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if e != nil {
		return -1, e
	}
	for len(data) > 0 {
		n, x := unix.Write(fd, data)
		if x != nil {
			_ = unix.Close(fd)
			return -1, x
		}
		data = data[n:]
	}
	if e = unix.Fsync(fd); e != nil {
		_ = unix.Close(fd)
		return -1, e
	}
	return fd, nil
}

func verifyApprovedTool(fd int, want []byte, requestDigest string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o777 != 0o500 || st.Size < 1 || st.Size > 16<<20 || int64(len(want)) != st.Size {
		return errors.New("unsafe staged tool")
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	for off := int64(0); off < st.Size; {
		n, err := unix.Pread(fd, buf, off)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			off += int64(n)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short staged tool")
		}
	}
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	wantHash := sha256.Sum256(want)
	if digest != requestDigest || digest != "sha256:"+hex.EncodeToString(wantHash[:]) {
		return errors.New("staged tool digest")
	}
	return nil
}

func (s *approvedStage) Close() error {
	if s == nil {
		return nil
	}
	var es []error
	if s.dir >= 0 {
		for i := len(s.projected) - 1; i >= 0; i-- {
			if e := unix.Unlinkat(s.dir, s.projected[i], 0); e != nil && e != unix.ENOENT {
				es = append(es, e)
			}
		}
		for i := len(s.projectDirs) - 1; i >= 0; i-- {
			if e := unix.Unlinkat(s.dir, s.projectDirs[i], unix.AT_REMOVEDIR); e != nil && e != unix.ENOENT {
				es = append(es, e)
			}
		}
	}
	if s.cwd >= 0 {
		if e := unix.Unlinkat(s.cwd, "stdin", 0); e != nil && e != unix.ENOENT {
			es = append(es, e)
		}
	}
	if s.dir >= 0 {
		if e := unix.Unlinkat(s.dir, "native-tool", 0); e != nil && e != unix.ENOENT {
			es = append(es, e)
		}
		if e := unix.Unlinkat(s.dir, ".tplaiter-execution", unix.AT_REMOVEDIR); e != nil && e != unix.ENOENT {
			es = append(es, e)
		}
	}
	if s.root >= 0 && s.name != "" {
		if e := unix.Unlinkat(s.root, s.name, unix.AT_REMOVEDIR); e != nil && e != unix.ENOENT {
			es = append(es, e)
		}
	}
	for _, fd := range []int{s.tool, s.cwd, s.dir, s.root} {
		if fd >= 0 {
			if e := unix.Close(fd); e != nil {
				es = append(es, e)
			}
		}
	}
	s.tool, s.cwd, s.dir, s.root = -1, -1, -1, -1
	if s.closeHook != nil {
		es = append(es, s.closeHook())
	}
	return errors.Join(es...)
}
