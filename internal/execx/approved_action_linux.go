//go:build linux

package execx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"golang.org/x/sys/unix"
)

func actionReadFlags() int           { return os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK }
func actionControlNonblock() error   { return unix.SetNonblock(3, true) }
func prepareActionChild(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killActionChild(c *exec.Cmd) {
	if c.Process != nil {
		unix.Kill(-c.Process.Pid, unix.SIGKILL)
		c.Process.Kill()
	}
}

func actionProcessSignal(s *os.ProcessState) int {
	x, ok := s.Sys().(syscall.WaitStatus)
	if ok && x.Signaled() {
		return int(x.Signal())
	}
	return 0
}

func executeReadonlyAction(ctx context.Context, scratch string, l actionLaunch) (result ActionProcessResult, err error) {
	if !linuxActionProfile(l.projection.Profile) || !validLinuxStaticELF(l.staged.ToolBytes) {
		return result, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	s, e := newActionStage(scratch, l)
	if e != nil {
		return result, e
	}
	defer func() {
		if e := s.close(); e != nil {
			if result.APIVersion != "" {
				result.Cleanup = "failed"
				result.Disposition = "recovery-required"
			}
			err = errors.Join(err, e)
		}
	}()
	// /proc/self/exe is the held running implementation, never PATH or a
	// caller-provided helper. A replacement pathname cannot select this image.
	self, e := os.Open("/proc/self/exe")
	if e != nil {
		return result, e
	}
	before, e := self.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 128<<20 {
		self.Close()
		return result, &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	defer self.Close()
	if !actionStaticBootstrap(self, before.Size()) {
		return result, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	hash := sha256.New()
	n, e := io.Copy(hash, io.LimitReader(self, 128<<20+1))
	after, se := self.Stat()
	if e != nil || se != nil || n != before.Size() || !actionOriginalStat(before, after) {
		return result, &ExecutionError{"TRUST_STAGE_FAILED"}
	}
	implementation := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	controlReader, controlWriter, e := os.Pipe()
	if e != nil {
		return result, e
	}
	defer controlReader.Close()
	defer controlWriter.Close()
	statusReader, statusWriter, e := os.Pipe()
	if e != nil {
		return result, e
	}
	defer statusReader.Close()
	defer statusWriter.Close()
	control, e := canonicaljson.Canonical(l.control)
	if e != nil || len(control) > 64<<10 {
		return result, &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	controlDone := make(chan error, 1)
	go func() { _, e := controlWriter.Write(control); controlDone <- errors.Join(e, controlWriter.Close()) }()
	defer func() { controlReader.Close(); controlWriter.Close(); <-controlDone }()
	statusDone := make(chan struct{})
	var statusBytes []byte
	var statusErr error
	go func() {
		defer close(statusDone)
		statusBytes, statusErr = io.ReadAll(io.LimitReader(statusReader, 4097))
	}()
	defer func() { statusWriter.Close(); statusReader.Close(); <-statusDone }()
	// Execute the held current running image, not a mutable staged pathname.
	// Linux ETXTBSY protects the currently mapped executable's body. Its FD is
	// retained in the parent and closes at the final confined tool exec.
	bootstrapFD := 7 + len(l.projection.Files)
	c := exec.Command("/proc/self/fd/"+strconv.Itoa(bootstrapFD), l.bootstrapToken)
	c.Dir = s.path
	c.Env = []string{"LANG=C"}
	c.Stdin = s.files[len(s.files)-1]
	c.ExtraFiles = []*os.File{controlReader, statusWriter, s.files[0], s.files[1]}
	c.ExtraFiles = append(c.ExtraFiles, s.files[2:len(s.files)-1]...)
	c.ExtraFiles = append(c.ExtraFiles, self)
	toolInfo := s.infos[0]
	witness := func() (bool, error) {
		if c.Process == nil {
			return false, nil
		}
		f, e := os.Open("/proc/" + strconv.Itoa(c.Process.Pid) + "/exe")
		if errors.Is(e, os.ErrNotExist) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		defer f.Close()
		i, e := f.Stat()
		return e == nil && os.SameFile(i, toolInfo), e
	}
	status := func() error {
		statusWriter.Close()
		<-statusDone
		if statusErr != nil {
			return statusErr
		}
		return parseActionStatus(statusBytes, l)
	}
	if e = s.check(); e != nil {
		return result, e
	}
	result, err = runActionProcess(ctx, c, l, func() { controlReader.Close(); statusWriter.Close() }, witness, status)
	result.ImplementationSHA256 = implementation
	current, ce := self.Stat()
	if ce != nil || !actionOriginalStat(after, current) {
		err = errors.Join(err, &ExecutionError{"TRUST_STAGE_FAILED"})
		result.Disposition = "recovery-required"
	}
	if check := s.check(); check != nil {
		err = errors.Join(err, check)
		result.Disposition = "recovery-required"
	}
	return result, err
}

func reflectLinuxIdentity(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yes := b.Sys().(*syscall.Stat_t)
	return ok && yes && *x == *y && x.Nlink == 1 && x.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) == 0
}

func verifyActionInherited(l actionLaunch) error {
	var st unix.Stat_t
	for _, fd := range []int{1, 2, 4} {
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
			return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
		}
	}
	flags, e := unix.FcntlInt(4, unix.F_GETFL, 0)
	if e != nil || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	if e = unix.SetNonblock(4, true); e != nil {
		return e
	}
	verify := func(fd int, want []byte, mode uint32) error {
		var before, after unix.Stat_t
		if unix.Fstat(fd, &before) != nil || before.Mode != unix.S_IFREG|mode || before.Nlink != 1 || before.Size != int64(len(want)) {
			return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
		}
		b := make([]byte, len(want)+1)
		n, e := unix.Pread(fd, b, 0)
		if e != nil || n != len(want) || !bytes.Equal(want, b[:n]) || unix.Fstat(fd, &after) != nil || !sameActionInheritedStat(before, after) {
			return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
		}
		return nil
	}
	if len(l.projection.Stdin) > 1<<20 {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	if e := verify(0, l.projection.Stdin, 0o400); e != nil {
		return e
	}
	if offset, e := unix.Seek(0, 0, io.SeekCurrent); e != nil || offset != 0 {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	if e := verify(5, l.staged.ToolBytes, 0o500); e != nil {
		return e
	}
	if e := verify(6, l.descriptor, 0o400); e != nil {
		return e
	}
	for i, f := range l.projection.Files {
		if e := verify(7+i, f.Bytes, 0o400); e != nil {
			return e
		}
	}
	return nil
}

func enterReadonlyAction(ctx context.Context, l actionLaunch) error {
	if ctx.Err() != nil || !linuxActionProfile(l.projection.Profile) {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	runtime.LockOSThread()
	// Everything below allocates before the final filter/exec transition.
	argv := make([]*byte, len(l.staged.Request.Action.Argv)+1)
	for i, s := range l.staged.Request.Action.Argv {
		p, e := unix.BytePtrFromString(s)
		if e != nil {
			return e
		}
		argv[i] = p
	}
	env0, e := unix.BytePtrFromString("LANG=C")
	if e != nil {
		return e
	}
	env := []*byte{env0, nil}
	empty := []byte{0}
	table := actionFDTable{last: 6 + len(l.projection.Files)}
	fds, e := os.ReadDir("/proc/self/fd")
	if e != nil || len(fds) > 4096 {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	for _, entry := range fds {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		target, e := os.Readlink("/proc/self/fd/" + entry.Name())
		if e == nil && (target == "anon_inode:[eventpoll]" || target == "anon_inode:[eventfd]") {
			table.pollers = append(table.pollers, fd)
		}
	}
	filters, e := linuxActionFilters(table, unix.Getpid(), l.projection.Profile)
	if e != nil {
		return e
	}
	ready := actionStatus(l, 1, 0)
	execError := actionStatus(l, 2, 0)
	for resource, limit := range map[int]uint64{unix.RLIMIT_CPU: 5, unix.RLIMIT_FSIZE: 0, unix.RLIMIT_CORE: 0, unix.RLIMIT_STACK: 8 << 20, unix.RLIMIT_AS: 2 << 30, unix.RLIMIT_NOFILE: 256} {
		var current unix.Rlimit
		if e = unix.Getrlimit(resource, &current); e != nil {
			return e
		}
		if current.Cur < limit {
			limit = current.Cur
		}
		if resource == unix.RLIMIT_NOFILE && limit < uint64(table.last+32) {
			return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
		}
		if e = unix.Setrlimit(resource, &unix.Rlimit{Cur: limit, Max: limit}); e != nil {
			return e
		}
	}
	if e = unix.CloseRange(3, ^uint(0)>>32, unix.CLOSE_RANGE_CLOEXEC); e != nil {
		return e
	}
	for fd := 6; fd <= table.last; fd++ {
		if _, e = unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); e != nil {
			return e
		}
	}
	if e = actionExecDescriptorClosure(table.last); e != nil {
		return e
	}
	if e = verifyActionInherited(l); e != nil {
		return e
	}
	if e = applyLinuxActionLandlock(5); e != nil {
		return e
	}
	if e = applyLinuxActionSeccomp(filters); e != nil {
		return e
	}
	// No allocation, logging, deferred cleanup or return to Cobra after filtering.
	written, _, errno := unix.RawSyscall(unix.SYS_WRITE, 4, uintptr(unsafe.Pointer(&ready[0])), uintptr(len(ready)))
	if errno != 0 || written != uintptr(len(ready)) {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 126, 0, 0)
		for {
		}
	}
	_, _, errno = unix.RawSyscall6(unix.SYS_EXECVEAT, 5, uintptr(unsafe.Pointer(&empty[0])), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])), unix.AT_EMPTY_PATH, 0)
	binary.LittleEndian.PutUint32(execError[107:], uint32(errno))
	unix.RawSyscall(unix.SYS_WRITE, 4, uintptr(unsafe.Pointer(&execError[0])), uintptr(len(execError)))
	runtime.KeepAlive(argv)
	runtime.KeepAlive(env)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(filters)
	unix.RawSyscall(unix.SYS_EXIT_GROUP, 126, 0, 0)
	for {
	}
}

func applyLinuxActionLandlock(toolFD int) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 8 {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	var rules [24]byte
	binary.LittleEndian.PutUint64(rules[0:], 0xffff)
	binary.LittleEndian.PutUint64(rules[16:], 3)
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&rules[0])), 24, 0)
	runtime.KeepAlive(rules)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))
	var rule [12]byte
	binary.LittleEndian.PutUint64(rule[:], 5)
	binary.LittleEndian.PutUint32(rule[8:], uint32(toolFD))
	_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, 1, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
	runtime.KeepAlive(rule)
	if errno != 0 {
		return errno
	}
	if e := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 8, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func applyLinuxActionSeccomp(filters []unix.SockFilter) error {
	if len(filters) == 0 || len(filters) > 4096 {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	p := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	n, _, errno := unix.RawSyscall6(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&p)), 0, 0, 0)
	runtime.KeepAlive(p)
	runtime.KeepAlive(filters)
	if errno != 0 {
		return errno
	}
	if n != 0 {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	return nil
}

func actionStatus(l actionLaunch, tag byte, errno uint32) []byte {
	b := make([]byte, 111)
	copy(b, []byte{'A', 'C', 'B', 'T', 'V', '1', 0, 0})
	b[8] = tag
	binary.LittleEndian.PutUint16(b[9:], 100)
	for i, d := range []string{l.staged.Request.RequestSHA256, l.control.SessionSHA256, l.profileDigest} {
		raw, _ := hex.DecodeString(d[7:])
		copy(b[11+i*32:], raw)
	}
	binary.LittleEndian.PutUint32(b[107:], errno)
	return b
}

func parseActionStatus(b []byte, l actionLaunch) error {
	if len(b) != 111 || !bytes.Equal(b, actionStatus(l, 1, 0)) {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	return nil
}

func linuxActionFilters(f actionFDTable, pid int, profiles ...string) ([]unix.SockFilter, error) {
	if len(profiles) > 1 || (len(profiles) == 1 && !linuxActionProfile(profiles[0])) {
		return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	poll := len(profiles) == 1 && profiles[0] == "linux-static-fd-go127-poll/v1"

	if f.last < 6 || f.last > 134 || len(f.pollers) > 32 || pid <= 0 {
		return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	stmt := func(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
	jump := func(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, K: k, Jt: jt, Jf: jf}
	}
	retD := stmt(unix.BPF_RET|unix.BPF_K, deny)
	retA := stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW)
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	} else if runtime.GOARCH != "amd64" {
		return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	code := []unix.SockFilter{stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, arch, 1, 0), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS)}
	u32 := func(arg int) []unix.SockFilter {
		return []unix.SockFilter{stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, uint32(20+arg*8)), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 1, 0), retD, stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, uint32(16+arg*8))}
	}
	eq := func(arg int, v uint32) []unix.SockFilter {
		b := u32(arg)
		return append(b, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, v, 1, 0), retD)
	}
	choices := func(arg int, values ...uint32) []unix.SockFilter {
		b := u32(arg)
		for i, v := range values {
			b = append(b, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, v, 0, 1), stmt(unix.BPF_JMP|unix.BPF_JA, uint32(2*(len(values)-i-1)+1)))
		}
		return append(b, retD)
	}
	max := func(arg int, v uint32) []unix.SockFilter {
		b := u32(arg)
		return append(b, jump(unix.BPF_JMP|unix.BPF_JGT|unix.BPF_K, v, 0, 1), retD)
	}
	mask := func(arg int, allowed uint32) []unix.SockFilter {
		b := u32(arg)
		return append(b, stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, ^allowed), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 1, 0), retD)
	}
	join := func(parts ...[]unix.SockFilter) []unix.SockFilter {
		var out []unix.SockFilter
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	add := func(n int, b []unix.SockFilter) {
		code = append(code, stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(n), 1, 0), stmt(unix.BPF_JMP|unix.BPF_JA, uint32(len(b)+1)))
		code = append(code, b...)
		code = append(code, retA)
	}
	fds := []uint32{0, 5, 6}
	for i := 7; i <= f.last; i++ {
		fds = append(fds, uint32(i))
	}
	for _, n := range []int{unix.SYS_PREAD64, unix.SYS_LSEEK, unix.SYS_FSTAT} {
		add(n, choices(0, fds...))
	}
	// A syscall block must contain all alternatives: a failed branch returns deny.
	alternatives := func(a, b []unix.SockFilter) []unix.SockFilter {
		out := append([]unix.SockFilter(nil), a...)
		for i := range out {
			if out[i].Code == unix.BPF_RET|unix.BPF_K && out[i].K == deny {
				out[i] = stmt(unix.BPF_JMP|unix.BPF_JA, uint32(len(a)-i))
			}
		}
		out = append(out, stmt(unix.BPF_JMP|unix.BPF_JA, uint32(len(b))))
		return append(out, b...)
	}
	if poll {
		add(unix.SYS_READ, alternatives(choices(0, fds...), join(eq(0, 4), eq(2, 8))))
	} else {
		add(unix.SYS_READ, choices(0, fds...))
	}
	if poll {
		add(unix.SYS_WRITE, alternatives(choices(0, 1, 2), join(eq(0, 4), choices(2, 8, 111))))
		add(unix.SYS_WRITEV, join(choices(0, 1, 2), max(2, 1024)))
	} else {
		add(unix.SYS_WRITE, choices(0, 1, 2, 4))
		add(unix.SYS_WRITEV, join(choices(0, 1, 2, 4), max(2, 1024)))
	}
	add(unix.SYS_CLOSE, max(0, 1<<20))
	for _, n := range []int{unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_BRK, unix.SYS_MUNMAP, unix.SYS_SCHED_YIELD, unix.SYS_NANOSLEEP, unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK, unix.SYS_GETPID, unix.SYS_GETTID, unix.SYS_UNAME, unix.SYS_GETCPU, unix.SYS_GETTIMEOFDAY} {
		add(n, nil)
	}
	add(unix.SYS_MPROTECT, mask(2, unix.PROT_READ|unix.PROT_WRITE))
	fdMinusOne := []unix.SockFilter{stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 52), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, ^uint32(0), 1, 0), retD, stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 48), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, ^uint32(0), 1, 0), retD}
	flags := u32(3)
	flags = append(flags, stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, 1, 0), retD)
	add(unix.SYS_MMAP, join(mask(2, unix.PROT_READ|unix.PROT_WRITE), mask(3, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED|unix.MAP_NORESERVE|unix.MAP_STACK), flags, fdMinusOne, eq(5, 0)))
	add(unix.SYS_MADVISE, choices(2, unix.MADV_DONTNEED, unix.MADV_FREE, unix.MADV_HUGEPAGE, unix.MADV_NOHUGEPAGE, unix.MADV_DONTDUMP))
	futexOps := []uint32{0, 1, 9, 10, 128, 129, 137, 138, 9 | 256, 9 | 128 | 256}
	add(unix.SYS_FUTEX, choices(1, futexOps...))
	cloneFlags := []uint32{0x50f00}
	if runtime.GOARCH == "amd64" {
		cloneFlags = append(cloneFlags, 0xd0f00)
	}
	add(unix.SYS_CLONE, choices(0, cloneFlags...))
	add(unix.SYS_EXECVEAT, join(eq(0, 5), eq(4, unix.AT_EMPTY_PATH)))
	add(unix.SYS_TGKILL, join(eq(0, uint32(pid)), choices(2, 23, 27)))
	add(unix.SYS_SCHED_GETAFFINITY, join(choices(0, 0, uint32(pid)), max(1, 4096)))
	add(unix.SYS_GETRANDOM, join(max(1, 256), choices(2, 0, unix.GRND_NONBLOCK)))
	add(unix.SYS_PRLIMIT64, join(choices(0, 0, uint32(pid)), eq(2, 0)))
	queryFDs := append(append([]uint32{}, fds...), 1, 2)
	if poll {
		queryFDs = append(queryFDs, 3, 4)
	}
	add(unix.SYS_FCNTL, join(choices(0, queryFDs...), choices(1, unix.F_GETFD, unix.F_GETFL)))
	add(unix.SYS_CLOCK_GETTIME, choices(0, unix.CLOCK_REALTIME, unix.CLOCK_MONOTONIC))
	add(unix.SYS_CLOCK_NANOSLEEP, join(choices(0, unix.CLOCK_REALTIME, unix.CLOCK_MONOTONIC), choices(1, 0, unix.TIMER_ABSTIME)))
	// Numeric architecture-specific calls avoid references absent from arm64's
	// generated unix constants; these fixed numbers are independently pinned.
	if runtime.GOARCH == "amd64" {
		add(158, eq(0, 0x1002))
	}
	if poll {
		add(unix.SYS_EPOLL_CREATE1, eq(0, unix.EPOLL_CLOEXEC))
		add(unix.SYS_EVENTFD2, join(eq(0, 0), eq(1, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)))
		targets := []uint32{0, 1, 2, 4, 6}
		for fd := 7; fd <= f.last; fd++ {
			targets = append(targets, uint32(fd))
		}
		add(unix.SYS_EPOLL_CTL, join(eq(0, 3), choices(1, unix.EPOLL_CTL_ADD, unix.EPOLL_CTL_DEL), choices(2, targets...)))
		polls := []uint32{3}
		for _, fd := range f.pollers {
			if fd <= f.last || fd > 1<<20 {
				return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
			}
			polls = append(polls, uint32(fd))
		}
		// Exact Go uintptr conversion: nonnegative int32 or sign-extended -1.
		timeout := alternatives(max(3, 0x7fffffff), []unix.SockFilter{
			stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 44), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0xffffffff, 1, 0), retD,
			stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 40), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0xffffffff, 1, 0), retD,
		})
		count := join(max(2, 128), u32(2), []unix.SockFilter{jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 0, 1), retD})
		add(unix.SYS_EPOLL_PWAIT, join(choices(0, polls...), count, timeout, eq(4, 0), eq(5, 0)))
	} else if len(f.pollers) > 0 {
		pollers := []uint32{}
		for _, fd := range f.pollers {
			if fd <= f.last || fd > 1<<20 {
				return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
			}
			pollers = append(pollers, uint32(fd))
		}
		numbers := []int{22, 441}
		if runtime.GOARCH == "amd64" {
			numbers = []int{232, 281, 441}
		}
		for _, n := range numbers {
			add(n, join(choices(0, pollers...), max(2, 4096)))
		}
	}
	// clone3 is explicitly unavailable, enabling the reviewed legacy clone ABI.
	code = append(code, stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 435, 0, 1), stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)), retD)
	if len(code) > 4096 {
		return nil, &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	return code, nil
}

// Reads may advance atime; mutation and identity fields must remain unchanged.
func sameActionInheritedStat(a, b unix.Stat_t) bool { a.Atim = b.Atim; return a == b }

func linuxActionProfile(p string) bool {
	return p == "linux-static-fd-go127/v1" || p == "linux-static-fd-go127-poll/v1"
}

// Validate the original held bootstrap without copying the entire executable.
func actionStaticBootstrap(file *os.File, size int64) (ok bool) {
	if size < 64 || size > 128<<20 {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	var h [64]byte
	if _, e := file.ReadAt(h[:], 0); e != nil {
		return false
	}
	if binary.LittleEndian.Uint16(h[56:58]) > 128 || binary.LittleEndian.Uint16(h[60:62]) > 4096 {
		return false
	}
	f, e := elf.NewFile(io.NewSectionReader(file, 0, size))
	if e != nil {
		return false
	}
	defer f.Close()
	machine, supported := linuxNativeMachine()
	if !supported || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Version != elf.EV_CURRENT || f.Machine != machine || f.Type != elf.ET_EXEC || f.Entry == 0 || (f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX) {
		return false
	}
	executable := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return false
		}
		if p.Type == elf.PT_LOAD {
			if p.Filesz > p.Memsz || p.Off+p.Filesz < p.Off || p.Off+p.Filesz > uint64(size) {
				return false
			}
			if p.Flags&elf.PF_X != 0 {
				if p.Flags&elf.PF_W != 0 {
					return false
				}
				executable = true
			}
		}
	}
	return executable
}

func actionExecDescriptorClosure(last int) error {
	if last < 6 || last > 134 {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	entries, e := os.ReadDir("/proc/self/fd")
	if e != nil || len(entries) > 4096 {
		return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil || fd < 0 || fd > 1<<20 {
			return &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(e, unix.EBADF) {
			continue
		}
		if e != nil {
			return e
		}
		survives := fd <= 2 || (fd >= 6 && fd <= last)
		if (flags&unix.FD_CLOEXEC == 0) != survives {
			return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
		}
	}
	for fd := 0; fd <= last; fd++ {
		if fd == 3 {
			continue
		}
		if _, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); e != nil {
			return e
		}
	}
	var status unix.Stat_t
	if unix.Fstat(4, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFIFO {
		return &ExecutionError{"TRUST_ACTION_BOOTSTRAP_INVALID"}
	}
	return nil
}
