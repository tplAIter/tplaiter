//go:build darwin

package execx

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func executeProjectBuild(ctx context.Context, scratch string, m trustverify.StagedMaterial, chain *trustload.GoToolchain, modules *trustload.GoModules) (ProjectProcessResult, error) {
	failure := func(code string) (ProjectProcessResult, error) { return ProjectProcessResult{}, &ExecutionError{code} }
	if chain == nil || m.Request.Action.Kind != "command" || m.Request.Action.Shell || m.Request.WorkingDirectoryScope != (trustverify.WorkingDirectoryScope{Root: "project", Path: "."}) || !equalBuildArgs(m.Request.Action.Argv) || m.Request.Tool.ID != "go" || m.Request.TimeoutMillis < 1 || m.Request.TimeoutMillis > 120000 {
		return failure("TRUST_EXECUTION_MATERIAL_UNAVAILABLE")
	}
	if !validProjectGoNative(m.ToolBytes) {
		return failure("TRUST_EXECUTION_MATERIAL_UNAVAILABLE")
	}
	rootFD, e := openApprovedRoot(scratch)
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	defer unix.Close(rootFD)
	rootPath, e := approvedPathForFD(rootFD)
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	stagePath, e := os.MkdirTemp(rootPath, ".tplaiter-go-build-")
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	defer os.RemoveAll(stagePath)
	stage, e := os.OpenRoot(stagePath)
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	defer stage.Close()
	for _, dir := range []string{"toolchain", "project", "home", "cache", "gopath", "modules", "tmp"} {
		if e := stage.Mkdir(dir, 0700); e != nil {
			return failure("TRUST_STAGE_FAILED")
		}
	}
	write := func(name string, b []byte, mode os.FileMode) error {
		if filepath.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") {
			return errors.New("unsafe path")
		}
		if e := stage.MkdirAll(filepath.Dir(name), 0700); e != nil {
			return e
		}
		f, e := stage.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		c := f.Close()
		if e == nil {
			e = c
		}
		return e
	}
	files, data := chain.Files()
	for i, f := range files {
		if e := ctx.Err(); e != nil {
			return ProjectProcessResult{}, e
		}
		mode := os.FileMode(0400)
		if f.Mode == "100755" {
			if !validProjectGoNative(data[i]) {
				return failure("TRUST_TOOLCHAIN_UNAVAILABLE")
			}
			mode = 0500
		}
		if evidencecas.Digest(data[i]) != f.SHA256 {
			return failure("TRUST_TOOLCHAIN_UNAVAILABLE")
		}
		if e := write("toolchain/"+f.Path, data[i], mode); e != nil {
			return failure("TRUST_STAGE_FAILED")
		}
	}
	if modules != nil {
		files, data := modules.Files()
		for i, f := range files {
			if e := ctx.Err(); e != nil {
				return ProjectProcessResult{}, e
			}
			if evidencecas.Digest(data[i]) != f.SHA256 {
				return failure("TRUST_GO_MODULE_CLOSURE_UNAVAILABLE")
			}
			if e := write("modules/"+f.Path, data[i], 0400); e != nil {
				return failure("TRUST_STAGE_FAILED")
			}
		}
	}
	for i, f := range m.Content {
		if f.Root == "project" {
			if e := write("project/"+f.Path, m.ContentBytes[i], 0400); e != nil {
				return failure("TRUST_STAGE_FAILED")
			}
		}
	}
	driver, e := stage.Open("toolchain/bin/go")
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	defer driver.Close()
	driverBytes, e := io.ReadAll(io.LimitReader(driver, 16<<20+1))
	if e != nil || !bytes.Equal(driverBytes, m.ToolBytes) {
		return failure("TRUST_TOOLCHAIN_UNAVAILABLE")
	}
	driver.Seek(0, io.SeekStart)
	project, e := stage.Open("project")
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	defer project.Close()
	// All path operands are adapter-created under a fresh held scratch stage.
	// The policy forbids secondary toolchain mutation and all outbound traffic.
	policy := projectGoPolicy(stagePath)
	if e := write("guard.sb", []byte(policy), 0400); e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	env := []string{}
	for _, v := range m.Environment.Variables {
		env = append(env, v.Name+"="+strings.ReplaceAll(v.Value, "@stage", stagePath))
	}
	if !equalEnvironment(m.Environment, operationtrust.ProjectBuildEnvironment()) {
		return failure("TRUST_EXECUTION_MATERIAL_UNAVAILABLE")
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Request.TimeoutMillis)*time.Millisecond)
	defer cancel()
	driverPath, e := approvedPathForFD(int(driver.Fd()))
	if e != nil || driverPath != stagePath+"/toolchain/bin/go" {
		return failure("TRUST_STAGE_FAILED")
	}
	projectPath, e := approvedPathForFD(int(project.Fd()))
	if e != nil || projectPath != stagePath+"/project" {
		return failure("TRUST_STAGE_FAILED")
	}
	heldInfo, e := driver.Stat()
	if e != nil {
		return failure("TRUST_STAGE_FAILED")
	}
	pathInfo, e := os.Lstat(driverPath)
	if e != nil || !os.SameFile(heldInfo, pathInfo) || !pathInfo.Mode().IsRegular() {
		return failure("TRUST_STAGE_FAILED")
	}
	args := append([]string{"-f", stagePath + "/guard.sb", driverPath}, m.Request.Action.Argv[1:]...)
	cmd := exec.Command("/usr/bin/sandbox-exec", args...)
	cmd.ExtraFiles = []*os.File{driver, project}
	cmd.Dir = projectPath
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(nil)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, serr limitedBuffer
	out.n, serr.n = 1<<20, 64<<10
	cmd.Stdout, cmd.Stderr = &out, &serr
	if e := cmd.Start(); e != nil {
		return failure("TRUST_EXECUTION_FAILED")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	overflow, stop := outputOverflow(&out, &serr)
	defer stop()
	timed, cancelled := false, false
	var wait error
	select {
	case wait = <-done:
	case <-runCtx.Done():
		timed = ctx.Err() == nil
		cancelled = !timed
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		wait = <-done
	case <-overflow:
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return failure("TRUST_EXECUTION_OUTPUT_LIMIT")
	}
	if out.overflowed() || serr.overflowed() {
		return failure("TRUST_EXECUTION_OUTPUT_LIMIT")
	}
	// sandbox-exec applies before the child; a failed application is not compiler evidence.
	if strings.Contains(string(serr.b), "sandbox_apply:") || strings.Contains(string(serr.b), "sandbox-exec:") {
		return ProjectProcessResult{}, fmt.Errorf("%w: local sandbox launcher: %q", &ExecutionError{"TRUST_EXECUTION_GUARD_UNAVAILABLE"}, string(serr.b))
	}
	exit := 0
	if wait != nil {
		exit = cmd.ProcessState.ExitCode()
		if exit < 0 {
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				exit = 128 + int(status.Signal())
			} else {
				return failure("TRUST_EXECUTION_FAILED")
			}
		}
	}
	if timed {
		exit = 124
	}
	if cancelled {
		exit = 130
	}
	result := ProjectProcessResult{RequestSHA256: m.Request.RequestSHA256, InputClosureSHA256: m.Request.Action.ContentClosureSHA256, ToolchainIndexSHA256: evidencecas.Digest(chain.IndexBytes()), ExitCode: exit, TimedOut: timed, Cancelled: cancelled, Stdout: string(out.b), Stderr: string(serr.b), StdoutSHA256: evidencecas.Digest(out.b), StderrSHA256: evidencecas.Digest(serr.b)}
	if modules != nil {
		result.ModuleIndexSHA256 = evidencecas.Digest(modules.IndexBytes())
	}
	return result, nil
}
func equalBuildArgs(a []string) bool {
	b := operationtrust.ProjectBuildArguments()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func equalEnvironment(a, b trustverify.EnvironmentPolicy) bool {
	if a.Inherit || a.APIVersion != b.APIVersion || len(a.Capabilities) != 0 || len(a.Variables) != len(b.Variables) {
		return false
	}
	for i := range a.Variables {
		if a.Variables[i] != b.Variables[i] {
			return false
		}
	}
	return true
}

// The project Go driver has a different reviewed loader closure from gofmt.
// Only these fixed macOS ABI libraries are admitted; no rpath, weak/reexported
// library, interpreter override, or ambient plugin executable is allowed.
func validProjectGoNative(b []byte) bool {
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf || binary.LittleEndian.Uint32(b[4:]) != 0x0100000c || binary.LittleEndian.Uint32(b[8:]) != 0 || binary.LittleEndian.Uint32(b[12:]) != 2 {
		return false
	}
	ncmd, size := int(binary.LittleEndian.Uint32(b[16:])), int(binary.LittleEndian.Uint32(b[20:]))
	if ncmd < 1 || ncmd > 4096 || size < 8 || size > len(b)-32 {
		return false
	}
	off, end := 32, 32+size
	dyld := false
	libs := map[string]bool{}
	allowed := map[string]bool{"/usr/lib/libSystem.B.dylib": true, "/usr/lib/libresolv.9.dylib": true, "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation": true, "/System/Library/Frameworks/Security.framework/Versions/A/Security": true}
	for i := 0; i < ncmd; i++ {
		if off+8 > end {
			return false
		}
		cmd, n := binary.LittleEndian.Uint32(b[off:]), int(binary.LittleEndian.Uint32(b[off+4:]))
		if n < 8 || n%8 != 0 || off+n > end {
			return false
		}
		switch cmd {
		case 0xe:
			p, ok := machoName(b[off:off+n], 8)
			if !ok || p != "/usr/lib/dyld" || dyld {
				return false
			}
			dyld = true
		case 0xc:
			p, ok := machoName(b[off:off+n], 8)
			if !ok || !allowed[p] || libs[p] {
				return false
			}
			libs[p] = true
		case 0x8000001c, 0x80000018, 0x8000001f, 0x80000023, 0x20:
			return false
		}
		off += n
	}
	return off == end && dyld && libs["/usr/lib/libSystem.B.dylib"]
}

func projectGoPolicy(stagePath string) string {
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return "(version 1)\n(allow default)\n(deny network*)\n(deny file-read*)\n(allow file-read* (literal \"/\") (subpath " + quote(stagePath) + ") (subpath \"/System/Library\") (subpath \"/usr/lib\") (literal \"/dev/null\") (literal \"/dev/fd/3\") (literal \"/dev/fd/4\"))\n(deny file-write*)\n(allow file-write* (subpath " + quote(stagePath) + ") (literal \"/dev/null\"))\n(deny file-write* (subpath " + quote(stagePath+"/toolchain") + ") (subpath " + quote(stagePath+"/modules") + "))\n(deny process-exec)\n(allow process-exec (subpath " + quote(stagePath+"/toolchain") + ") (literal \"/dev/fd/3\"))\n(deny mach-lookup (global-name \"com.apple.securityd\") (global-name \"com.apple.cfprefsd.daemon\"))\n"
}
