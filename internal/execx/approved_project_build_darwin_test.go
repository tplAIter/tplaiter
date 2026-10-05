//go:build darwin

package execx

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestProjectGoLoaderClosedActualDriver(t *testing.T) {
	b, e := os.ReadFile(filepath.Join(runtime.GOROOT(), "bin", "go"))
	if e != nil {
		t.Fatal(e)
	}
	if !validProjectGoNative(b) {
		t.Fatal("actual signed-fixture Go driver ABI unsupported")
	}
	foreign := append([]byte(nil), b...)
	name := []byte("/System/Library/Frameworks/Security.framework/Versions/A/Security")
	at := bytes.Index(foreign, name)
	if at < 0 {
		t.Fatal("qualified driver loader changed")
	}
	foreign[at+1] = 'x'
	if validProjectGoNative(foreign) {
		t.Fatal("unrecognized native dependency admitted")
	}
	if validProjectGoNative(b[:31]) {
		t.Fatal("truncated envelope admitted")
	}
	foreign = append([]byte(nil), b...)
	foreign[4] = 0
	if validProjectGoNative(foreign) {
		t.Fatal("wrong architecture admitted")
	}
	t.Logf("qualified actual toolchain %s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func TestProjectBuildOpaqueReceiptBinding(t *testing.T) {
	r := &ApprovedRunner{}
	other := &ApprovedRunner{}
	// Actual successful receipt behavior is covered by the signed installed CLI
	// fixture. Counterexamples here verify the private receipt cannot cross runners.
	p := &ProcessReceipt{runner: r, request: "expected"}
	req := trustverify.ExecutionRequest{RequestSHA256: "expected"}
	if _, e := p.ResultFor(r, req); e == nil {
		t.Fatal("noncanonical caller request with same digest label accepted")
	}
	if _, e := p.ResultFor(other, req); e == nil {
		t.Fatal("foreign runner accepted")
	}
	req.RequestSHA256 = "other"
	if _, e := p.ResultFor(r, req); e == nil {
		t.Fatal("foreign request accepted")
	}
}

func TestProjectGoGuardHeldLaunch(t *testing.T) {
	stage := t.TempDir()
	stage, e := filepath.EvalSymlinks(stage)
	if e != nil {
		t.Fatal(e)
	}
	tool := filepath.Join(stage, "toolchain")
	if e = os.Mkdir(tool, 0700); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(runtime.GOROOT(), "bin", "go"))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(tool, "go")
	if e = os.WriteFile(path, data, 0500); e != nil {
		t.Fatal(e)
	}
	held, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	got, e := approvedPathForFD(int(held.Fd()))
	if e != nil || got != path {
		t.Fatal("lost held path", e)
	}
	hi, e := held.Stat()
	if e != nil {
		t.Fatal(e)
	}
	pi, e := os.Lstat(path)
	if e != nil || !os.SameFile(hi, pi) {
		t.Fatal("lost held identity", e)
	}
	policy := projectGoPolicy(stage)
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", policy, got, "version")
	cmd.Dir = stage
	cmd.Env = []string{"HOME=" + stage, "GOROOT=" + tool, "GOENV=off", "GOAUTH=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOTELEMETRY=off"}
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("exact held Go launch %v %s", e, out)
	}
	if string(out) != "go version "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH+"\n" {
		t.Fatalf("unexpected version %q", out)
	}
	t.Logf("exact held Go launch: %s", out)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	probe, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	probePath := filepath.Join(tool, "guard-probe")
	if e = os.WriteFile(probePath, probe, 0500); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	outside, e = filepath.EvalSymlinks(outside)
	if e != nil {
		t.Fatal(e)
	}
	sentinel := filepath.Join(outside, "synthetic.txt")
	if e = os.WriteFile(sentinel, []byte("preserve synthetic outside"), 0600); e != nil {
		t.Fatal(e)
	}
	cmd = exec.Command("/usr/bin/sandbox-exec", "-p", policy, probePath, "-test.run=^TestProjectGoGuardChild$")
	cmd.Dir = stage
	cmd.Env = []string{"HOME=" + stage, "TPLAITER_GO_GUARD_CHILD=1", "TPLAITER_OUTSIDE_FILE=" + sentinel, "TPLAITER_TOOLCHAIN_FILE=" + path}
	out, e = cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("guard counterexample %v %s", e, out)
	}
	after, e := os.ReadFile(sentinel)
	if e != nil || string(after) != "preserve synthetic outside" {
		t.Fatal("outside changed", e)
	}
	after, e = os.ReadFile(path)
	if e != nil || !bytes.Equal(data, after) {
		t.Fatal("toolchain changed", e)
	}
	t.Logf("exact profile counterexamples: %s", out)
}

// The child touches only explicitly synthetic fixture paths. It never opens
// credentials or machine configuration to demonstrate a guard.
func TestProjectGoGuardChild(t *testing.T) {
	if os.Getenv("TPLAITER_GO_GUARD_CHILD") != "1" {
		t.Skip("synthetic sandbox child only")
	}
	if e := os.WriteFile("allowed-stage.txt", []byte("synthetic stage write accepted"), 0600); e != nil {
		t.Fatalf("stage write unavailable: %v", e)
	}
	outside := os.Getenv("TPLAITER_OUTSIDE_FILE")
	tool := os.Getenv("TPLAITER_TOOLCHAIN_FILE")
	if _, e := os.ReadFile(outside); !errors.Is(e, os.ErrPermission) {
		t.Fatalf("outside read was not OS-denied: %v", e)
	}
	if e := os.WriteFile(outside, []byte("forbidden"), 0600); !errors.Is(e, os.ErrPermission) {
		t.Fatalf("outside write was not OS-denied: %v", e)
	}
	if e := os.WriteFile(tool, []byte("forbidden"), 0600); !errors.Is(e, os.ErrPermission) {
		t.Fatalf("toolchain write was not OS-denied: %v", e)
	}
	if e := exec.Command("/usr/bin/true").Run(); !errors.Is(e, os.ErrPermission) {
		t.Fatalf("ambient executable was not OS-denied: %v", e)
	}
	conn, e := net.Dial("tcp", "127.0.0.1:1")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(e, syscall.EPERM) && !errors.Is(e, syscall.EACCES) {
		t.Fatalf("network was not OS-denied: %v", e)
	}
	fmt.Println("synthetic read/write/toolchain-mutation/ambient-exec/network all OS-denied")
}
