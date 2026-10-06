//go:build darwin

package execx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Native kernel counter, not an installed source/tool/approval carrier.
// Maps bounded virtual address space with PROT_NONE, touches no mapped pages.
func TestActionDarwinAddressBoundCounter(t *testing.T) {
	if os.Getenv("TPLAITER_ACTION_AS_COUNTER") == "1" {
		if unix.RLIMIT_AS != unix.RLIMIT_RSS {
			t.Fatal("platform ABI changed")
		}
		var old unix.Rlimit
		if e := unix.Getrlimit(unix.RLIMIT_AS, &old); e != nil {
			t.Fatal(e)
		}
		limit := uint64(2 << 30)
		if old.Cur < limit {
			limit = old.Cur
		}
		if old.Max < limit {
			limit = old.Max
		}
		if e := unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{Cur: limit, Max: limit}); e != nil {
			if !errors.Is(e, unix.EINVAL) {
				t.Fatal(e)
			}
			t.Logf("native counter: requested AS/RSS=%d refused EINVAL; approved address-space bound cannot be installed", limit)
			return
		}
		var observed unix.Rlimit
		if e := unix.Getrlimit(unix.RLIMIT_AS, &observed); e != nil || observed.Cur != limit || observed.Max != limit {
			t.Fatal("limit not installed", e)
		}
		b, e := unix.Mmap(-1, 0, 3<<30, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if e != nil {
			t.Fatalf("counter no longer demonstrates unsupported bound: %v", e)
		}
		if e = unix.Munmap(b); e != nil {
			t.Fatal(e)
		}
		t.Logf("native counter: installed AS/RSS=%d; 3221225472-byte PROT_NONE mapping succeeded; physical pages untouched", limit)
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, exe, "-test.run=^TestActionDarwinAddressBoundCounter$", "-test.v")
	c.Env = []string{"TPLAITER_ACTION_AS_COUNTER=1"}
	out, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("native counter failed: %v %s", e, out)
	}
	if !bytes.Contains(out, []byte("mapping succeeded")) && !bytes.Contains(out, []byte("cannot be installed")) {
		t.Fatal("missing counter evidence")
	}
	t.Log(string(out))
}
