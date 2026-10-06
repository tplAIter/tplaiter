//go:build darwin || linux

package receiptevidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type boundaryContext struct {
	context.Context
	calls  int
	at     int
	effect func()
	cancel bool
}

func (c *boundaryContext) Err() error {
	c.calls++
	if c.calls == c.at {
		if c.effect != nil {
			c.effect()
		}
		if c.cancel {
			return context.Canceled
		}
	}
	return c.Context.Err()
}
func kernelDirectory(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestReceiptKernelConfinementAndFIFO(t *testing.T) {
	parent := kernelDirectory(t)
	dir := filepath.Join(parent, "receipts")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(dir, "plan.json")
	if e := os.WriteFile(name, []byte("original"), 0o600); e != nil {
		t.Fatal(e)
	}
	d, e := openDirectory(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	raw, fact, e := d.read(context.Background(), "plan.json", 128, nil)
	if e != nil || !bytes.Equal(raw, []byte("original")) || fact.device == 0 || fact.inode == 0 {
		t.Fatal("real physical identity", e, fact)
	}
	alias := filepath.Join(parent, "alias")
	if e = os.Symlink(dir, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = openDirectory(context.Background(), alias); e == nil {
		t.Fatal("ancestor symlink accepted")
	}
	if e = os.Symlink(name, filepath.Join(dir, "other.json")); e != nil {
		t.Fatal(e)
	}
	if _, _, e = d.read(context.Background(), "other.json", 128, nil); e == nil {
		t.Fatal("leaf symlink accepted")
	}
	// Swap a genuinely regular observed leaf for a kernel FIFO before openat.
	ctx := &boundaryContext{Context: context.Background(), at: 2, effect: func() {
		if e := os.Remove(name); e != nil {
			t.Fatal(e)
		}
		if e := syscall.Mkfifo(name, 0o600); e != nil {
			t.Fatal(e)
		}
	}}
	start := time.Now()
	if _, _, e = d.read(ctx, "plan.json", 128, nil); e == nil {
		t.Fatal("raced FIFO accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO boundary blocked")
	}
	if e = os.Remove(name); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(name, []byte("replacement"), 0o600); e != nil {
		t.Fatal(e)
	}
	ctx = &boundaryContext{Context: context.Background(), at: 3, effect: func() {
		if e := os.Rename(dir, dir+"-old"); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(dir, 0o700); e != nil {
			t.Fatal(e)
		}
	}}
	if _, _, e = d.read(ctx, "plan.json", 128, nil); e == nil {
		t.Fatal("parent replacement accepted")
	}
}
func TestReceiptKernelBudgetsCancellationAndModes(t *testing.T) {
	dir := kernelDirectory(t)
	name := filepath.Join(dir, "plan.json")
	f, e := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(maxRawReceiptBytes + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	d, e := openDirectory(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	if _, _, e = d.read(context.Background(), "plan.json", maxRawReceiptBytes, nil); e == nil {
		t.Fatal("oversize accepted")
	}
	f, e = os.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(maxRawReceiptBytes); e != nil {
		t.Fatal(e)
	}
	f.Close()
	budget := int64(1)
	if _, _, e = d.read(context.Background(), "plan.json", maxRawReceiptBytes, &budget); e == nil || budget != 1 {
		t.Fatal("aggregate cap not refused before read allocation", e, budget)
	}
	raw, _, e := d.read(context.Background(), "plan.json", maxRawReceiptBytes, nil)
	if e != nil || int64(len(raw)) != maxRawReceiptBytes {
		t.Fatal("ordinary exact 128 MiB compatibility", e)
	}
	raw = nil
	ctx := &boundaryContext{Context: context.Background(), at: 4, cancel: true}
	if _, _, e = d.read(ctx, "plan.json", maxRawReceiptBytes, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("chunk cancellation lost", e)
	}
	if e = os.Chmod(name, 0o640); e != nil {
		t.Fatal(e)
	}
	if _, _, e = d.read(context.Background(), "plan.json", maxRawReceiptBytes, nil); e == nil {
		t.Fatal("foreign mode accepted")
	}
	if e = os.Chmod(name, 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(name, filepath.Join(dir, "alias")); e != nil {
		t.Fatal(e)
	}
	if _, _, e = d.read(context.Background(), "plan.json", maxRawReceiptBytes, nil); e == nil {
		t.Fatal("hardlinked receipt accepted")
	}
	if signedDevice(int32(-1)) != ^uint64(0) {
		t.Fatal("signed Darwin device identity lost")
	}
}
func TestReceiptKernelGrowthAndInPlaceMutation(t *testing.T) {
	dir := kernelDirectory(t)
	name := filepath.Join(dir, "state.json")
	if e := os.WriteFile(name, bytes.Repeat([]byte("a"), 128<<10), 0o600); e != nil {
		t.Fatal(e)
	}
	d, e := openDirectory(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	ctx := &boundaryContext{Context: context.Background(), at: 4, effect: func() {
		f, e := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write([]byte("growth")); e != nil {
			t.Fatal(e)
		}
		f.Close()
	}}
	if _, _, e = d.read(ctx, "state.json", 1<<20, nil); e == nil {
		t.Fatal("growth accepted")
	}
	ctx = &boundaryContext{Context: context.Background(), at: 4, effect: func() {
		f, e := os.OpenFile(name, os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.WriteAt([]byte("b"), 0); e != nil {
			t.Fatal(e)
		}
		f.Close()
	}}
	if _, _, e = d.read(ctx, "state.json", 1<<20, nil); e == nil {
		t.Fatal("same-size in-place mutation accepted")
	}
}
