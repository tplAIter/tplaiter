//go:build darwin || linux

package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const fixtureBridgeLimit = 32 << 20

type fixtureBridgeRequest struct {
	Operation  string                    `json:"operation"`
	Selection  trustload.LaunchSelection `json:"selection"`
	ProjectKey string                    `json:"projectKey"`
	Clock      string                    `json:"clock"`
	Home       string                    `json:"home"`
	Project    string                    `json:"project"`
	Name       string                    `json:"name"`
	Module     string                    `json:"module"`
	Ref        string                    `json:"ref"`
	Renderer   string                    `json:"renderer"`
	Source     json.RawMessage           `json:"source,omitempty"`
	Target     json.RawMessage           `json:"target,omitempty"`
	Intent     json.RawMessage           `json:"intent,omitempty"`
}
type fixtureBridgeLog struct {
	mu   sync.Mutex
	data []byte
}

func (b *fixtureBridgeLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if remain := 65536 - len(b.data); remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (b *fixtureBridgeLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

type fixtureBridge struct {
	t        *testing.T
	request  fixtureBridgeRequest
	command  *exec.Cmd
	input    io.WriteCloser
	output   *os.File
	scan     *bufio.Scanner
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	log      *fixtureBridgeLog
	once     sync.Once
	terminal error
}

// Every child is a finite, exact locally built test image, with bounded pipes.
// The original prepared plan remains in that child across lease acquisition.
func startFixtureBridge(t *testing.T, q fixtureBridgeRequest) *fixtureBridge {
	t.Helper()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "fixture.test")
	buildCtx, buildCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer buildCancel()
	buildLog := &fixtureBridgeLog{}
	build := fixtureBridgeCommand(buildCtx, filepath.Join(runtime.GOROOT(), "bin", "go"), "test", "-c", "-o", image, "./internal/projecttransaction")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "PYTHONDONTWRITEBYTECODE=1")
	build.Stdout = buildLog
	build.Stderr = buildLog
	if err := runFixtureBuild(buildCtx, build); err != nil {
		t.Fatalf("fixture image build: %v: %s", err, buildLog.String())
	}
	imageRaw, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("exact local fixture test image sha256:%x", sha256.Sum256(imageRaw))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	command := fixtureBridgeCommand(ctx, image, "-test.run=^TestManagedEngineFixtureBridge$", "-test.count=1")
	command.Dir = root
	command.Env = append(os.Environ(), "TPLAITER_ENGINE_FIXTURE_BRIDGE=1", "PYTHONDONTWRITEBYTECODE=1")
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		cancel()
		_ = input.Close()
		t.Fatal(err)
	}
	log := &fixtureBridgeLog{}
	command.Stdout = log
	command.Stderr = log
	command.ExtraFiles = []*os.File{wr}
	if err = command.Start(); err != nil {
		cancel()
		_ = input.Close()
		_ = rd.Close()
		_ = wr.Close()
		t.Fatal(err)
	}
	_ = wr.Close()
	b := &fixtureBridge{t: t, request: q, command: command, input: input, output: rd, ctx: ctx, cancel: cancel, done: make(chan struct{}), log: log}
	b.scan = bufio.NewScanner(rd)
	b.scan.Buffer(make([]byte, 4096), fixtureBridgeLimit)
	t.Cleanup(b.Close)
	return b
}

func fixtureBridgeCommand(ctx context.Context, image string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, image, args...)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.WaitDelay = time.Second
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGTERM) }
	return c
}

func runFixtureBuild(ctx context.Context, c *exec.Cmd) error {
	if err := c.Start(); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() { wait <- c.Wait() }()
	select {
	case err := <-wait:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
		select {
		case err := <-wait:
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			return err
		case <-time.After(time.Second):
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			return <-wait
		}
	}
}

func (b *fixtureBridge) finish() error {
	b.once.Do(func() {
		_ = b.input.Close()
		wait := make(chan error, 1)
		go func() { wait <- b.command.Wait() }()
		select {
		case b.terminal = <-wait:
		case <-time.After(time.Second):
			b.cancel()
			_ = syscall.Kill(-b.command.Process.Pid, syscall.SIGTERM)
			select {
			case b.terminal = <-wait:
			case <-time.After(time.Second):
				_ = syscall.Kill(-b.command.Process.Pid, syscall.SIGKILL)
				b.terminal = <-wait
			}
		}
		_ = syscall.Kill(-b.command.Process.Pid, syscall.SIGKILL)
		_ = b.output.Close()
		b.cancel()
		close(b.done)
	})
	return b.terminal
}

func (b *fixtureBridge) Close() {
	select {
	case <-b.done:
		return
	default:
	}
	if err := b.finish(); err != nil {
		b.t.Errorf("fixture helper terminal failure: %v: %s", err, b.log.String())
	}
}

func (b *fixtureBridge) exchange(operation string, intent json.RawMessage) (json.RawMessage, error) {
	q := b.request
	q.Operation = operation
	q.Intent = intent
	raw, err := canonicaljson.Canonical(q)
	if err != nil || len(raw) >= fixtureBridgeLimit {
		return nil, errors.New("invalid fixture request")
	}
	result := make(chan struct {
		raw []byte
		err error
	}, 1)
	go func() {
		if _, e := fmt.Fprintf(b.input, "%s\n", raw); e != nil {
			result <- struct {
				raw []byte
				err error
			}{nil, e}
			return
		}
		if !b.scan.Scan() {
			e := b.scan.Err()
			if e == nil {
				e = io.ErrUnexpectedEOF
			}
			result <- struct {
				raw []byte
				err error
			}{nil, e}
			return
		}
		result <- struct {
			raw []byte
			err error
		}{bytes.Clone(b.scan.Bytes()), nil}
	}()
	select {
	case v := <-result:
		return v.raw, v.err
	case <-b.ctx.Done():
		b.cancel()
		_ = syscall.Kill(-b.command.Process.Pid, syscall.SIGKILL)
		_ = b.input.Close()
		_ = b.output.Close()
		<-result // Closing both pipes joins the exchange watcher before returning.
		return nil, b.ctx.Err()
	}
}

func (b *fixtureBridge) call(operation string, intent json.RawMessage) json.RawMessage {
	b.t.Helper()
	raw, err := b.exchange(operation, intent)
	if err != nil {
		b.t.Fatalf("fixture %s result: %v: %s", operation, err, b.log.String())
	}
	return raw
}

func (b *fixtureBridge) material(operation string, intent json.RawMessage) Material {
	b.t.Helper()
	var m Material
	if err := canonicaljson.DecodeStrict(b.call(operation, intent), &m); err != nil {
		b.t.Fatal(err)
	}
	return m
}

func updateFixtureBridge(t *testing.T, f *t5DIntegrationFixture, home string) *fixtureBridge {
	t.Helper()
	raw, err := json.Marshal(f.selection)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, "engine-bridge-launch.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b := startFixtureBridge(t, fixtureBridgeRequest{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}.Now().Format(time.RFC3339Nano), Home: home, Project: f.project, Name: "Ordinary Project", Module: "example.test/ordinary", Ref: f.source.Commit, Renderer: "v1", Source: t5DSelection(f.source, f.sourceRefs), Target: t5DSelection(f.target, f.targetRefs)})
	b.call("create", nil)
	return b
}

func authenticateFixtureMaterial(t *testing.T, home string, intent json.RawMessage) Material {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, "engine-bridge-launch.json"))
	if err != nil {
		t.Fatal(err)
	}
	var selection trustload.LaunchSelection
	if err = json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	b := startFixtureBridge(t, fixtureBridgeRequest{Selection: selection, ProjectKey: "project", Clock: t5DClock{}.Now().Format(time.RFC3339Nano), Home: home, Renderer: "v1"})
	m := b.material("authenticate-update", intent)
	b.Close()
	return m
}

func TestFixtureBridgeRejectsInvalidOperationAndNonzeroExit(t *testing.T) {
	f := t5DNewIntegrationFixtureWithSource(t, func(t *testing.T, root, suffix, output, extra string) ([]byte, trustverify.Subject) {
		return t5DWriteNativeSourceFiles(t, root, suffix, output, extra, nil)
	})
	home := filepath.Join(f.dir, "bridge-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	b := startFixtureBridge(t, fixtureBridgeRequest{Selection: f.selection, ProjectKey: "project", Clock: t5DClock{}.Now().Format(time.RFC3339Nano), Home: home, Renderer: "v1"})
	if raw, err := b.exchange("unknown-operation", nil); err == nil || len(raw) != 0 {
		t.Fatal("invalid operation produced accepted output")
	}
	if err := b.finish(); err == nil {
		t.Fatal("source-owner refusal exited successfully")
	}
	// Cleanup has already joined/reaped this deliberately rejected helper.
	if entries, err := os.ReadDir(f.project); err != nil || len(entries) != 0 {
		t.Fatal("invalid operation changed project")
	}
}

func TestFixtureBridgeBoundedResultTransport(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"missing", nil}, {"invalid", []byte("{bad}\n")}, {"oversize", bytes.Repeat([]byte("x"), fixtureBridgeLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scan := bufio.NewScanner(bytes.NewReader(tc.input))
			scan.Buffer(make([]byte, 4096), fixtureBridgeLimit)
			if !scan.Scan() {
				if tc.name == "invalid" {
					t.Fatal("invalid JSON did not reach decoder")
				}
				return
			}
			var m Material
			if err := canonicaljson.DecodeStrict(scan.Bytes(), &m); err == nil {
				t.Fatal("invalid transport accepted as material")
			}
		})
	}
}
