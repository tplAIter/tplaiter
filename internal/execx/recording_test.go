package execx

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRecordingRunner_OnExactMatch(t *testing.T) {
	r := NewRecordingRunner().On("git", []string{"status"}, Response{Result: Result{Stdout: "clean"}})

	res, err := r.Run(context.Background(), "git", []string{"status"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "clean" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "clean")
	}

	if len(r.Calls) != 1 {
		t.Fatalf("len(Calls) = %d, want 1", len(r.Calls))
	}
	if r.Calls[0].Name != "git" || len(r.Calls[0].Args) != 1 || r.Calls[0].Args[0] != "status" {
		t.Errorf("Calls[0] = %+v, unexpected", r.Calls[0])
	}
}

func TestRecordingRunner_OnCommandFallback(t *testing.T) {
	// Script a response for any "git" arguments; the call uses different args
	// ("git log"), so there is no exact match and OnCommand must be used.
	r := NewRecordingRunner().OnCommand("git", Response{Result: Result{Stdout: "generic"}})

	res, err := r.Run(context.Background(), "git", []string{"log"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "generic" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "generic")
	}
}

func TestRecordingRunner_ExactBeatsCommand(t *testing.T) {
	r := NewRecordingRunner().
		OnCommand("git", Response{Result: Result{Stdout: "generic"}}).
		On("git", []string{"status"}, Response{Result: Result{Stdout: "specific"}})

	res, err := r.Run(context.Background(), "git", []string{"status"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "specific" {
		t.Errorf("Stdout = %q, want %q (exact match must win over command-level)", res.Stdout, "specific")
	}
}

func TestRecordingRunner_FIFOSequence(t *testing.T) {
	r := NewRecordingRunner().
		On("git", []string{"pull"}, Response{Result: Result{Stdout: "first"}}).
		On("git", []string{"pull"}, Response{Result: Result{Stdout: "second"}})

	res1, _ := r.Run(context.Background(), "git", []string{"pull"}, Options{})
	res2, _ := r.Run(context.Background(), "git", []string{"pull"}, Options{})
	res3, _ := r.Run(context.Background(), "git", []string{"pull"}, Options{})

	if res1.Stdout != "first" {
		t.Errorf("call 1 = %q, want %q", res1.Stdout, "first")
	}
	if res2.Stdout != "second" {
		t.Errorf("call 2 = %q, want %q", res2.Stdout, "second")
	}
	if res3.Stdout != "second" {
		t.Errorf("call 3 (past queue end) = %q, want last scripted %q", res3.Stdout, "second")
	}
}

func TestRecordingRunner_ScriptedError(t *testing.T) {
	wantErr := errors.New("boom")
	r := NewRecordingRunner().On("glab", []string{"auth", "status"}, Response{Err: wantErr})

	_, err := r.Run(context.Background(), "glab", []string{"auth", "status"}, Options{})
	if !errors.Is(err, wantErr) {
		t.Errorf("Run() error = %v, want %v", err, wantErr)
	}
}

func TestRecordingRunner_NoScriptIsError(t *testing.T) {
	r := NewRecordingRunner()
	_, err := r.Run(context.Background(), "git", []string{"status"}, Options{})
	if err == nil {
		t.Fatal("Run() expected error when no script and no default is set")
	}
}

func TestRecordingRunner_Default(t *testing.T) {
	r := NewRecordingRunner().SetDefault(Response{Result: Result{Stdout: "fallback"}})
	res, err := r.Run(context.Background(), "anything", []string{"whatever"}, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res.Stdout != "fallback" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "fallback")
	}
}

func TestRecordingRunner_StreamsToWriters(t *testing.T) {
	r := NewRecordingRunner().On("build", nil, Response{Result: Result{Stdout: "compiling\n", Stderr: "warn\n"}})

	var stdout, stderr bytes.Buffer
	_, err := r.Run(context.Background(), "build", nil, Options{Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if stdout.String() != "compiling\n" {
		t.Errorf("streamed stdout = %q", stdout.String())
	}
	if stderr.String() != "warn\n" {
		t.Errorf("streamed stderr = %q", stderr.String())
	}
}

func TestRecordingRunner_LookPath(t *testing.T) {
	r := NewRecordingRunner().SetLookPath("git", "/usr/bin/git")

	path, err := r.LookPath("git")
	if err != nil {
		t.Fatalf("LookPath(git) error = %v", err)
	}
	if path != "/usr/bin/git" {
		t.Errorf("LookPath(git) = %q, want %q", path, "/usr/bin/git")
	}

	if _, err := r.LookPath("nonexistent"); err == nil {
		t.Error("LookPath(nonexistent) expected error")
	}
}

func TestRecordingRunner_RecordsCallsAcrossMultipleCommands(t *testing.T) {
	r := NewRecordingRunner().SetDefault(Response{Result: Result{Stdout: "ok"}})

	_, _ = r.Run(context.Background(), "git", []string{"clone", "x"}, Options{Dir: "/tmp/a"})
	_, _ = r.Run(context.Background(), "glab", []string{"mr", "create"}, Options{Dir: "/tmp/b"})

	if len(r.Calls) != 2 {
		t.Fatalf("len(Calls) = %d, want 2", len(r.Calls))
	}
	if r.Calls[0].Name != "git" || r.Calls[0].Opts.Dir != "/tmp/a" {
		t.Errorf("Calls[0] = %+v, unexpected", r.Calls[0])
	}
	if r.Calls[1].Name != "glab" || r.Calls[1].Opts.Dir != "/tmp/b" {
		t.Errorf("Calls[1] = %+v, unexpected", r.Calls[1])
	}
}
