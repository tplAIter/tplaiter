package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

func TestUpgrade_GoInstall(t *testing.T) {
	r := execx.NewRecordingRunner()
	r.On("go", []string{"install", "github.com/tplAIter/tplaiter@latest"}, execx.Response{
		Result: execx.Result{Stdout: "go: downloading ...\n"},
	})

	var out bytes.Buffer
	err := Upgrade(context.Background(), r, ChannelGoInstall, "github.com/tplAIter/tplaiter", &out)
	if err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if len(r.Calls) != 1 {
		t.Fatalf("Upgrade() ran %d commands, want 1", len(r.Calls))
	}
	if !strings.Contains(out.String(), "go install github.com/tplAIter/tplaiter@latest") {
		t.Errorf("Upgrade() output = %q, want it to mention the go install command", out.String())
	}
}

func TestUpgrade_GoInstall_MissingModulePath(t *testing.T) {
	r := execx.NewRecordingRunner()
	var out bytes.Buffer
	err := Upgrade(context.Background(), r, ChannelGoInstall, "", &out)
	if err == nil {
		t.Fatal("Upgrade() error = nil, want error for empty modulePath")
	}
	if len(r.Calls) != 0 {
		t.Errorf("Upgrade() ran %d commands, want 0 (should fail before invoking go)", len(r.Calls))
	}
}

func TestUpgrade_GoInstall_RunnerError(t *testing.T) {
	r := execx.NewRecordingRunner()
	wantErr := errors.New("exit code 1")
	r.OnCommand("go", execx.Response{Err: wantErr})

	var out bytes.Buffer
	err := Upgrade(context.Background(), r, ChannelGoInstall, "example.com/mod", &out)
	if err == nil {
		t.Fatal("Upgrade() error = nil, want non-nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Upgrade() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestUpgrade_Brew(t *testing.T) {
	r := execx.NewRecordingRunner()
	var out bytes.Buffer
	if err := Upgrade(context.Background(), r, ChannelBrew, "", &out); err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if len(r.Calls) != 0 {
		t.Errorf("Upgrade() ran %d commands for brew channel, want 0 (instruction only)", len(r.Calls))
	}
	if !strings.Contains(out.String(), "brew upgrade tplaiter") {
		t.Errorf("Upgrade() output = %q, want brew instruction", out.String())
	}
}

func TestUpgrade_Unknown(t *testing.T) {
	r := execx.NewRecordingRunner()
	var out bytes.Buffer
	if err := Upgrade(context.Background(), r, ChannelUnknown, "example.com/mod", &out); err != nil {
		t.Fatalf("Upgrade() error = %v", err)
	}
	if len(r.Calls) != 0 {
		t.Errorf("Upgrade() ran %d commands for unknown channel, want 0 (instructions only)", len(r.Calls))
	}
	got := out.String()
	if !strings.Contains(got, "go install example.com/mod@latest") || !strings.Contains(got, "brew upgrade tplaiter") {
		t.Errorf("Upgrade() output = %q, want both go install and brew instructions", got)
	}
}
