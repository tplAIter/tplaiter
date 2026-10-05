package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
)

func scriptLsRemote(r *execx.RecordingRunner, repoURL, output string) {
	r.On("git", []string{"ls-remote", "--tags", repoURL}, execx.Response{Result: execx.Result{Stdout: output}})
}

func TestMaybeSuggest_PrintsWhenOutdated(t *testing.T) {
	home := t.TempDir()
	r := execx.NewRecordingRunner()
	scriptLsRemote(r, RepoURL(), "aaa\trefs/tags/v9.9.9\n")

	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", time.Now(), &out)

	if !strings.Contains(out.String(), "v9.9.9") || !strings.Contains(out.String(), "tplaiter --upgrade") {
		t.Errorf("MaybeSuggest() output = %q, want mention of v9.9.9 and tplaiter --upgrade", out.String())
	}

	rs, err := state.LoadRunState(home)
	if err != nil {
		t.Fatalf("LoadRunState() error = %v", err)
	}
	if rs.LastUpdateCheck.IsZero() {
		t.Error("MaybeSuggest() did not persist LastUpdateCheck")
	}
}

func TestMaybeSuggest_SilentWhenUpToDate(t *testing.T) {
	home := t.TempDir()
	r := execx.NewRecordingRunner()
	scriptLsRemote(r, RepoURL(), "aaa\trefs/tags/v1.0.0\n")

	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", time.Now(), &out)

	if out.Len() != 0 {
		t.Errorf("MaybeSuggest() printed %q, want silence when up to date", out.String())
	}
}

func TestMaybeSuggest_24hGate(t *testing.T) {
	home := t.TempDir()
	now := time.Now()

	if err := state.SaveRunState(home, state.RunState{Version: state.RunStateVersion, LastUpdateCheck: now.Add(-1 * time.Hour)}); err != nil {
		t.Fatalf("SaveRunState() error = %v", err)
	}

	r := execx.NewRecordingRunner()
	scriptLsRemote(r, RepoURL(), "aaa\trefs/tags/v9.9.9\n")

	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", now, &out)

	if out.Len() != 0 {
		t.Errorf("MaybeSuggest() printed %q within 24h of last check, want silence", out.String())
	}
	if len(r.Calls) != 0 {
		t.Errorf("MaybeSuggest() made %d network calls within 24h gate, want 0", len(r.Calls))
	}
}

func TestMaybeSuggest_24hGate_ChecksAgainAfterInterval(t *testing.T) {
	home := t.TempDir()
	now := time.Now()

	if err := state.SaveRunState(home, state.RunState{Version: state.RunStateVersion, LastUpdateCheck: now.Add(-25 * time.Hour)}); err != nil {
		t.Fatalf("SaveRunState() error = %v", err)
	}

	r := execx.NewRecordingRunner()
	scriptLsRemote(r, RepoURL(), "aaa\trefs/tags/v9.9.9\n")

	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", now, &out)

	if out.Len() == 0 {
		t.Error("MaybeSuggest() stayed silent after 24h+ gap, want suggestion")
	}
}

func TestMaybeSuggest_DisabledByConfig(t *testing.T) {
	home := t.TempDir()
	if err := state.SaveConfig(home, state.Config{Version: state.ConfigVersion, Updates: state.UpdatesSettings{Check: false}}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	r := execx.NewRecordingRunner()
	// Do not register any ls-remote script: the call must not even be attempted
	// when updates.check=false.
	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", time.Now(), &out)

	if out.Len() != 0 {
		t.Errorf("MaybeSuggest() printed %q with updates.check=false, want silence", out.String())
	}
	if len(r.Calls) != 0 {
		t.Errorf("MaybeSuggest() made %d network calls with updates.check=false, want 0", len(r.Calls))
	}
}

func TestMaybeSuggest_NetworkErrorSwallowedSilently(t *testing.T) {
	home := t.TempDir()
	r := execx.NewRecordingRunner()
	r.On("git", []string{"ls-remote", "--tags", RepoURL()}, execx.Response{Err: errors.New("network unreachable")})

	var out bytes.Buffer
	MaybeSuggest(context.Background(), r, home, "v1.0.0", time.Now(), &out)

	if out.Len() != 0 {
		t.Errorf("MaybeSuggest() printed %q on network error, want silence", out.String())
	}

	// The timestamp must still advance: a failed check is not repeated on every
	// subsequent launch (see suggest.go).
	rs, err := state.LoadRunState(home)
	if err != nil {
		t.Fatalf("LoadRunState() error = %v", err)
	}
	if rs.LastUpdateCheck.IsZero() {
		t.Error("MaybeSuggest() did not persist LastUpdateCheck despite network error")
	}
}
