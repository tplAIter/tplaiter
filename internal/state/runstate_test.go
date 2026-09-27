package state

import (
	"testing"
	"time"
)

func TestLoadRunState_MissingFileReturnsDefault(t *testing.T) {
	home := t.TempDir()

	got, err := LoadRunState(home)
	if err != nil {
		t.Fatalf("LoadRunState() error = %v", err)
	}
	if got != DefaultRunState() {
		t.Errorf("LoadRunState() = %+v, want default %+v", got, DefaultRunState())
	}
	if !got.LastUpdateCheck.IsZero() {
		t.Errorf("DefaultRunState().LastUpdateCheck = %v, want zero", got.LastUpdateCheck)
	}
}

func TestRunState_SaveLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	checked := time.Date(2026, 7, 11, 9, 30, 0, 0, time.UTC)
	s := RunState{Version: RunStateVersion, LastUpdateCheck: checked}

	if err := SaveRunState(home, s); err != nil {
		t.Fatalf("SaveRunState() error = %v", err)
	}

	got, err := LoadRunState(home)
	if err != nil {
		t.Fatalf("LoadRunState() error = %v", err)
	}
	if !got.LastUpdateCheck.Equal(checked) {
		t.Errorf("LoadRunState() LastUpdateCheck = %v, want %v", got.LastUpdateCheck, checked)
	}
}

func TestLoadRunState_FutureVersionErrors(t *testing.T) {
	home := t.TempDir()
	writeRaw(t, home, runStateFileName, "version: 42\n")

	if _, err := LoadRunState(home); err == nil {
		t.Fatal("LoadRunState() with future version = nil error, want error")
	}
}
