package update

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/repo"
)

func TestRunDeniesLegacyRoutesBeforeProjectOrHomeAccess(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-project")
	home := filepath.Join(t.TempDir(), "home")
	for _, opts := range []Options{
		{StartDir: missing},
		{StartDir: missing, DryRun: true},
		{StartDir: missing, All: true},
		{StartDir: missing, All: true, Check: true},
	} {
		err := Run(context.Background(), Deps{Home: home}, opts)
		if !errors.Is(err, ErrLifecycleUnavailable) {
			t.Fatalf("Run(%+v) error = %v", opts, err)
		}
		if _, statErr := os.Stat(home); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("legacy Run touched home: %v", statErr)
		}
	}
}

func TestCheckIsLocalOnlyAndPlanApplyCannotWrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "conflict.txt"), []byte("<<<<<<< local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Deps{Out: io.Discard, Err: io.Discard}, Options{StartDir: root, Check: true})
	var exit *ExitCodeError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("local --check error = %v", err)
	}
	output := filepath.Join(root, "would-write.txt")
	plan := &Plan{Actions: []Action{{Path: filepath.Base(output), Op: OpWrite, Content: []byte("forbidden")}}}
	if _, err := plan.Apply(root); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("Plan.Apply error = %v", err)
	}
	if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Plan.Apply wrote output: %v", statErr)
	}
}

func TestApplyUpdateDeniesBeforeLegacyWrites(t *testing.T) {
	root := t.TempDir()
	if err := applyUpdate(context.Background(), Deps{}, root, nil, &Plan{}, nil, nil, repo.Resolved{}); !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("applyUpdate error = %v", err)
	}
}
