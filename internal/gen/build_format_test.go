package gen

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

func TestRunPostFormatFallsBackToGofmt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	runner := execx.NewRecordingRunner().
		SetLookPath("gofmt", "/go/bin/gofmt").
		On("/go/bin/gofmt", []string{"-w", "/project/a.go"}, execx.Response{})

	runPostFormat(context.Background(), Options{
		ProjectRoot: "/project",
		Runner:      runner,
	}, []string{"/project/a.go", "/project/readme.md"}, func(string, ...any) {})

	if len(runner.Calls) != 1 {
		t.Fatalf("formatter calls = %d, want 1", len(runner.Calls))
	}
	call := runner.Calls[0]
	if call.Name != "/go/bin/gofmt" ||
		!reflect.DeepEqual(call.Args, []string{"-w", "/project/a.go"}) ||
		call.Opts.Dir != filepath.Clean("/project") {
		t.Fatalf("formatter call = %#v", call)
	}
}

func TestFindFormatterPrefersGofumpt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	runner := execx.NewRecordingRunner().
		SetLookPath("gofumpt", "/go/bin/gofumpt").
		SetLookPath("gofmt", "/go/bin/gofmt")

	path, name, ok := findFormatter(runner)
	if !ok || path != "/go/bin/gofumpt" || name != "gofumpt" {
		t.Fatalf("findFormatter = %q, %q, %v", path, name, ok)
	}
}
