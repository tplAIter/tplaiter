package gen

import (
	"context"
	"errors"
	"testing"
)

func TestRunPostFormatFallsBackToGofmt(t *testing.T) {
	err := runPostFormat(context.Background(), Options{
		ProjectRoot: "/project",
	}, []string{"/project/a.go", "/project/readme.md"}, func(string, ...any) {})

	if !errors.Is(err, ErrExecutionUnavailable) {
		t.Fatalf("runPostFormat error = %v", err)
	}
}

func TestFindFormatterPrefersGofumpt(t *testing.T) {
	path, name, err := findFormatter()
	if !errors.Is(err, ErrExecutionUnavailable) || path != "" || name != "" {
		t.Fatalf("findFormatter = %q, %q, %v", path, name, err)
	}
}
