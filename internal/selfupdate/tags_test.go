package selfupdate

import (
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
)

func TestParseLatestTag(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "empty output",
			output: "",
			want:   "",
		},
		{
			name: "picks highest semver, ignores non-v refs and dereferenced tags",
			output: "" +
				"aaa\trefs/tags/v1.0.0\n" +
				"bbb\trefs/tags/v1.2.0\n" +
				"bbb\trefs/tags/v1.2.0^{}\n" +
				"ccc\trefs/tags/not-a-version\n" +
				"ddd\trefs/heads/main\n" +
				"eee\trefs/tags/v1.10.0\n" +
				"fff\trefs/tags/v1.3.0\n",
			want: "v1.10.0",
		},
		{
			name:   "single malformed line is skipped, not fatal",
			output: "not-two-fields\n",
			want:   "",
		},
		{
			name:   "prerelease tags parse but lose to stable",
			output: "aaa\trefs/tags/v2.0.0-rc1\nbbb\trefs/tags/v1.9.0\n",
			want:   "v2.0.0-rc1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseLatestTag(c.output); got != c.want {
				t.Errorf("parseLatestTag() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestLatestTag_UsesRunner(t *testing.T) {
	r := execx.NewRecordingRunner()
	r.On("git", []string{"ls-remote", "--tags", "https://example.invalid/tplater.git"}, execx.Response{
		Result: execx.Result{Stdout: "aaa\trefs/tags/v0.3.0\nbbb\trefs/tags/v0.4.1\n"},
	})

	got, err := LatestTag(context.Background(), r, "https://example.invalid/tplater.git")
	if err != nil {
		t.Fatalf("LatestTag() error = %v", err)
	}
	if got != "v0.4.1" {
		t.Errorf("LatestTag() = %q, want v0.4.1", got)
	}
}

func TestLatestTag_RunnerError(t *testing.T) {
	r := execx.NewRecordingRunner()
	wantErr := errors.New("network unreachable")
	r.On("git", []string{"ls-remote", "--tags", "https://example.invalid/tplater.git"}, execx.Response{Err: wantErr})

	_, err := LatestTag(context.Background(), r, "https://example.invalid/tplater.git")
	if err == nil {
		t.Fatal("LatestTag() error = nil, want non-nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("LatestTag() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    CompareResult
	}{
		{"outdated", "v1.0.0", "v1.1.0", CompareOutdated},
		{"up to date", "v1.1.0", "v1.1.0", CompareUpToDate},
		{"up to date without v prefix on current", "1.1.0", "v1.1.0", CompareUpToDate},
		{"ahead", "v2.0.0", "v1.1.0", CompareAhead},
		{"unknown current (dev)", "dev", "v1.1.0", CompareUnknown},
		{"unknown latest (empty)", "v1.0.0", "", CompareUnknown},
		{"both unknown", "dev", "", CompareUnknown},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Compare(c.current, c.latest); got != c.want {
				t.Errorf("Compare(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
			}
		})
	}
}
