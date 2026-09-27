package repo

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
)

func TestDetectKind(t *testing.T) {
	tests := []struct {
		url  string
		want state.RepoKind
	}{
		{"https://gitlab.com/group/repo.git", state.RepoKindGitLab},
		{"https://gitlab.example.test/idp/tpl.git", state.RepoKindGitLab},
		{"https://github.com/tplAIter/tplaiter.git", state.RepoKindGitHub},
		{"git@gitlab.example.test:idp/tpl.git", state.RepoKindGitLab},
		{"https://github.com/org/repo.git", state.RepoKindGitHub},
		{"https://github.enterprise.local/org/repo.git", state.RepoKindGitHub},
		{"git@github.com:org/repo.git", state.RepoKindGitHub},
		{"https://bitbucket.org/team/repo.git", state.RepoKindGit},
		{"ssh://git@example.com/repo.git", state.RepoKindGit},
		{"file:///tmp/repo", state.RepoKindGit},
	}
	for _, tt := range tests {
		host, _ := parseGitURL(tt.url)
		if got := detectKind(host); got != tt.want {
			t.Errorf("detectKind(%q) host=%q = %q, want %q", tt.url, host, got, tt.want)
		}
	}
}

func TestParseGitURL(t *testing.T) {
	tests := []struct {
		url      string
		wantHost string
		wantPath string
	}{
		{"https://gitlab.com/group/repo.git", "gitlab.com", "group/repo"},
		{"https://github.com/tplAIter/tplaiter.git", "github.com", "tplAIter/tplaiter"},
		{"http://host/a/b/", "host", "a/b"},
		{"git@github.com:org/repo.git", "github.com", "org/repo"},
		{"ssh://git@example.com:2222/team/repo.git", "example.com", "team/repo"},
		{"file:///tmp/repo", "", "tmp/repo"},
	}
	for _, tt := range tests {
		host, path := parseGitURL(tt.url)
		if host != tt.wantHost || path != tt.wantPath {
			t.Errorf("parseGitURL(%q) = (%q, %q), want (%q, %q)", tt.url, host, path, tt.wantHost, tt.wantPath)
		}
	}
}

func TestValidateAlias(t *testing.T) {
	valid := []string{"a", "example", "example-templates", "go-service", "a1b2"}
	invalid := []string{"", "1abc", "-abc", "Abc", "abc_def", "abc.def", "abc/def", "ABC", "abc "}
	for _, a := range valid {
		if err := validateAlias(a); err != nil {
			t.Errorf("validateAlias(%q) = %v, want nil", a, err)
		}
	}
	for _, a := range invalid {
		if err := validateAlias(a); err == nil {
			t.Errorf("validateAlias(%q) = nil, want error", a)
		}
	}
}

func TestIsHTTPURL(t *testing.T) {
	yes := []string{"https://x/y", "http://x/y"}
	no := []string{"git@x:y", "ssh://git@x/y", "file:///tmp/x"}
	for _, u := range yes {
		if !isHTTPURL(u) {
			t.Errorf("isHTTPURL(%q) = false, want true", u)
		}
	}
	for _, u := range no {
		if isHTTPURL(u) {
			t.Errorf("isHTTPURL(%q) = true, want false", u)
		}
	}
}

func TestStableTagsFor(t *testing.T) {
	all := []string{"v1.0.0", "v1.1.0", "v2.0.0-rc1", "svc/v0.1.0", "other/v9.9.9", "not-a-tag"}

	// single: только `vX.Y.Z` без «/», без пре-релизов, по убыванию.
	single := stableTagsFor(all, "whatever", false)
	if want := []string{"v1.1.0", "v1.0.0"}; !equalStrings(single, want) {
		t.Errorf("single tags = %v, want %v", single, want)
	}

	// multi: только `svc/vX.Y.Z`.
	multi := stableTagsFor(all, "svc", true)
	if want := []string{"svc/v0.1.0"}; !equalStrings(multi, want) {
		t.Errorf("multi tags = %v, want %v", multi, want)
	}

	// multi для несуществующего имени → пусто.
	if got := stableTagsFor(all, "nope", true); len(got) != 0 {
		t.Errorf("multi tags for unknown = %v, want empty", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
