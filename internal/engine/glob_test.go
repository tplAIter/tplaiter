package engine

import "testing"

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"internal/infra/db/**", "internal/infra/db/doc.go", true},
		{"internal/infra/db/**", "internal/infra/db/sub/x.go", true},
		{"internal/infra/db/**", "internal/infra/dbx/x.go", false},
		{"dashboards/*.json", "dashboards/app.json", true},
		{"dashboards/*.json", "dashboards/sub/app.json", false},
		{"**/dashboards/*.json", "a/b/dashboards/app.json", true},
		{"**/dashboards/*.json", "dashboards/app.json", true},
		{"*.go", "main.go", true},
		{"*.go", "cmd/main.go", false},
		{"integrations/**", "integrations/common.txt", true},
		{"integrations/**", "integrations/nested/x.txt", true},
		{"integrations/**", "other/common.txt", false},
	}
	for _, c := range cases {
		if got := globToRegexp(c.glob).MatchString(c.path); got != c.want {
			t.Errorf("glob %q vs %q = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

func TestGlobSetMatchAny(t *testing.T) {
	gs := newGlobSet([]string{"a/**", "*.json"})
	if !gs.matchAny("a/b/c.txt") {
		t.Error("expected a/** to match a/b/c.txt")
	}
	if !gs.matchAny("root.json") {
		t.Error("expected *.json to match root.json")
	}
	if gs.matchAny("b/root.json") {
		t.Error("*.json should not cross a segment boundary")
	}

	empty := newGlobSet(nil)
	if empty.matchAny("anything") {
		t.Error("empty globSet should never match")
	}
}
