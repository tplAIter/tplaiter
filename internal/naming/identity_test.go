package naming

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestResolveHomeCompatibility(t *testing.T) {
	get := func(v map[string]string) func(string) string { return func(k string) string { return v[k] } }
	if got, _ := ResolveHome(get(map[string]string{HomeEnv: "/tmp/new"}), "/home/u"); got != "/tmp/new" {
		t.Fatalf("modern home = %q", got)
	}
	if got, _ := ResolveHome(get(map[string]string{LegacyHomeEnv: "/tmp/old"}), "/home/u"); got != "/tmp/old" {
		t.Fatalf("legacy home = %q", got)
	}
	if _, err := ResolveHome(get(map[string]string{HomeEnv: "/tmp/a", LegacyHomeEnv: "/tmp/b"}), "/home/u"); !errors.Is(err, ErrAmbiguousHome) {
		t.Fatalf("distinct homes error = %v", err)
	}
	if got, _ := ResolveHome(get(map[string]string{}), "/home/u"); got != filepath.Join("/home/u", HomeDir) {
		t.Fatalf("default home = %q", got)
	}
}
