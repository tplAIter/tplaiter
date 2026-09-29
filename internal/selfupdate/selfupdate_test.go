package selfupdate

import (
	"runtime/debug"
	"testing"
)

func TestDetectChannel(t *testing.T) {
	goBinDirs := []string{"/home/dev/go/bin", "/home/dev/gopath/bin"}

	cases := []struct {
		name    string
		exePath string
		info    *debug.BuildInfo
		want    Channel
	}{
		{
			name:    "go install bin dir (HOME/go/bin)",
			exePath: "/home/dev/go/bin/tplater",
			info:    nil,
			want:    ChannelGoInstall,
		},
		{
			name:    "go install bin dir (GOPATH/bin)",
			exePath: "/home/dev/gopath/bin/tplater",
			info:    nil,
			want:    ChannelGoInstall,
		},
		{
			name:    "brew apple silicon",
			exePath: "/opt/homebrew/Cellar/tplater/1.2.3/bin/tplater",
			info:    nil,
			want:    ChannelBrew,
		},
		{
			name:    "brew intel cellar",
			exePath: "/usr/local/Cellar/tplater/1.2.3/bin/tplater",
			info:    nil,
			want:    ChannelBrew,
		},
		{
			name:    "unrecognized path, no build info",
			exePath: "/usr/local/bin/tplater",
			info:    nil,
			want:    ChannelUnknown,
		},
		{
			name:    "unrecognized path, devel build info",
			exePath: "/usr/local/bin/tplater",
			info:    &debug.BuildInfo{Main: debug.Module{Path: "github.com/tplAIter/tplaiter", Version: "(devel)"}},
			want:    ChannelUnknown,
		},
		{
			name:    "unrecognized path, tagged module version falls back to go-install",
			exePath: "/usr/local/bin/tplater",
			info:    &debug.BuildInfo{Main: debug.Module{Path: "github.com/tplAIter/tplaiter", Version: "v1.2.3"}},
			want:    ChannelGoInstall,
		},
		{
			name:    "empty exe path falls back to build info",
			exePath: "",
			info:    &debug.BuildInfo{Main: debug.Module{Path: "github.com/tplAIter/tplaiter", Version: "v1.2.3"}},
			want:    ChannelGoInstall,
		},
		{
			name:    "nothing recognized at all",
			exePath: "",
			info:    nil,
			want:    ChannelUnknown,
		},
		{
			name:    "brew path wins over goBinDirs mismatch",
			exePath: "/opt/homebrew/bin/tplater",
			info:    &debug.BuildInfo{Main: debug.Module{Path: "x", Version: "v9.9.9"}},
			want:    ChannelBrew,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := detectChannel(c.exePath, c.info, goBinDirs); got != c.want {
				t.Errorf("detectChannel(%q) = %q, want %q", c.exePath, got, c.want)
			}
		})
	}
}

func TestChannelLabel(t *testing.T) {
	cases := map[Channel]string{
		ChannelGoInstall: "go install",
		ChannelBrew:      "brew",
		ChannelUnknown:   "unknown",
		Channel("bogus"): "unknown",
	}
	for ch, want := range cases {
		if got := ch.Label(); got != want {
			t.Errorf("Channel(%q).Label() = %q, want %q", ch, got, want)
		}
	}
}

func TestRepoURL_EnvOverride(t *testing.T) {
	if got := RepoURL(); got != DefaultRepoURL {
		t.Fatalf("RepoURL() without env = %q, want %q", got, DefaultRepoURL)
	}

	t.Setenv(RepoEnv, "file:///tmp/fake-repo.git")
	if got := RepoURL(); got != "file:///tmp/fake-repo.git" {
		t.Errorf("RepoURL() with %s set = %q, want override", RepoEnv, got)
	}
}
