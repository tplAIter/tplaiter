package cmd

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/state"
)

func TestBuildInfoVersion(t *testing.T) {
	cases := []struct {
		name string
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		{
			name: "no build info",
			read: func() (*debug.BuildInfo, bool) { return nil, false },
			want: "",
		},
		{
			name: "devel placeholder",
			read: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true
			},
			want: "",
		},
		{
			name: "tagged module version",
			read: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
			},
			want: "v1.2.3",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildInfoVersion(c.read); got != c.want {
				t.Errorf("buildInfoVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestResolveVersion_LdflagsWins(t *testing.T) {
	old := version
	defer func() { version = old }()

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Errorf("resolveVersion() = %q, want v9.9.9", got)
	}
}

func TestResolveVersion_FallbackDev(t *testing.T) {
	old := version
	defer func() { version = old }()

	version = ""
	// In `go test`, BuildInfo.Main.Version is usually empty/"(devel)", so expect dev.
	got := resolveVersion()
	if got == "" {
		t.Error("resolveVersion() must never return empty string")
	}
}

func TestBuildRevision(t *testing.T) {
	cases := []struct {
		name string
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		{
			name: "no build info",
			read: func() (*debug.BuildInfo, bool) { return nil, false },
			want: unknownRevision,
		},
		{
			name: "no vcs.revision setting",
			read: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}}}, true
			},
			want: unknownRevision,
		},
		{
			name: "empty vcs.revision value",
			read: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: ""}}}, true
			},
			want: unknownRevision,
		},
		{
			name: "vcs.revision present",
			read: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc1234"}}}, true
			},
			want: "abc1234",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildRevision(c.read); got != c.want {
				t.Errorf("buildRevision() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestNewVersionCmd_PrintsVersionCommitChannelAndConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)

	old := version
	version = "v1.2.3"
	defer func() { version = old }()

	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("newVersionCmd().Execute() error = %v", err)
	}

	got := out.String()
	for _, want := range []string{"v1.2.3", "commit:", "installation channel:", "config:", home} {
		if !strings.Contains(got, want) {
			t.Errorf("newVersionCmd() output = %q, want it to contain %q", got, want)
		}
	}
}

func TestNewVersionCmd_RejectsArgs(t *testing.T) {
	cmd := newVersionCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"extra"})

	if err := cmd.Execute(); err == nil {
		t.Error("newVersionCmd().Execute() with an extra arg error = nil, want error (Args: cobra.NoArgs)")
	}
}
