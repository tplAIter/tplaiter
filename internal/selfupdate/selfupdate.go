// Package selfupdate implements tplaiter CLI self-updates: detecting the install
// channel, comparing versions with the canonical repository through
// `git ls-remote --tags`, performing updates, and a quiet background suggest
// check every 24h.
//
// All external processes (git, go install) run through
// [github.com/tplAIter/tplaiter/internal/execx.Runner]; the package does not
// call os/exec directly, keeping it unit-testable.
package selfupdate

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// Channel is the channel through which the current tplaiter binary was installed.
type Channel string

// Supported installation channels (go install is primary, brew is additional or
// future, unknown means the source was not recognized, such as a manually
// copied binary or a local `go build`).
const (
	ChannelGoInstall Channel = "go-install"
	ChannelBrew      Channel = "brew"
	ChannelUnknown   Channel = "unknown"
)

// Label returns the human-readable channel name for `tplaiter version`.
func (c Channel) Label() string {
	switch c {
	case ChannelGoInstall:
		return "go install"
	case ChannelBrew:
		return "brew"
	default:
		return "unknown"
	}
}

// RepoEnv overrides the canonical tplaiter repository URL for version checks and
// module builds. Tests use it to avoid real network access; it is also a
// temporary workaround if [DefaultRepoURL] is wrong before release.
const RepoEnv = "TPLAITER_SELF_REPO"

// DefaultRepoURL is the canonical tplaiter git repository used for
// `git ls-remote --tags` when checking versions.
//
// The URL is owner-confirmed (and matches the module path in go.mod), but is a
// separate constant rather than derived from BuildInfo.Main.Path: the template
// repository and CLI repository may diverge in the future.
const DefaultRepoURL = "https://github.com/tplAIter/tplaiter.git"

// RepoURL returns the canonical tplaiter repository URL: [RepoEnv] when set,
// otherwise [DefaultRepoURL].
func RepoURL() string {
	if v := os.Getenv(RepoEnv); v != "" {
		return v
	}
	return DefaultRepoURL
}

// brewPathMarkers are path fragments characteristic of a Homebrew installation
// on macOS (Apple Silicon /opt/homebrew, Intel /usr/local/Cellar). Linuxbrew
// (~/.linuxbrew, /home/linuxbrew) is intentionally excluded because it is not a
// target platform.
var brewPathMarkers = []string{"/opt/homebrew/", "/usr/local/Cellar/"}

// DetectChannel determines how the current tplaiter executable was installed:
// from its path (go install places binaries in $GOPATH/bin or $HOME/go/bin,
// brew in /opt/homebrew or /usr/local/Cellar), and, when the path is unknown
// (for example, a binary copied or symlinked into an arbitrary PATH directory),
// from [debug.ReadBuildInfo] — `go install
// module@version` sets the actual module version (not "(devel)").
func DetectChannel() Channel {
	exePath, err := os.Executable()
	if err != nil {
		exePath = ""
	}
	info, _ := debug.ReadBuildInfo()
	return detectChannel(exePath, info, goInstallBinDirs())
}

// goInstallBinDirs returns candidate directories where `go install` places
// binaries: $GOPATH/bin for each GOPATH element (the environment variable may
// contain multiple paths separated by [filepath.ListSeparator]) and $HOME/go/bin,
// Go's default when GOPATH is not explicitly set.
func goInstallBinDirs() []string {
	var dirs []string
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, p := range filepath.SplitList(gopath) {
			if p != "" {
				dirs = append(dirs, filepath.Join(p, "bin"))
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	return dirs
}

// detectChannel is the pure function extracted from [DetectChannel] for unit
// tests: it accepts the computed binary path, BuildInfo, and $GOPATH/bin
// candidates explicitly instead of reading the environment or os.
func detectChannel(exePath string, info *debug.BuildInfo, goBinDirs []string) Channel {
	if exePath != "" {
		for _, marker := range brewPathMarkers {
			if strings.Contains(exePath, marker) {
				return ChannelBrew
			}
		}
		dir := filepath.Dir(exePath)
		for _, d := range goBinDirs {
			if d != "" && dir == d {
				return ChannelGoInstall
			}
		}
	}

	// BuildInfo fallback: the path matches no known directory (the binary was
	// moved or symlinked), but the module version is real—possible only when the
	// binary was installed through `go install
	// module@version` (ordinary `go build` leaves Main.Version == "(devel)").
	if info != nil && info.Main.Path != "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return ChannelGoInstall
	}
	return ChannelUnknown
}
