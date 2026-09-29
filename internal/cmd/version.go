package cmd

import (
	"fmt"
	"path/filepath"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/selfupdate"
	"github.com/tplAIter/tplaiter/internal/state"
)

// version — CLI version. The linker sets it in release builds
// (-ldflags "-X .../internal/cmd.version=vX.Y.Z", see Makefile). If empty
// (local `go build .` / `go run .`), the version is resolved through
// runtime/debug.BuildInfo — with `go install module@vX.Y.Z`, Go sets
// info.Main.Version automatically. If that is unavailable too, print "dev".
var version = ""

// resolveVersion returns the CLI version in priority order:
// ldflags variable -> runtime/debug.BuildInfo -> "dev".
func resolveVersion() string {
	if version != "" {
		return version
	}
	if v := buildInfoVersion(debug.ReadBuildInfo); v != "" {
		return v
	}
	return "dev"
}

// buildInfoVersion extracts the module version from BuildInfo. It accepts a
// reader function for testing (without a real go install build).
func buildInfoVersion(read func() (*debug.BuildInfo, bool)) string {
	info, ok := read()
	if !ok {
		return ""
	}
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}

// unknownRevision — placeholder when the commit hash is unavailable (for
// example, a local build without VCS metadata; see [buildRevision]).
const unknownRevision = "unknown"

// buildRevision extracts vcs.revision (short commit hash) from
// BuildInfo.Settings — Go sets it automatically when building from VCS
// (go install/go build inside a git repository). It accepts a reader like
// [buildInfoVersion] for testing without a real build.
func buildRevision(read func() (*debug.BuildInfo, bool)) string {
	info, ok := read()
	if !ok {
		return unknownRevision
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	return unknownRevision
}

// newVersionCmd creates `tplaiter version`: version, commit, installation
// channel (see internal/selfupdate.DetectChannel), and config path
// (~/.tplaiter/config.yaml or TPLAITER_HOME).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Annotations: prerunAnnotations(prerunReadonly),

		Use:   "version",
		Short: "Show tplaiter version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, resolveVersion())
			fmt.Fprintln(out, "commit:", buildRevision(debug.ReadBuildInfo))
			fmt.Fprintln(out, "installation channel:", selfupdate.DetectChannel().Label())
			if home, err := state.Home(); err == nil {
				fmt.Fprintln(out, "config:", filepath.Join(home, "config.yaml"))
			}
			return nil
		},
	}
}
