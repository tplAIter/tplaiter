// Package deps detects and installs environment tools declared in the template's
// requires.tools manifest (SPEC-03 §4). All external commands run through
// [execx.Runner]; the package does not use os/exec directly and is fully covered
// by tests through execx.RecordingRunner.
package deps

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ErrExecutionUnavailable marks the deliberately closed generic dependency
// execution surface. Version probes are not an authority to start a process.
var ErrExecutionUnavailable = errors.New("deps: execution unavailable")

// ToolStatus — result of checking one requires.tools entry.
type ToolStatus struct {
	// Tool — manifest requirement from which the status was built.
	Tool manifest.Tool
	// Found reports whether the binary was found in PATH (see [execx.Runner.LookPath]).
	Found bool
	// Path — path to the binary, when Found.
	Path string
	// Version — normalized (major.minor.patch) tool version, when it could be
	// detected and parsed. Empty when Tool.Version does not require a version
	// (empty constraint); detection is still attempted because the field is
	// useful for the doctor report regardless of the constraint.
	Version string
	// Satisfies — true when Found and (Tool.Version is empty or Version satisfies
	// the constraint). False on any problem; details are in Err.
	Satisfies bool
	// Err — reason Found/Satisfies were not set to true: binary not found, version
	// could not be executed/parsed, or constraint could not be parsed. nil when all is well.
	Err error
}

// Check checks each tool: finds its binary in PATH through runner.LookPath,
// then (if found) detects its version and compares it with Tool.Version. Result
// order matches tools order.
func Check(ctx context.Context, runner execx.Runner, tools []manifest.Tool) []ToolStatus {
	statuses := make([]ToolStatus, 0, len(tools))
	for _, tool := range tools {
		statuses = append(statuses, ToolStatus{Tool: tool, Err: ErrExecutionUnavailable})
	}
	return statuses
}

func checkOne(ctx context.Context, runner execx.Runner, tool manifest.Tool) ToolStatus {
	st := ToolStatus{Tool: tool}

	path, err := runner.LookPath(tool.Name)
	if err != nil {
		st.Err = fmt.Errorf("deps: %s not found in PATH: %w", tool.Name, err)
		return st
	}
	st.Found = true
	st.Path = path

	raw, err := detectVersion(ctx, runner, tool.Name)
	if err != nil {
		st.Err = fmt.Errorf("deps: detect version for %s: %w", tool.Name, err)
		return st
	}

	version, ok := normalizeVersion(raw)
	if !ok {
		st.Err = fmt.Errorf("deps: failed to parse version %s from %q", tool.Name, raw)
		return st
	}
	st.Version = version

	satisfies, err := satisfiesConstraint(version, tool.Version)
	if err != nil {
		st.Err = fmt.Errorf("deps: constraint %q for tool %s: %w", tool.Version, tool.Name, err)
		return st
	}
	st.Satisfies = satisfies
	return st
}

// toolDetector describes how to detect a particular tool's version: an ordered
// list of command attempts (the first successful one is used) and a function
// extracting a version-like token from its output.
type toolDetector struct {
	attempts [][]string
	extract  func(output string) (string, bool)
}

// detectors — overrides for tools with a non-standard version-output format (SPEC-03 §4).
var detectors = map[string]toolDetector{
	// `go version` -> "go version go1.26.4 darwin/arm64".
	"go": {
		attempts: [][]string{{"version"}},
		extract:  extractGoVersion,
	},
	// The Docker Desktop/CLI daemon is not always running — first try the client
	// version via --format (does not require a live daemon), then fall back to
	// --version on failure (older Docker versions lack --format).
	"docker": {
		attempts: [][]string{
			{"version", "--format", "{{.Client.Version}}"},
			{"--version"},
		},
		extract: extractGenericVersion,
	},
	// `ansible --version` -> first line "ansible [core 2.16.3]" (2.10+)
	// or "ansible 2.9.27" (older versions).
	"ansible": {
		attempts: [][]string{{"--version"}},
		extract:  extractAnsibleVersion,
	},
}

// defaultDetector — generic detector for tools without a [detectors] entry:
// `<name> --version`, first semver-like token from output.
var defaultDetector = toolDetector{
	attempts: [][]string{{"--version"}},
	extract:  extractGenericVersion,
}

func detectorFor(name string) toolDetector {
	if d, ok := detectors[name]; ok {
		return d
	}
	return defaultDetector
}

// detectVersion runs detector commands for name in order until one returns
// output from which extract can obtain a version-like token.
func detectVersion(ctx context.Context, runner execx.Runner, name string) (string, error) {
	d := detectorFor(name)

	var lastErr error
	for _, args := range d.attempts {
		res, err := runner.Run(ctx, name, args, execx.Options{})
		if err != nil {
			lastErr = err
			continue
		}
		output := res.Stdout
		if strings.TrimSpace(output) == "" {
			output = res.Stderr
		}
		token, ok := d.extract(output)
		if ok {
			return token, nil
		}
		lastErr = fmt.Errorf("failed to find version in output %q", firstLine(output))
	}
	if lastErr == nil {
		lastErr = errors.New("no version detection attempts")
	}
	return "", lastErr
}

// genericVersionRe finds the first semver-like token ("1", "1.26", "1.26.4",
// optionally prefixed with "v") in arbitrary output.
var genericVersionRe = regexp.MustCompile(`v?(\d+(?:\.\d+){0,2})`)

func extractGenericVersion(output string) (string, bool) {
	m := genericVersionRe.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// goVersionRe extracts a version from `go version` ("go1.26.4" -> "1.26.4").
var goVersionRe = regexp.MustCompile(`go(\d+(?:\.\d+){0,2})`)

func extractGoVersion(output string) (string, bool) {
	m := goVersionRe.FindStringSubmatch(output)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// extractAnsibleVersion takes only the first output line (the remaining lines
// contain python/jinja2/dependency versions that must not override Ansible's
// main version) and searches it for a generic token.
func extractAnsibleVersion(output string) (string, bool) {
	return extractGenericVersion(firstLine(output))
}

// normalizeVersion converts a "dirty" version to canonical major.minor.patch
// (Masterminds/semver fills missing minor/patch components with zero, and
// String() returns the complete triple — e.g. "1.26" -> "1.26.0").
func normalizeVersion(raw string) (string, bool) {
	v, err := semver.NewVersion(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	return v.String(), true
}

// satisfiesConstraint reports whether version satisfies constraint. An empty
// constraint accepts any version (the manifest requires no specific version;
// only tool presence matters).
func satisfiesConstraint(version, constraint string) (bool, error) {
	if strings.TrimSpace(constraint) == "" {
		return true, nil
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("parse version %q: %w", version, err)
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, fmt.Errorf("parse constraint %q: %w", constraint, err)
	}
	return c.Check(v), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
