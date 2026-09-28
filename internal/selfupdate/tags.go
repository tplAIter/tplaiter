package selfupdate

import (
	"context"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// LatestTag returns the highest v* (SemVer) tag from repoURL via
// `git ls-remote --tags`. An empty string without an error means the repository
// has no v* tags.
func LatestTag(ctx context.Context, runner execx.Runner, repoURL string) (string, error) {
	res, err := runner.Run(ctx, "git", []string{"ls-remote", "--tags", repoURL}, execx.Options{})
	if err != nil {
		return "", fmt.Errorf("selfupdate: git ls-remote --tags %s: %w", repoURL, err)
	}
	return parseLatestTag(res.Stdout), nil
}

// parseLatestTag parses `git ls-remote --tags` output (lines of the form
// "<sha>\trefs/tags/<ref>") and returns the highest valid v*-SemVer tag.
// Invalid lines (not starting with "v" or not parseable as SemVer) and
// dereferenced annotated-tag references ("^{}") are silently ignored; they are
// normal ls-remote noise, not format errors.
func parseLatestTag(output string) string {
	var (
		latest    *semver.Version
		latestRaw string
	)

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		ref := strings.TrimSuffix(strings.TrimPrefix(fields[1], "refs/tags/"), "^{}")
		if !strings.HasPrefix(ref, "v") {
			continue
		}
		v, err := semver.NewVersion(ref)
		if err != nil {
			continue
		}
		if latest == nil || v.GreaterThan(latest) {
			latest = v
			latestRaw = ref
		}
	}
	return latestRaw
}

// CompareResult is the result of comparing the current CLI version with the
// highest discovered tag (see [Compare]).
type CompareResult int

// Possible [Compare] results.
const (
	// CompareUnknown means comparison is impossible: one version (usually the
	// current local "dev" build) is not valid SemVer.
	CompareUnknown CompareResult = iota
	// CompareUpToDate means the current version equals latest.
	CompareUpToDate
	// CompareOutdated means the current version is older than latest and should update.
	CompareOutdated
	// CompareAhead means the current version is newer than latest (a local or
	// prerelease build is ahead of published tags); no update is needed.
	CompareAhead
)

// Compare compares current (usually the result of `tplater version`) with
// latest (the result of [LatestTag]). The "v" prefix is optional in both.
func Compare(current, latest string) CompareResult {
	cv, err := semver.NewVersion(strings.TrimPrefix(current, "v"))
	if err != nil {
		return CompareUnknown
	}
	lv, err := semver.NewVersion(strings.TrimPrefix(latest, "v"))
	if err != nil {
		return CompareUnknown
	}

	switch {
	case cv.LessThan(lv):
		return CompareOutdated
	case cv.GreaterThan(lv):
		return CompareAhead
	default:
		return CompareUpToDate
	}
}
