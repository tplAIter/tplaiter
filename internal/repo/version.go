package repo

import (
	"sort"
	"strconv"
	"strings"
)

// semver is a parsed vMAJOR.MINOR.PATCH version. Prereleases (the `-...`
// suffix) are unstable and are excluded from the release-tag index (the
// default is the highest stable tag).
type semver struct {
	major, minor, patch int
}

// parseStableSemver parses a `vX.Y.Z` version (the leading `v` is required).
// It returns ok=false for empty input, an invalid format, or a prerelease.
// (`vX.Y.Z-rc1`, `+build`) — such tags are not considered stable.
func parseStableSemver(v string) (semver, bool) {
	if len(v) < 2 || v[0] != 'v' {
		return semver{}, false
	}
	core := v[1:]
	// Prerelease/build metadata is not a stable release.
	if strings.ContainsAny(core, "-+") {
		return semver{}, false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2]}, true
}

// less reports whether a is less than b, lexicographically by major/minor/patch.
func (a semver) less(b semver) bool {
	switch {
	case a.major != b.major:
		return a.major < b.major
	case a.minor != b.minor:
		return a.minor < b.minor
	default:
		return a.patch < b.patch
	}
}

// tagVersion is a tag with its parsed version (for sorting).
type tagVersion struct {
	tag     string // Full git tag: "v1.2.0" or "name/v1.2.0".
	version string // Version suffix: "v1.2.0".
	ver     semver
}

// stableTagsFor filters allTags to stable release tags applicable to
// templateName in a repository of kind (single/multi), returning full git tags
// sorted by descending version (result[0] is the highest stable tag).
//
// Matching rules:
//   - single: a `vX.Y.Z` tag (without a prefix);
//   - multi: a `<templateName>/vX.Y.Z` tag.
func stableTagsFor(allTags []string, templateName string, multi bool) []string {
	matched := make([]tagVersion, 0, len(allTags))
	prefix := templateName + "/"
	for _, tag := range allTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		var versionPart string
		if multi {
			if !strings.HasPrefix(tag, prefix) {
				continue
			}
			versionPart = strings.TrimPrefix(tag, prefix)
		} else {
			// single: only tags without "/" (otherwise it is another namespaced tag).
			if strings.Contains(tag, "/") {
				continue
			}
			versionPart = tag
		}
		ver, ok := parseStableSemver(versionPart)
		if !ok {
			continue
		}
		matched = append(matched, tagVersion{tag: tag, version: versionPart, ver: ver})
	}

	sort.Slice(matched, func(i, j int) bool {
		// Descending version; tag name breaks ties deterministically.
		if matched[i].ver.less(matched[j].ver) {
			return false
		}
		if matched[j].ver.less(matched[i].ver) {
			return true
		}
		return matched[i].tag < matched[j].tag
	})

	out := make([]string, len(matched))
	for i, m := range matched {
		out[i] = m.tag
	}
	return out
}

// tagVersionSuffix extracts the version suffix from a full git tag relative to
// the template name: `name/v1.0.0` → `v1.0.0`, `v1.0.0` → `v1.0.0`. It is used
// when matching a user-supplied `@vX.Y.Z` against stored tags.
func tagVersionSuffix(tag, templateName string) string {
	return strings.TrimPrefix(tag, templateName+"/")
}
