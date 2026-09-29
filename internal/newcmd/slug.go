package newcmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// slugRe is the allowed project slug format: a lowercase letter followed by
// lowercase letters, digits, or underscores. It matches the generator's
// identRe and Go identifier restrictions so the slug can name a package/module.
var slugRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// slugSepRe matches runs of spaces and hyphens normalized to one underscore
// before validation ("spaces/hyphens → _").
var slugSepRe = regexp.MustCompile(`[\s-]+`)

// Slugify normalizes a human-readable project name into a slug: it lowercases,
// collapses spaces and hyphens to "_", and validates the result with [slugRe].
// Errors include the original name and candidate so the user can see what
// failed validation.
func Slugify(name string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugSepRe.ReplaceAllString(s, "_")
	if s == "" {
		return "", errors.New("newcmd: empty project name — slug cannot be derived")
	}
	if !slugRe.MatchString(s) {
		return "", fmt.Errorf(
			"newcmd: name %q produces invalid slug %q (expected %s) — use only Latin letters/digits",
			name, s, slugRe.String(),
		)
	}
	return s, nil
}

// checkTplaterVersion checks the template's requires.tplaiter requirement
// against the CLI version. A dev build (a version that is not valid semver,
// such as "dev" or "(devel)") always passes the gate: a template developer
// should not be blocked by the template's own requirement on an unreleased CLI.
func checkTplaterVersion(constraint, cliVersion string) error {
	if strings.TrimSpace(constraint) == "" {
		return nil
	}
	ver := strings.TrimSpace(cliVersion)
	// Dev builds pass the gate: "dev" (the ldflags placeholder), VCS pseudo-
	// versions v0.0.0-<timestamp>-<sha> (go build from a git tree), and +dirty builds.
	if ver == "dev" || strings.HasPrefix(ver, "v0.0.0-") || strings.HasSuffix(ver, "+dirty") {
		return nil
	}
	v, err := semver.NewVersion(ver)
	if err != nil {
		// An unparsable version is a local dev build, so the gate does not apply.
		return nil //nolint:nilerr // Dev builds intentionally pass the version gate.
	}
	c, cerr := semver.NewConstraint(constraint)
	if cerr != nil {
		return fmt.Errorf("newcmd: unparseable requires.tplaiter requirement %q: %w", constraint, cerr)
	}
	if !c.Check(v) {
		return fmt.Errorf(
			"newcmd: template requires tplaiter %s, but %s is installed — update tplaiter (`tplaiter self-upgrade`)",
			constraint, cliVersion,
		)
	}
	return nil
}

// newUUIDv4 generates a random version 4 UUID for the project ID in
// .tplaiter/project.yaml. It uses a local generator instead of an external
// dependency because the format is trivial and google/uuid is unnecessary for one call.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("newcmd: UUID generation: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
