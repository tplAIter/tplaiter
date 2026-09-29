package manifest

import (
	"fmt"
	"path"
	"strings"
)

// Typed repository-discovery error codes. They are stable identifiers for
// callers (CLI, MCP, lint) and must not change once published.
const (
	// CodeRepoPathEscape: a declared template path, a template root or a
	// manifest symlink resolves outside the repository root (absolute path,
	// ".." segment or escaping symlink).
	CodeRepoPathEscape = "TPL-E-REPO-PATH-ESCAPE"
	// CodeRepoDupName: two discovered templates declare the same
	// metadata.name, which would make <repo>/<name> ambiguous.
	CodeRepoDupName = "TPL-E-REPO-DUP-NAME"
	// CodeRepoDupPath: two templates[] entries name the same directory, either
	// literally after normalization or after symlink resolution.
	CodeRepoDupPath = "TPL-E-REPO-DUP-PATH"
	// CodeRepoPathInvalid: a declared template path is empty, malformed,
	// missing, not a directory, points into an excluded directory, or
	// declares no template.
	CodeRepoPathInvalid = "TPL-E-REPO-PATH-INVALID"
)

// RepositoryError is a typed repository discovery or repository-manifest
// validation failure. Code is one of the CodeRepo* constants; Path is the
// offending repository-relative path (slash separated) as declared or
// discovered; Detail is a human-readable explanation.
type RepositoryError struct {
	Code   string
	Path   string
	Detail string
}

func (e *RepositoryError) Error() string {
	if e == nil {
		return ""
	}
	msg := e.Code
	if e.Path != "" {
		msg += fmt.Sprintf(": %q", e.Path)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// NewRepositoryError builds a [RepositoryError].
func NewRepositoryError(code, p, detail string) *RepositoryError {
	return &RepositoryError{Code: code, Path: p, Detail: detail}
}

// Validate checks the repository manifest contract that can be decided
// without touching the filesystem: every templates[].path must be a
// non-empty, relative, slash-separated path without ".." segments, and no two
// entries may name the same directory. Filesystem confinement (symlinks,
// existence) is enforced by repository discovery (internal/repo).
//
// The first problem is returned as a [*RepositoryError]; entries are checked
// in declaration order, so the result is deterministic.
func (r *Repository) Validate() error {
	seen := make(map[string]string, len(r.Templates))
	for i, ref := range r.Templates {
		clean, err := CleanTemplatePath(ref.Path)
		if err != nil {
			return err
		}
		if prior, dup := seen[clean]; dup {
			return NewRepositoryError(CodeRepoDupPath, ref.Path,
				fmt.Sprintf("templates[%d].path names the same directory as %q", i, prior))
		}
		seen[clean] = ref.Path
	}
	return nil
}

// CleanTemplatePath normalizes a declared templates[].path into its canonical
// slash-separated repository-relative form ("." is the repository root). It
// rejects empty and backslash-separated paths with [CodeRepoPathInvalid], and
// absolute paths, drive-letter paths and any ".." segment with
// [CodeRepoPathEscape]. A ".." segment is rejected even when the cleaned path
// would stay inside the repository: declared paths must be written
// canonically.
func CleanTemplatePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", NewRepositoryError(CodeRepoPathInvalid, raw, "empty templates[].path")
	}
	if strings.Contains(p, `\`) {
		return "", NewRepositoryError(CodeRepoPathInvalid, raw, "templates[].path must use '/' separators")
	}
	if strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') {
		return "", NewRepositoryError(CodeRepoPathEscape, raw, "templates[].path must be relative to the repository root")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", NewRepositoryError(CodeRepoPathEscape, raw, "templates[].path must not contain '..' segments")
		}
	}
	return path.Clean(p), nil
}
