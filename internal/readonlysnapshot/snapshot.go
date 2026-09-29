// Package readonlysnapshot captures project state without mutating it. The
// snapshot has five components (HEAD, index, tracked files, untracked files
// and state ledgers), so a caller can prove that a read-only command changed
// nothing by comparing a snapshot taken before and after it.
package readonlysnapshot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/naming"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

// OfflineMissCode is the typed diagnostic for a cache miss in offline mode.
const OfflineMissCode = "TPL-E-OFFLINE-MISS-001"

// OfflineMissError reports that a required cached object is absent while the
// caller is not allowed to fetch it.
type OfflineMissError struct{ Subject string }

func (e *OfflineMissError) Error() string {
	return OfflineMissCode + ": required cached object is absent: " + e.Subject
}

// Code returns the stable diagnostic code.
func (e *OfflineMissError) Code() string { return OfflineMissCode }

// FileDigest is the content evidence for one path.
type FileDigest struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// Snapshot is the five-component read-only project evidence.
type Snapshot struct {
	ProjectID   string       `json:"projectID"`
	Root        string       `json:"root"`
	Head        string       `json:"head"`
	IndexSHA256 string       `json:"indexSHA256"`
	Tracked     []FileDigest `json:"tracked"`
	Untracked   []FileDigest `json:"untracked"`
	Ledgers     []FileDigest `json:"ledgers"`
}

// SHA256 is the digest of the snapshot's canonical JSON. Two snapshots of an
// unchanged project have the same digest.
func (s Snapshot) SHA256() (string, error) {
	b, err := canonicaljson.Canonical(s)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

// Options configures Project.
type Options struct {
	// Runner executes git. Nil uses execx.Exec.
	Runner execx.Runner
}

// Project captures root with the default runner.
func Project(root string) (Snapshot, error) {
	return ProjectWith(context.Background(), root, Options{})
}

// ProjectWith captures root. Git is invoked with optional locks disabled, no
// credential helper, no prompts, no lazy fetch and no system or global
// configuration, so it can neither write the index nor reach the network.
// Without a git work tree the whole tree (except .git and the state
// directory) is hashed instead of the tracked set.
func ProjectWith(ctx context.Context, root string, opts Options) (Snapshot, error) {
	runner := opts.Runner
	if runner == nil {
		runner = execx.Exec{}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Snapshot{}, err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return Snapshot{}, fmt.Errorf("snapshot root is not a directory: %s", root)
	}
	markerData, err := os.ReadFile(filepath.Join(root, naming.ProjectDir, "project.yaml"))
	if err != nil {
		return Snapshot{}, err
	}
	var marker struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal(markerData, &marker); err != nil || marker.ID == "" {
		return Snapshot{}, errors.New("snapshot: invalid project marker")
	}
	git := func(args ...string) (string, error) { return gitOutput(ctx, runner, root, args...) }
	s := Snapshot{Root: root, ProjectID: marker.ID, Tracked: []FileDigest{}, Untracked: []FileDigest{}, Ledgers: []FileDigest{}}
	if head, e := git("rev-parse", "HEAD"); e == nil {
		s.Head = strings.TrimSpace(head)
	}
	indexPath := filepath.Join(root, ".git", "index")
	if rawPath, e := git("rev-parse", "--git-path", "index"); e == nil {
		candidate := strings.TrimSpace(rawPath)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(root, candidate)
		}
		indexPath = filepath.Clean(candidate)
	}
	if index, e := os.ReadFile(indexPath); e == nil {
		staged, stageErr := git("ls-files", "--stage", "-z")
		if stageErr != nil {
			return Snapshot{}, fmt.Errorf("snapshot: read index entries: %w", stageErr)
		}
		s.IndexSHA256 = digestFramed(index, []byte(staged))
	}
	entries, err := hashTracked(root, git)
	if err != nil {
		return Snapshot{}, err
	}
	s.Tracked = entries
	for _, rel := range ledgerPaths() {
		if item, exists, e := hashProjectPath(root, rel); e != nil {
			return Snapshot{}, e
		} else if exists {
			s.Ledgers = append(s.Ledgers, item)
		}
	}
	if raw, e := git("ls-files", "--others", "--exclude-standard", "-z"); e == nil {
		for _, rel := range splitNUL(raw) {
			item, exists, hashErr := hashProjectPath(root, rel)
			if hashErr != nil {
				return Snapshot{}, hashErr
			}
			if exists {
				s.Untracked = append(s.Untracked, item)
			}
		}
		sort.Slice(s.Untracked, func(i, j int) bool { return s.Untracked[i].Path < s.Untracked[j].Path })
	}
	return s, nil
}

// ledgerPaths are the project marker plus every standard ledger pointer.
func ledgerPaths() []string {
	return append([]string{naming.ProjectDir + "/project.yaml"}, stateledger.StandardPointers().Paths()...)
}

func hashTree(root string) ([]FileDigest, error) {
	var out []FileDigest
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == naming.ProjectDir || d.Name() == naming.LegacyProjectDir) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		item, exists, e := hashProjectPath(root, filepath.ToSlash(rel))
		if e != nil {
			return e
		}
		if exists {
			out = append(out, item)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

func hashTracked(root string, git func(...string) (string, error)) ([]FileDigest, error) {
	raw, err := git("ls-files", "-z")
	if err != nil {
		return hashTree(root)
	}
	var out []FileDigest
	for _, rel := range splitNUL(raw) {
		if filepath.IsAbs(rel) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "../") {
			return nil, fmt.Errorf("snapshot: unsafe tracked path %q", rel)
		}
		item, exists, err := hashProjectPath(root, rel)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("snapshot: tracked path is absent: %s", rel)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func hashProjectPath(root, rel string) (FileDigest, bool, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "\\") || filepath.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") {
		return FileDigest{}, false, fmt.Errorf("snapshot: unsafe path %q", rel)
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return FileDigest{}, false, nil
	}
	if err != nil {
		return FileDigest{}, false, err
	}
	item := FileDigest{Path: filepath.ToSlash(rel), Mode: uint32(info.Mode().Perm())}
	var data []byte
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		item.Kind = "symlink"
		target, readErr := os.Readlink(path)
		if readErr != nil {
			return FileDigest{}, false, readErr
		}
		data = []byte(target)
	case info.Mode().IsRegular():
		item.Kind = "file"
		data, err = os.ReadFile(path)
		if err != nil {
			return FileDigest{}, false, err
		}
	default:
		return FileDigest{}, false, fmt.Errorf("snapshot: unsupported path kind %q", rel)
	}
	item.SHA256 = digest(data)
	return item, true, nil
}

func splitNUL(raw string) []string {
	parts := strings.Split(raw, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// digestFramed hashes length-prefixed parts so that concatenation boundaries
// cannot be shifted between them.
func digestFramed(parts ...[]byte) string {
	h := sha256.New()
	for _, part := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(part)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// gitEnv isolates git from user and system configuration, credentials,
// prompts and lazy fetches. Repository-local configuration is still read, so
// gitOutput also disables the settings that can execute a program
// (core.fsmonitor, hooks).
var gitEnv = []string{"GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_OPTIONAL_LOCKS=0"}

func gitOutput(ctx context.Context, runner execx.Runner, root string, args ...string) (string, error) {
	argv := append([]string{"-C", root, "-c", "credential.helper=", "-c", "core.askPass=", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "--no-optional-locks"}, args...)
	res, err := runner.Run(ctx, "git", argv, execx.Options{Env: gitEnv})
	if err != nil {
		return "", err
	}
	return res.Stdout, nil
}
