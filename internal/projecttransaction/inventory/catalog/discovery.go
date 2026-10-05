// Package catalog lists confined transaction namespaces without reading authority.
package catalog

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
)

// ErrUnsafeDiscovery reports an invalid root or an oversized namespace listing.
var ErrUnsafeDiscovery = errors.New("project transaction inventory: unsafe discovery")

// Candidate reports a directory entry only. Even a candidate named state.json
// does not carry an authenticated phase, terminal status or recovery permission.
type Candidate struct {
	Scope       string
	Path        string
	ID          string
	Directory   bool
	Symlink     bool
	CanonicalID bool
}

// Discover lists only the two existing-tree namespaces, without reading any
// journal/image/key bytes, creating files, acquiring writer locks or resolving
// a journal-supplied path. projectRoot and home are untrusted observation roots.
func Discover(ctx context.Context, projectRoot, home string) ([]Candidate, error) {
	if ctx == nil {
		return nil, ErrUnsafeDiscovery
	}
	out := []Candidate{}
	for _, loc := range []struct{ scope, root, namespace string }{
		{"project", projectRoot, ".tplaiter/" + ledgerpath.ProjectTransactionImagesDir},
		{"home", home, ledgerpath.ProjectTransactionsDir},
	} {
		if loc.root == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		held, err := openDiscoveryRoot(loc.root)
		if err != nil {
			return nil, err
		}
		entries, err := namespaceEntries(held, loc.namespace)
		held.Close()
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := entry.Name()
			id := name
			if loc.scope == "home" {
				id = strings.TrimPrefix(name, "tx-")
			}
			canonical := ledgerpath.ProjectTransactionID(id) && (loc.scope != "home" || strings.HasPrefix(name, "tx-"))
			out = append(out, Candidate{Scope: loc.scope, Path: loc.namespace + "/" + name, ID: id, Directory: entry.IsDir(), Symlink: entry.Type()&os.ModeSymlink != 0, CanonicalID: canonical})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func openDiscoveryRoot(name string) (*os.Root, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, ErrUnsafeDiscovery
	}
	if name == string(filepath.Separator) {
		return os.OpenRoot(name)
	}
	// Existing stateledger accepts ancestor aliases such as macOS /var, but
	// rejects a symlink at the selected root itself. Resolve only the parent;
	// the final root is observed/opened against that retained real parent.
	parent, err := filepath.EvalSymlinks(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	held, err := openPhysicalDiscoveryRoot(parent)
	if err != nil {
		return nil, err
	}
	defer held.Close()
	leaf := filepath.Base(name)
	info, err := held.Lstat(leaf)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeDiscovery
	}
	selected, err := held.OpenRoot(leaf)
	if err != nil {
		return nil, err
	}
	opened, err := selected.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		selected.Close()
		return nil, ErrUnsafeDiscovery
	}
	return selected, nil
}

func openPhysicalDiscoveryRoot(name string) (*os.Root, error) {
	held, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(name, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, err := held.Lstat(part)
		if err != nil {
			held.Close()
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			held.Close()
			return nil, ErrUnsafeDiscovery
		}
		next, err := held.OpenRoot(part)
		held.Close()
		if err != nil {
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			return nil, ErrUnsafeDiscovery
		}
		held = next
	}
	return held, nil
}

func namespaceEntries(root *os.Root, namespace string) ([]os.DirEntry, error) {
	// Reject even in-root symlink directories rather than following them.
	held, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = held.Close() }()
	for _, part := range strings.Split(namespace, "/") {
		info, err := held.Lstat(part)
		if os.IsNotExist(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafeDiscovery
		}
		next, err := held.OpenRoot(part)
		if err != nil {
			return nil, err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			next.Close()
			return nil, ErrUnsafeDiscovery
		}
		held.Close()
		held = next
	}
	dir, err := held.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(10001)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 10000 {
		return nil, ErrUnsafeDiscovery
	}
	return entries, nil
}
