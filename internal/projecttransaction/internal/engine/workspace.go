package engine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/trustload"
)

const NativeWorkspaceKind = "NativeWorkspaceTransaction"

func pairedKind(kind string) bool { return kind == NativeUpdateKind || kind == NativeWorkspaceKind }

// CheckWorkspaceTerminal reauthenticates current child ownership under both
// writer leases. Receipt authentication alone proves history, not present ownership.
// In-place owner edits are allowed; replacement inodes never gain authority from
// matching bytes. Other services and later workspace registrations are independent.
func (t *Transaction) CheckWorkspaceTerminal(ctx context.Context, r *trustload.Runtime) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.plan.Kind != NativeWorkspaceKind || t.lease == nil || !t.admitted || r == nil || r.TrustRuntime() == nil || !r.SharesInstallation(t.runtime) {
		return false, ErrAuthentication
	}
	state := t.state
	if t.pendingCommit != nil {
		state = *t.pendingCommit
	}
	if state.Phase != "committed" && state.Phase != "rolled-back" {
		return false, nil
	}
	if err := t.authenticate(ctx); err != nil {
		return false, err
	}
	pc := r.ProjectContext()
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return false, err
	}
	rel, err := filepath.Rel(t.plan.Material.Root, pc.RootPath)
	if err != nil || !filepath.IsLocal(rel) || rel == "." {
		return false, ErrAuthentication
	}
	prefix := filepath.ToSlash(rel)
	if err := t.checkNamespace(step{Path: prefix}); err != nil {
		return false, err
	}
	if state.Phase == "rolled-back" {
		if _, err := confinedLstat(pc.RootPath); !os.IsNotExist(err) {
			return false, ErrConflict
		}
		return false, nil
	}
	rootRecorded := false
	for _, s := range state.Steps {
		if s.Registry || s.Path != prefix && !strings.HasPrefix(s.Path, prefix+"/") {
			continue
		}
		if s.Path == prefix {
			rootRecorded = true
		}
		if err := t.checkNamespace(s); err != nil {
			return false, err
		}
		info, err := confinedLstat(filepath.Join(t.plan.Material.Root, filepath.FromSlash(s.Path)))
		after, exists := t.plan.Material.After[s.Path]
		if err != nil || !exists || fileID(info) != s.AfterIdentity || info.IsDir() != after.Directory || !info.IsDir() && (!info.Mode().IsRegular() || !singleLink(info)) {
			return false, ErrConflict
		}
	}
	if !rootRecorded {
		return false, ErrAuthentication
	}
	return true, nil
}

// LeaseWorkspaceService coordinates a finite secondary context with creation
// and native writers. The absent service path never supplies writer authority.
// This seam is restricted to concrete adapters by the nested internal boundary.
func (t *Transaction) LeaseWorkspaceService(ctx context.Context, r *trustload.Runtime) error {
	if t.plan.Kind != NativeWorkspaceKind || t.lease == nil || r == nil || r.TrustRuntime() == nil || r.ScratchRoot() != t.runtime.ScratchRoot() || !r.SharesInstallation(t.runtime) {
		return ErrAuthentication
	}
	pc := r.ProjectContext()
	if pc.ProjectID == t.plan.Material.ProjectID || pc.RootPath == t.plan.Material.Root {
		return ErrAuthentication
	}
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID); err != nil {
		return err
	}
	lease, err := acquireLease(r, pc.RootPath)
	if err != nil {
		return err
	}
	t.writerLocks = append(t.writerLocks, lease)
	parent := filepath.Join(t.plan.Material.Home, "transactions")
	if err := privateDirectory(parent); err != nil {
		return err
	}
	root, name, err := confinedParent(filepath.Join(parent, "new.lock"))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(name, writeLockFlags(), 0o600)
	if err != nil {
		return err
	}
	t.writerLocks = append(t.writerLocks, f)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !singleLink(info) {
		return ErrAuthentication
	}
	if err := checkStorageParent(root, filepath.Join(parent, "new.lock")); err != nil {
		return err
	}
	return lock(f)
}

func privateReadAny(root *os.Root, name string, before os.FileInfo, limit int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(before, held) {
		return nil, ErrConflict
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := root.Lstat(name)
	if err != nil || statErr != nil {
		return nil, errors.Join(err, statErr)
	}
	if int64(len(raw)) > limit || int64(len(raw)) != held.Size() || !os.SameFile(held, after) || held.Mode() != after.Mode() || held.Size() != after.Size() || !held.ModTime().Equal(after.ModTime()) {
		return nil, ErrConflict
	}
	return raw, nil
}

func WorkspaceRegistrySnapshot(home string) (File, error) {
	canonical, err := filepath.EvalSymlinks(home)
	if err != nil || canonical != home {
		return File{}, ErrAuthentication
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return File{}, err
	}
	defer root.Close()
	info, err := root.Lstat("projects.yaml")
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) {
		return File{}, ErrAuthentication
	}
	raw, err := privateReadAny(root, "projects.yaml", info, 1<<20)
	if err != nil {
		return File{}, err
	}
	id := fileID(info)
	return File{Data: raw, Mode: uint32(info.Mode().Perm()), Device: id.Device, Inode: id.Inode}, nil
}

// WorkspaceSnapshot observes a complete confined existing tree; inode identity
// participates in the plan so matching bytes cannot adopt a foreign replacement.
func WorkspaceSnapshot(ctx context.Context, name string) (map[string]File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(name)
	if err != nil || canonical != name {
		return nil, ErrAuthentication
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := map[string]File{}
	var total int64
	err = filepath.WalkDir(name, func(p string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(name, p)
		if err != nil || len(files) >= 4096 {
			return ErrAuthentication
		}
		rel = filepath.ToSlash(rel)
		info, err := root.Lstat(rel)
		if err != nil || !info.IsDir() && !info.Mode().IsRegular() {
			return ErrAuthentication
		}
		id := fileID(info)
		image := File{Mode: uint32(info.Mode().Perm()), Directory: info.IsDir(), Device: id.Device, Inode: id.Inode, Data: Bytes{}}
		if !info.IsDir() {
			if !singleLink(info) || info.Size() > (64<<20)-total {
				return ErrAuthentication
			}
			image.Data, err = privateReadAny(root, rel, info, (64<<20)-total)
			if err != nil {
				return err
			}
			total += int64(len(image.Data))
		}
		files[rel] = image
		return nil
	})
	if err != nil {
		return nil, err
	}
	info, err := confinedLstat(name)
	if err != nil || fileID(info) != (Identity{files["."].Device, files["."].Inode}) {
		return nil, ErrConflict
	}
	return files, nil
}
