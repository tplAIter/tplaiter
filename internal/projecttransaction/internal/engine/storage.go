package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tplAIter/tplaiter/internal/trustload"
)

// Internal sealing authority is generated and consumed only by this package,
// under the scratch root authenticated by the installed runtime. It is not a
// user credential/profile, caller key, journal field or model-visible value.
func runtimeKey(ctx context.Context, runtime *trustload.Runtime, id string, create bool) ([]byte, error) {
	if runtime == nil || runtime.TrustRuntime() == nil {
		return nil, ErrAuthentication
	}
	pc := runtime.ProjectContext()
	if err := runtime.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, id); err != nil {
		return nil, err
	}
	root := runtime.ScratchRoot()
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrAuthentication
	}
	dir := filepath.Join(root, "project-transaction-authority")
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "seal.key")
	key, err := privateRead(name, 32)
	if os.IsNotExist(err) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := durableExclusive(name, key, 0o600); err != nil {
			if !os.IsExist(err) {
				return nil, err
			}
			key, err = privateRead(name, 32)
			if err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrAuthentication
	}
	return key, nil
}

func acquireLease(runtime *trustload.Runtime, root string) (*os.File, error) {
	dir := filepath.Join(runtime.ScratchRoot(), "project-transaction-authority")
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(root))
	name := filepath.Join(dir, hex.EncodeToString(h[:])+".lock")
	parent, base, err := confinedParent(name)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	f, err := parent.OpenFile(base, writeLockFlags(), 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !singleLink(info) || info.Mode().Perm() != 0o600 {
		f.Close()
		return nil, ErrAuthentication
	}
	if err := checkStorageParent(parent, name); err != nil {
		f.Close()
		return nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func privateDirectory(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ErrAuthentication
	}
	parts := []string{}
	for current := name; current != filepath.Dir(current); current = filepath.Dir(current) {
		parts = append(parts, current)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		info, err := confinedLstat(p)
		if os.IsNotExist(err) {
			if err := confinedMkdir(p, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
			info, err = confinedLstat(p)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrAuthentication
		}
	}
	info, err := confinedLstat(name)
	if err != nil || info.Mode().Perm() != 0o700 {
		return ErrAuthentication
	}
	return nil
}

// confinedParent resolves an absolute, canonical name one directory at a time.
// Each opened directory must be the same non-symlink inode observed in its held
// parent. All subsequent file operations use the retained final os.Root.
func confinedParent(name string) (*os.Root, string, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || name == string(filepath.Separator) {
		return nil, "", ErrAuthentication
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, "", err
	}
	parent := filepath.Dir(name)
	if parent != string(filepath.Separator) {
		for _, component := range strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator)) {
			info, err := root.Lstat(component)
			if err != nil {
				root.Close()
				return nil, "", err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				root.Close()
				return nil, "", ErrAuthentication
			}
			next, err := root.OpenRoot(component)
			root.Close()
			if err != nil {
				return nil, "", err
			}
			opened, err := next.Stat(".")
			if err != nil || !os.SameFile(info, opened) {
				next.Close()
				return nil, "", ErrAuthentication
			}
			root = next
		}
	}
	return root, filepath.Base(name), nil
}

// A retained descriptor confines access even when its directory is moved. Also
// refuse a changed absolute binding: detached storage cannot confirm durability
// at the authenticated journal/authority location.
func checkStorageParent(root *os.Root, name string) error {
	fresh, _, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer fresh.Close()
	oldInfo, err := root.Stat(".")
	if err != nil {
		return err
	}
	newInfo, err := fresh.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(oldInfo, newInfo) {
		return ErrAuthentication
	}
	return nil
}

func confinedLstat(name string) (os.FileInfo, error) {
	root, base, err := confinedParent(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil {
		return nil, err
	}
	if err := checkStorageParent(root, name); err != nil {
		return nil, err
	}
	return info, nil
}

func confinedMkdir(name string, mode os.FileMode) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Mkdir(base, mode); err != nil {
		return err
	}
	return checkStorageParent(root, name)
}

func confinedReadDir(name string) ([]os.DirEntry, error) {
	root, base, err := confinedParent(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrConflict
	}
	f, err := root.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrConflict
	}
	entries, err := f.ReadDir(4097)
	if len(entries) > 4096 {
		return nil, ErrConflict
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := checkStorageParent(root, name); err != nil {
		return nil, err
	}
	return entries, nil
}

func privateRead(name string, byteLimit int64) ([]byte, error) {
	if byteLimit < 0 || byteLimit > 128<<20 {
		return nil, ErrAuthentication
	}
	root, base, err := confinedParent(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !singleLink(info) || info.Size() > byteLimit {
		return nil, ErrAuthentication
	}
	f, err := root.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return nil, ErrAuthentication
	}
	data, err := io.ReadAll(io.LimitReader(f, byteLimit+1))
	if err != nil || int64(len(data)) > byteLimit {
		return nil, ErrAuthentication
	}
	if err := checkStorageParent(root, name); err != nil {
		return nil, err
	}
	return data, nil
}

func durableExclusive(name string, data []byte, mode os.FileMode) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(base, exclusiveFlags(), mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := checkStorageParent(root, name); err != nil {
		return err
	}
	return syncStorageRoot(root)
}

// Finite private storage fault points are used only by package boundary tests;
// they are not wire fields, callbacks, public parameters or authority grants.
type commitWriteFault uint8

const (
	commitWriteOK commitWriteFault = iota
	commitWriteBeforePublish
	commitWriteAfterPublish
)

var errCommitWriteFault = errors.New("project transaction: injected terminal storage failure")

type publishedWriteError struct{ cause error }

func (e *publishedWriteError) Error() string { return e.cause.Error() }
func (e *publishedWriteError) Unwrap() error { return e.cause }
func durableReplace(name string, data []byte, fault commitWriteFault) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer root.Close()
	// Randomness identifies a private exclusive temporary file, never authority.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".state-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temp, exclusiveFlags(), 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(temp) }()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if fault == commitWriteBeforePublish {
		return errCommitWriteFault
	}
	if err := checkStorageParent(root, name); err != nil {
		return err
	}
	if err := root.Rename(temp, base); err != nil {
		return err
	}
	if fault == commitWriteAfterPublish {
		return &publishedWriteError{errCommitWriteFault}
	}
	if err := checkStorageParent(root, name); err != nil {
		return &publishedWriteError{err}
	}
	if err := syncStorageRoot(root); err != nil {
		return &publishedWriteError{err}
	}
	return nil
}

func syncReceipt(name string) error {
	root, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(base, readNoFollow(), 0)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || !singleLink(opened) || opened.Mode().Perm() != 0o600 {
		f.Close()
		return ErrAuthentication
	}
	err = errors.Join(f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err := checkStorageParent(root, name); err != nil {
		return err
	}
	return syncStorageRoot(root)
}

type receiptSyncFault uint8

const (
	receiptSyncOK receiptSyncFault = iota
	receiptSyncBeforeDirectory
)

var errReceiptSyncFault = errors.New("project transaction: injected receipt directory sync failure")

// Confirm the exact authenticated bytes through the descriptor being synced.
// No write, chmod or replacement is performed on an unexpected receipt.
func syncReceiptExact(ctx context.Context, name string, expected []byte, fault receiptSyncFault) error {
	if ctx == nil || len(expected) > 128<<20 {
		return ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(base, receiptReadFlags(), 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || !singleLink(opened) || opened.Mode().Perm() != 0o600 {
		return ErrAuthentication
	}
	if err := matchReceiptContext(ctx, f, expected); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := matchReceiptContext(ctx, f, expected); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := root.Lstat(base)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) || !singleLink(current) || current.Mode().Perm() != 0o600 {
		return ErrAuthentication
	}
	if err := checkStorageParent(root, name); err != nil {
		return err
	}
	if fault == receiptSyncBeforeDirectory {
		return errReceiptSyncFault
	}
	if err := syncStorageRoot(root); err != nil {
		return err
	}
	current, err = root.Lstat(base)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) || !singleLink(current) || current.Mode().Perm() != 0o600 {
		return ErrAuthentication
	}
	return checkStorageParent(root, name)
}

func syncStorageRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// Compare a receipt through the already confined descriptor with bounded
// caller cancellation checks, preserving the exact before/after fsync bytes.
func matchReceiptContext(ctx context.Context, file *os.File, expected []byte) error {
	var buffer [64 << 10]byte
	for offset := 0; offset < len(expected); {
		if err := ctx.Err(); err != nil {
			return err
		}
		size := min(len(buffer), len(expected)-offset)
		if _, err := io.ReadFull(file, buffer[:size]); err != nil {
			return err
		}
		if !bytes.Equal(buffer[:size], expected[offset:offset+size]) {
			return ErrAuthentication
		}
		offset += size
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var sentinel [1]byte
	n, err := file.Read(sentinel[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return ErrAuthentication
	}
	return ctx.Err()
}
