//go:build darwin || linux

package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func (f *FirstMarker) acquireLocks() error {
	m := f.tx.plan.Material
	if err := privateDirectory(filepath.Join(m.Home, "transactions")); err != nil {
		return err
	}
	for _, name := range []string{filepath.Join(m.Home, ".lock"), filepath.Join(m.Home, "transactions", "new.lock")} {
		root, base, err := confinedParent(name)
		if err != nil {
			return err
		}
		fd, err := root.OpenFile(base, writeLockFlags(), 0o600)
		if err != nil {
			root.Close()
			return err
		}
		err = checkStorageParent(root, name)
		root.Close()
		f.tx.writerLocks = append(f.tx.writerLocks, fd)
		if err != nil {
			return err
		}
		info, err := fd.Stat()
		if err != nil || !singleLink(info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return ErrConflict
		}
		if err = lock(fd); err != nil {
			return err
		}
	}
	return nil
}
func (f *FirstMarker) publishState(ctx context.Context, reverse bool) error {
	if err := f.checkSealedPlan(ctx); err != nil {
		return err
	}
	if err := f.checkSealedState(ctx); err != nil {
		return err
	}
	if err := f.checkUsers(); err != nil {
		return err
	}
	root, err := directoryDescriptor(f.tx.plan.Material.Root, f.tx.plan.RootIdentity)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	parent, err := directoryDescriptor(filepath.Dir(f.tx.plan.Material.Root), f.state.Parent)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	stage := filepath.Base(f.stage())
	if reverse {
		err = exclusiveRenameAt(root, ".tplaiter", parent, stage)
	} else {
		err = exclusiveRenameAt(parent, stage, root, ".tplaiter")
	}
	if err != nil {
		return err
	}
	target := f.target()
	if reverse {
		target = f.stage()
	}
	info, err := confinedLstat(target)
	if err != nil || fileID(info) != f.state.Stage {
		return ErrConflict
	}
	return errors.Join(unix.Fsync(root), unix.Fsync(parent))
}
func (f *FirstMarker) publishRegistry(ctx context.Context, reverse bool) error {
	if err := f.checkSealedPlan(ctx); err != nil {
		return err
	}
	if err := f.checkSealedState(ctx); err != nil {
		return err
	}
	if err := f.checkUsers(); err != nil {
		return err
	}
	m := f.tx.plan.Material
	home, err := directoryDescriptor(m.Home, f.tx.plan.HomeIdentity)
	if err != nil {
		return err
	}
	defer unix.Close(home)
	receipt, err := directoryDescriptor(f.tx.dir, f.state.Receipt)
	if err != nil {
		return err
	}
	defer unix.Close(receipt)
	if m.Registry.Before.Inode != 0 {
		err = exchangeAt(receipt, firstMarkerRegistrySlot, home, "projects.yaml")
	} else if reverse {
		err = exclusiveRenameAt(home, "projects.yaml", receipt, firstMarkerRegistrySlot)
	} else {
		err = exclusiveRenameAt(receipt, firstMarkerRegistrySlot, home, "projects.yaml")
	}
	if err != nil {
		return err
	}
	want, id := m.Registry.After, f.state.RegistryAfter
	slot, slotID := m.Registry.Before, Identity{m.Registry.Before.Device, m.Registry.Before.Inode}
	if reverse {
		want, id, slot, slotID = slot, slotID, want, id
	}
	if err = firstRegistryCheck(filepath.Join(m.Home, "projects.yaml"), want, id); err != nil {
		return err
	}
	if err = firstRegistryCheck(filepath.Join(f.tx.dir, firstMarkerRegistrySlot), slot, slotID); err != nil {
		return err
	}
	return errors.Join(unix.Fsync(home), unix.Fsync(receipt))
}

// Keep os in this platform file's signature space for unsupported counterparts.
var _ *os.File
