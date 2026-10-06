//go:build !darwin && !linux

package ossinstall

import (
	"context"
)

type fileHandle struct{}

func (fileHandle) close() error { return nil }

func acquireInstallLocks(context.Context, string, string) (*InstallLocks, error) {
	return nil, ErrInstallLockUnsupported
}

func validateDestinationPath(string) error { return ErrInstallLockUnsupported }

func publishExecutable(string, string) (PublicationResult, error) {
	return PublicationResult{}, ErrInstallLockUnsupported
}
