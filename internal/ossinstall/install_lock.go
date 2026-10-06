package ossinstall

import "context"

// ErrInstallLockUnsupported reports that the platform cannot provide the
// install transaction's required advisory lock semantics.
var ErrInstallLockUnsupported = errInstallLockUnsupported{}

type errInstallLockUnsupported struct{}

func (errInstallLockUnsupported) Error() string {
	return "ossinstall: install transaction locking is unsupported on this platform"
}

// InstallLocks holds the stable coordination descriptors for one install
// transaction. The descriptors are deliberately independent of TRUST_ROOT so
// rotation cannot remove them.
type InstallLocks struct {
	files []*lockFile
}

type lockFile struct {
	file *fileHandle
	path string
}

// AcquireInstallLocks prepares canonical parents and acquires the root and,
// when present, final-destination locks in lexical path order.
func AcquireInstallLocks(ctx context.Context, root, destination string) (*InstallLocks, error) {
	return acquireInstallLocks(ctx, root, destination)
}

// Close releases the locks in reverse acquisition order.
func (l *InstallLocks) Close() error {
	if l == nil {
		return nil
	}
	var first error
	for i := len(l.files) - 1; i >= 0; i-- {
		if err := l.files[i].file.close(); err != nil && first == nil {
			first = err
		}
	}
	l.files = nil
	return first
}

// ValidateInstallDestination checks the exact final publication leaf without
// creating or following any path component.
func ValidateInstallDestination(path string) error {
	return validateDestinationPath(path)
}

// PublicationResult records whether the destination rename crossed the
// publication boundary. A committed result must be classified as committed
// even when a later durability or descriptor-close operation reports an error.
type PublicationResult struct {
	Committed bool
}

// PublishExecutable copies source to the exact destination leaf. It refuses a
// symlink or directory at the leaf and never interprets destination as a
// directory containing the source basename.
func PublishExecutable(source, destination string) (PublicationResult, error) {
	return publishExecutable(source, destination)
}
