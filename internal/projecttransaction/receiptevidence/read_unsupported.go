//go:build !darwin && !linux

package receiptevidence

import "context"

type physicalFact struct{ device, inode uint64 }
type directoryHandle struct{}

func openDirectory(context.Context, string) (*directoryHandle, error) { return nil, ErrAuthentication }
func (*directoryHandle) check() error                                 { return ErrAuthentication }
func (*directoryHandle) close()                                       {}
func (*directoryHandle) private() error                               { return ErrAuthentication }
func (*directoryHandle) read(context.Context, string, int64, *int64) ([]byte, physicalFact, error) {
	return nil, physicalFact{}, ErrAuthentication
}
func readPhysical(context.Context, string, int64, *int64) ([]byte, physicalFact, error) {
	return nil, physicalFact{}, ErrAuthentication
}

func (*directoryHandle) observe(string) (physicalFact, error) {
	return physicalFact{}, ErrAuthentication
}
