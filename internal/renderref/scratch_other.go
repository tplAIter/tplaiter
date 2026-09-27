//go:build !darwin && !linux

package renderref

import "errors"

type scratchDirectory struct{}

func openScratch(string) (*scratchDirectory, error) {
	return nil, errors.New("renderref: secure scratch unsupported")
}
func (*scratchDirectory) Path() string { return "" }
func (*scratchDirectory) Close() error { return nil }
func (*scratchDirectory) ReadFile(string) ([]byte, error) {
	return nil, errors.New("renderref: secure scratch unsupported")
}
func (*scratchDirectory) Check() error { return errors.New("renderref: secure scratch unsupported") }
