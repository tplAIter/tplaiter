//go:build !darwin && !linux

package engine

func (f *FirstMarker) acquireLocks() error        { return ErrUnsupported }
func (f *FirstMarker) publishState(bool) error    { return ErrUnsupported }
func (f *FirstMarker) publishRegistry(bool) error { return ErrUnsupported }
