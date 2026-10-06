//go:build !darwin && !linux

package engine

import "context"

func (f *FirstMarker) acquireLocks() error                         { return ErrUnsupported }
func (f *FirstMarker) publishState(context.Context, bool) error    { return ErrUnsupported }
func (f *FirstMarker) publishRegistry(context.Context, bool) error { return ErrUnsupported }
