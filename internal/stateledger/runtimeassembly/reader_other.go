//go:build !darwin && !linux

package runtimeassembly

import (
	"context"
	"errors"
)

type readCoordination struct{}

func (*readCoordination) close()         {}
func (*readCoordination) complete() bool { return false }
func (*readCoordination) check(context.Context) error {
	return errors.New("stateledger: read coordination unavailable")
}

func holdReaders(context.Context, string, string) (*readCoordination, error) {
	return nil, errors.New("stateledger: read coordination unavailable")
}
