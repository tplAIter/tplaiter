//go:build !darwin && !linux

package runtimeassembly

import (
	"context"
	"errors"

	"github.com/tplAIter/tplaiter/internal/stateledger"
)

type writerLocks struct{}

func (*writerLocks) close() {}
func (*writerLocks) check(context.Context) error {
	return errors.New("stateledger: writer coordination unavailable on this platform")
}

func holdWriters(context.Context, string, string) (*writerLocks, error) {
	return nil, errors.New("stateledger: writer coordination unavailable on this platform")
}

func (*writerLocks) bindMigrationWriter(context.Context) (*stateledger.BoundMigrationWriter, error) {
	return nil, errors.New("stateledger: writer coordination unavailable on this platform")
}
