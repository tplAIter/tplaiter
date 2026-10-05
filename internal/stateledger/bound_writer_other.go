//go:build !darwin && !linux

package stateledger

import (
	"context"
	"os"
)

type BoundMigrationWriter struct{ rootPath string }

func BindMigrationWriter(context.Context, string, *os.File, *os.File, *os.File, *os.File, *os.File) (*BoundMigrationWriter, error) {
	return nil, ErrUnsafe
}
func (*BoundMigrationWriter) Close()                                      {}
func (*BoundMigrationWriter) Check(context.Context) error                 { return ErrUnsafe }
func (*BoundMigrationWriter) write(context.Context, string, []byte) error { return ErrUnsafe }
func ApplyPlanBoundContext(context.Context, string, Options, string, *BoundMigrationWriter) (*MigrationPlan, error) {
	return nil, ErrUnsafe
}
