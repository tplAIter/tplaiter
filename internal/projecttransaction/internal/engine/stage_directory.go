//go:build darwin || linux

package engine

import (
	"context"
	"os"

	"github.com/tplAIter/tplaiter/internal/execx"
)

// Only newly staged public directories use the accepted fixed child mkdir.
// No global umask change or chmod of an existing/foreign directory occurs.
func stageDirectory(ctx context.Context, name string, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if mode != 0o755 {
		return confinedMkdir(name, mode)
	}
	parent, base, err := confinedParent(name)
	if err != nil {
		return err
	}
	defer parent.Close()
	f, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := execx.MkdirAtParent(ctx, f, info, base); err != nil {
		return err
	}
	return checkStorageParent(parent, name)
}
