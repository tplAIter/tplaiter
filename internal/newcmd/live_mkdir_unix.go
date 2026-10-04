//go:build darwin || linux

package newcmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/newtransaction"
)

func mkdirLiveDirectory(root *os.Root, name string, expectedParent os.FileInfo) error {
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := execx.MkdirAtParent(context.Background(), parent, expectedParent, filepath.Base(name)); err != nil {
		return errors.Join(newtransaction.ErrOwnershipUncertain, err)
	}
	return nil
}
