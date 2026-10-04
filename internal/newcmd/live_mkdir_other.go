//go:build !darwin && !linux

package newcmd

import (
	"os"

	"github.com/tplAIter/tplaiter/internal/newtransaction"
)

// Other platforms have no reviewed exact-mode mkdir primitive for live new.
func mkdirLiveDirectory(*os.Root, string, os.FileInfo) error {
	return newtransaction.ErrOwnershipUncertain
}
