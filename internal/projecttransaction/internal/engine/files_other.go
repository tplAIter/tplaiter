//go:build !darwin && !linux

package engine

import (
	"context"
	"os"
)

func fileID(os.FileInfo) Identity               { return Identity{} }
func singleLink(os.FileInfo) bool               { return false }
func readNoFollow() int                         { return os.O_RDONLY }
func exclusiveFlags() int                       { return os.O_WRONLY | os.O_CREATE | os.O_EXCL }
func writeLockFlags() int                       { return os.O_RDWR | os.O_CREATE }
func lock(*os.File) error                       { return ErrAuthentication }
func (t *Transaction) publish(step, bool) error { return ErrAuthentication }
func (t *Transaction) quarantine(step) error    { return ErrAuthentication }

func (t *Transaction) acquireWriterLocks() error { return ErrAuthentication }

func stageDirectory(context.Context, string, os.FileMode) error { return ErrAuthentication }

func receiptReadFlags() int { return readNoFollow() }
