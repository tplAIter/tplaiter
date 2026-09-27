//go:build !darwin && !linux

package cmd

import (
	"context"
	"errors"
)

var errRegisteredLock = errors.New("registered lock unavailable")

func readRegisteredLock(context.Context, string, string) ([]byte, error) {
	return nil, errRegisteredLock
}

func readFixedTrustDocument(context.Context, string) ([]byte, error) {
	return nil, errRegisteredLock
}

func readUntrustedDocument(context.Context, string) ([]byte, error) {
	return nil, errRegisteredLock
}

func readRegisteredPreimageFile(context.Context, string, string, int64) ([]byte, error) {
	return nil, errRegisteredLock
}
