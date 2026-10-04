//go:build !darwin && !linux

package sourcepackage

import (
	"context"
	"errors"
)

func snapshotRepository(context.Context, string) (string, func(), error) {
	return "", nil, errors.New("sourcepackage: confined offline capture unavailable on this platform")
}
