//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package contextpack

import (
	"runtime"
)

func newSourceReader(string) (sourceReader, error) {
	return nil, unsupportedSourceReadingError{platform: runtime.GOOS}
}
