//go:build linux

package renderref

import "fmt"

func enginePathForFD(fd int) (string, error) { return fmt.Sprintf("/dev/fd/%d", fd), nil }
