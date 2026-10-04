//go:build !linux && !darwin

package ossinstall

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
)

func defaultEntropy() io.Reader { return rand.Reader }
func syncDirectory(string) error {
	return errors.New("ossinstall: durable publication unavailable on this platform")
}

func readConfined(string, string) ([]byte, error) {
	return nil, errors.New("ossinstall: confined publication unavailable on this platform")
}

func publishImmutable(string, string, []byte) error {
	return errors.New("ossinstall: confined publication unavailable on this platform")
}

func publishInstallation(string, string) error {
	return ErrPublicationUnsupported
}

func publishInstallationWithContext(context.Context, string, string, ...func() error) (bool, error) {
	return false, ErrPublicationUnsupported
}
