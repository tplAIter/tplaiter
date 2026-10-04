//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

// Refuse unsupported platforms rather than falling back to a blocking open.
func openPublicInput(string) (*os.File, error) {
	return nil, errors.New("nonblocking public input unavailable on this platform")
}
