//go:build !darwin && !linux

package evidencecas

import "errors"

type casRoot struct{}

func openCASRoot(string) (*casRoot, error) {
	return nil, errors.New("evidencecas: platform does not support strict descriptor CAS reads")
}

func (*casRoot) read(string) ([]byte, error) {
	return nil, errors.New("evidencecas: platform unsupported")
}
func (*casRoot) close() error { return nil }
