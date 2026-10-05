package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ErrUnsupportedAPIVersion is returned when this tplaiter does not support the
// contract major version (the message asks the user to update).
var ErrUnsupportedAPIVersion = errors.New("unsupported contract API version")

// LoadTemplate reads and parses a template manifest at path. Unknown fields are
// rejected (KnownFields), and apiVersion and kind are checked. Content validation
// (§9) is separately performed by [Template.Validate].
func LoadTemplate(path string) (*Template, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := decodeStrict(data, &t); err != nil {
		return nil, fmt.Errorf("parsing template manifest %s: %w", path, err)
	}
	if err := checkKind(t.APIVersion, t.Kind, KindTemplate); err != nil {
		return nil, err
	}
	return &t, nil
}

// LoadRepository reads, parses and validates a multi-template repository
// manifest. Path-level validation ([Repository.Validate]) runs here so that
// every consumer (repository indexing, lint) rejects absolute, ".." and
// duplicate templates[].path entries with the same typed error.
func LoadRepository(path string) (*Repository, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var r Repository
	if err := decodeStrict(data, &r); err != nil {
		return nil, fmt.Errorf("parsing repository manifest %s: %w", path, err)
	}
	if err := checkKind(r.APIVersion, r.Kind, KindRepository); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// LoadProject reads and parses the .tplaiter/project.yaml project marker.
func LoadProject(path string) (*Project, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var p Project
	if err := decodeStrict(data, &p); err != nil {
		return nil, fmt.Errorf("parsing project marker %s: %w", path, err)
	}
	if err := checkKind(p.APIVersion, p.Kind, KindProject); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseTemplate parses a template manifest from bytes without reading a file, for
// snapshots and tests.
func ParseTemplate(data []byte) (*Template, error) {
	var t Template
	if err := decodeStrict(data, &t); err != nil {
		return nil, fmt.Errorf("parsing template manifest: %w", err)
	}
	if err := checkKind(t.APIVersion, t.Kind, KindTemplate); err != nil {
		return nil, err
	}
	return &t, nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %s: %w", path, err)
	}
	return data, nil
}

// decodeStrict parses YAML with KnownFields(true): any unknown field is an error
// with line and column coordinates from yaml.v3.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// checkKind validates kind and the apiVersion major version. It parses apiVersion
// first: an incompatible major takes precedence over any other error because the
// user must update the CLI first.
func checkKind(apiVersion, kind, want string) error {
	if err := checkAPIVersion(apiVersion); err != nil {
		return err
	}
	if kind != want {
		return fmt.Errorf("expected kind %q, got %q", want, kind)
	}
	return nil
}

// checkAPIVersion validates the contract group and major version.
func checkAPIVersion(apiVersion string) error {
	if apiVersion == "" {
		return fmt.Errorf("%w: apiVersion field is empty (expected %s)", ErrUnsupportedAPIVersion, APIVersion)
	}
	group, version, ok := splitAPIVersion(apiVersion)
	if !ok || group != APIGroup {
		return fmt.Errorf("%w: unknown apiVersion %q (expected group %s)", ErrUnsupportedAPIVersion, apiVersion, APIGroup)
	}
	major, ok := parseMajor(version)
	if !ok {
		return fmt.Errorf("%w: could not determine major version in apiVersion %q", ErrUnsupportedAPIVersion, apiVersion)
	}
	if major != SupportedMajor {
		return fmt.Errorf(
			"%w: manifest uses major v%d (%s), but this tplaiter supports v%d — update tplaiter",
			ErrUnsupportedAPIVersion, major, apiVersion, SupportedMajor,
		)
	}
	return nil
}

// splitAPIVersion splits "group/version" into its parts.
func splitAPIVersion(s string) (group, version string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// parseMajor extracts an integer major from a version like "v1alpha1" → 1.
func parseMajor(version string) (int, bool) {
	if len(version) < 2 || version[0] != 'v' {
		return 0, false
	}
	major := 0
	digits := 0
	for i := 1; i < len(version); i++ {
		c := version[i]
		if c < '0' || c > '9' {
			break
		}
		major = major*10 + int(c-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return major, true
}
