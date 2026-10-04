package trustload

import (
	"errors"
	"testing"
)

func TestRuntimeInstallProjectIdentityIsUnambiguous(t *testing.T) {
	for _, tc := range []struct{ name, id, root string }{
		{"duplicate ID", "project.test", "/var/tmp/another-project"},
		{"duplicate root", "another.id", "/var/tmp/tplaiter-project"},
		{"nested root", "another.id", "/var/tmp/tplaiter-project/sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := validInstall()
			other := v.ProjectContexts[0]
			other.Key = "other"
			other.ProjectID = tc.id
			other.RootPath = tc.root
			v.ProjectContexts = append(v.ProjectContexts, other)
			if err := v.Validate(); !errors.Is(err, ErrConfigInvalid) {
				t.Fatalf("ambiguous selected identity: %v", err)
			}
		})
	}
	v := validInstall()
	other := v.ProjectContexts[0]
	other.Key = "other"
	other.ProjectID = "other.id"
	other.RootPath = "/var/tmp/another-project"
	v.ProjectContexts = append(v.ProjectContexts, other)
	if err := v.Validate(); err != nil {
		t.Fatalf("distinct IDs and roots rejected: %v", err)
	}
}
