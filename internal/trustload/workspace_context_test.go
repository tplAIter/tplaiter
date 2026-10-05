package trustload

import (
	"context"
	"path/filepath"
	"testing"
)

func TestInstalledWorkspaceContextConfinement(t *testing.T) {
	for _, scenario := range []string{"valid", "parent-last", "unlinked", "unknown-parent", "outside-services", "nested-service", "duplicate-root", "linked-parent"} {
		t.Run(scenario, func(t *testing.T) {
			v := validInstall()
			parent := v.ProjectContexts[0]
			child := parent
			child.Key = "billing"
			child.ProjectID = "billing-id"
			child.RootPath = filepath.Join(parent.RootPath, "services", "billing")
			child.WorkspaceContext = parent.Key
			switch scenario {
			case "unlinked":
				child.WorkspaceContext = ""
			case "unknown-parent":
				child.WorkspaceContext = "absent"
			case "outside-services":
				child.RootPath = filepath.Join(parent.RootPath, "billing")
			case "nested-service":
				child.RootPath = filepath.Join(parent.RootPath, "services", "billing", "nested")
			case "duplicate-root":
				child.RootPath = parent.RootPath
			case "linked-parent":
				parent.WorkspaceContext = child.Key
			}
			v.ProjectContexts = []ProjectContext{parent, child}
			if scenario == "parent-last" {
				v.ProjectContexts = []ProjectContext{child, parent}
			}
			err := v.Validate()
			if scenario == "valid" || scenario == "parent-last" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unadmitted overlapping root accepted")
			}
		})
	}
}

func TestWorkspaceRuntimeInstallationPair(t *testing.T) {
	requireNativeStore(t)
	f := runtimeFixture(t)
	open := func(selection LaunchSelection) *Runtime {
		t.Helper()
		r, err := OpenRuntime(context.Background(), RuntimeOptions{Selection: selection, ProjectKey: "project", Clock: fixedRuntimeClock{}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	first, same := open(f.selection), open(f.selection)
	other := open(runtimeFixture(t).selection)
	if !first.SharesInstallation(same) || first.SharesInstallation(other) || first.SharesInstallation(nil) || (&Runtime{}).SharesInstallation(&Runtime{}) {
		t.Fatal("installation pairing failed closed")
	}
	same.Close()
	if first.SharesInstallation(same) {
		t.Fatal("closed runtime admitted")
	}
}
