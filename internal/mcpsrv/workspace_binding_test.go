package mcpsrv

import (
	"reflect"
	"testing"
)

func TestNativeWorkspaceBindingArguments(t *testing.T) {
	a := workspaceAddServiceArgs{Name: "billing", ProjectContext: "workspace", ServiceContext: "billing-context", SourceInput: "/signed/service.json", DryRun: true, Defaults: true}
	got := argvNativeWorkspaceAddService(a, "/registered/workspace")
	want := []string{"workspace", "add-service", "billing", "--defaults", "--no-env-setup", "--yes", "--dir", "/registered/workspace", "--service-context", "billing-context", "--source-input", "/signed/service.json", "--project-context", "workspace", "--dry-run"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native context/source transport: %v", got)
	}
}
