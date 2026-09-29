package mcpsrv

import (
	"reflect"
	"testing"
)

// TestArgvBuilders is a table-driven test of tool-to-argv mapping: key cases
// from the specification (project_new set map to correct --set pairs; stats
// adds --json; gen params/noBuild to flags; env_setup forces --yes; settings_set
// adds --yes).
func TestArgvBuilders(t *testing.T) {
	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{
			name: "repo_add without branch",
			got:  argvRepoAdd("go", "https://example/go.git", ""),
			want: []string{"repo", "add", "go", "https://example/go.git"},
		},
		{
			name: "repo_add with branch",
			got:  argvRepoAdd("go", "https://example/go.git", "main"),
			want: []string{"repo", "add", "go", "https://example/go.git", "--branch", "main"},
		},
		{
			name: "repo_update all",
			got:  argvRepoUpdate(""),
			want: []string{"repo", "update"},
		},
		{
			name: "repo_update one",
			got:  argvRepoUpdate("go"),
			want: []string{"repo", "update", "go"},
		},
		{
			name: "template_list with filters and labels",
			got:  argvTemplateList("go", "svc", []string{"kind=service", "tier=backend"}),
			want: []string{"template", "list", "--repo", "go", "--name", "svc", "--label", "kind=service", "--label", "tier=backend"},
		},
		{
			name: "project_new with set map, lifecycle flags and port",
			got:  argvProjectNew("go/service", "billing", map[string]string{"broker": "kafka", "api": "rest"}, true, true, true, true, true, 9090),
			want: []string{"new", "go/service", "billing", "--set", "api=rest", "--set", "broker=kafka", "--defaults", "--no-hooks", "--no-deps-check", "--port", "9090", "--no-env-setup", "--yes"},
		},
		{
			name: "project_new without set/port",
			got:  argvProjectNew("go/service", "billing", nil, false, false, false, false, false, 0),
			want: []string{"new", "go/service", "billing"},
		},
		{
			name: "run without args",
			got:  argvRun("build", nil),
			want: []string{"run", "build"},
		},
		{
			name: "run with args after --",
			got:  argvRun("build", []string{"--race", "./..."}),
			want: []string{"run", "build", "--", "--race", "./..."},
		},
		{
			name: "settings_set adds --yes and sorts pairs",
			got:  argvSettingsSet(map[string]string{"logging": "slog", "broker": "nats"}),
			want: []string{"settings", "set", "broker=nats", "logging=slog", "--yes"},
		},
		{
			name: "update with all flags",
			got:  argvUpdate("v2.0.0", true, true),
			want: []string{"update", "--to", "v2.0.0", "--dry-run", "--check"},
		},
		{
			name: "stats always --json",
			got:  argvStats(),
			want: []string{"stats", "--json"},
		},
		{
			name: "gen params to dynamic flags (sorted)",
			got:  argvGen("usecase", "CreateOrder", map[string]string{"fields": "name:string", "aggregate": "Order"}, true),
			want: []string{"gen", "usecase", "CreateOrder", "--aggregate", "Order", "--fields", "name:string", "--no-build"},
		},
		{
			name: "gen without params",
			got:  argvGen("handler", "orders", nil, false),
			want: []string{"gen", "handler", "orders"},
		},
		{
			name: "workspace add-service non-interactive",
			got:  argvWorkspaceAddService("billing", "corp/platform/billing", map[string]string{"database": "postgres"}, true, true, true, 9091),
			want: []string{"workspace", "add-service", "billing", "--module", "corp/platform/billing", "--set", "database=postgres", "--defaults", "--no-hooks", "--no-deps-check", "--port", "9091", "--no-env-setup", "--yes"},
		},
		{
			name: "lint_template with path and combo",
			got:  argvLintTemplate("/abs/repo", "defaults"),
			want: []string{"lint-template", "--path", "/abs/repo", "--combo", "defaults"},
		},
		{
			name: "init_template multi with dir",
			got:  argvInitTemplate("mytpl", "/abs/mytpl", true),
			want: []string{"init-template", "mytpl", "--dir", "/abs/mytpl", "--multi"},
		},
		{
			name: "init_template minimal",
			got:  argvInitTemplate("mytpl", "", false),
			want: []string{"init-template", "mytpl"},
		},
		{
			name: "env_setup forces --yes and omits the default name",
			got:  argvEnvSetup(""),
			want: []string{"env", "setup", "--yes"},
		},
		{
			name: "env_setup with playbook name",
			got:  argvEnvSetup("provision"),
			want: []string{"env", "setup", "provision", "--yes"},
		},
		{
			name: "doctor",
			got:  argvDoctor(),
			want: []string{"doctor"},
		},
		{
			name: "projects_list",
			got:  argvProjectsList(),
			want: []string{"projects", "list"},
		},
		{
			name: "ai_gen",
			got:  argvAIGen(),
			want: []string{"ai", "gen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Errorf("argv mismatch\n got: %#v\nwant: %#v", tt.got, tt.want)
			}
		})
	}
}

func TestArgvGenBatch(t *testing.T) {
	got := argvGenBatch([]genBatchOperation{
		{Kind: "crud", Name: "Ride", Params: map[string]string{"fields": "status:string"}},
		{Kind: "workflow", Name: "MatchRide"},
	}, true)
	want := []string{"gen", "batch", "--operations", `[{"kind":"crud","name":"Ride","params":{"fields":"status:string"}},{"kind":"workflow","name":"MatchRide"}]`, "--no-build"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("argv mismatch\n got: %#v\nwant: %#v", got, want)
	}
}
