package contextsource

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestNativeNewOpaqueClosureAndCopies(t *testing.T) {
	f := newContextFixture(t, nil)
	ctx := context.Background()
	sources, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	input := NativeNewInput{Render: renderref.Input{Values: settings.Values{}, Project: manifest.ProjectInfo{Name: "Example", Slug: "example", Module: "example.invalid/project"}}, RendererVersion: "1.0.0"}
	p, err := PrepareNativeNew(ctx, f.runtime, sources, input)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	root, err := p.RootLock(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || len(dependencies.Dependencies) != 3 || provenance.ValidateLockPair(root, dependencies) != nil {
		t.Fatalf("complete lock: %+v %v", dependencies, err)
	}
	rendered, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(rendered.Files["hello.txt"]) != "Hello public project.\n" {
		t.Fatalf("root render: %+v %v", rendered, err)
	}
	dependencies.Dependencies[0].Commit = "changed"
	rendered.Files["hello.txt"][0] = 'X'
	rendered.Template.Metadata.Name = "changed"
	rendered.Baseline.Files["hello.txt"] = "changed"
	again, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(again.Files["hello.txt"]) != "Hello public project.\n" || again.Template.Metadata.Name == "changed" || again.Baseline.Files["hello.txt"] == "changed" {
		t.Fatal("mutable intent")
	}
	locks, err := p.DependencyLock(ctx, f.runtime)
	if err != nil || locks.Dependencies[0].Commit == "changed" {
		t.Fatal("mutable ledger")
	}
	if p.RecheckFor(ctx, &trustload.Runtime{}) == nil {
		t.Fatal("foreign runtime accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.Rendered(cancelled, f.runtime); err == nil {
		t.Fatal("cancel ignored")
	}
	sources.Close()
	if p.RecheckFor(ctx, f.runtime) == nil {
		t.Fatal("closed source carrier accepted")
	}
}

func TestNativeNewRefusesFabricatedIntent(t *testing.T) {
	p := &PreparedNativeNew{}
	if _, err := p.RootLock(context.Background(), &trustload.Runtime{}); err == nil {
		t.Fatal("fabricated intent")
	}
	if _, err := PrepareNativeNew(context.Background(), &trustload.Runtime{}, &PreparedContextSources{}, NativeNewInput{RendererVersion: "1.0.0"}); err == nil {
		t.Fatal("fabricated source grant")
	}
}

func TestNativeNewFreshTypedAnswersPreserveCodecSemantics(t *testing.T) {
	tpl := &manifest.Template{Settings: []manifest.SettingGroup{
		{Group: "text", Type: manifest.TypeString},
		{Group: "count", Type: manifest.TypeInt},
		{Group: "enabled", Type: manifest.TypeToggle},
		{Group: "choice", Type: manifest.TypeSelect, Options: []manifest.Option{{ID: "current"}, {ID: "retired", Deprecated: true}, {ID: "future", Status: manifest.StatusPlanned}}},
		{Group: "many", Type: manifest.TypeMultiselect, Options: []manifest.Option{{ID: "current"}, {ID: "retired", Deprecated: true}}},
		{Group: "retiredGroup", Type: manifest.TypeString, Deprecated: true},
	}}
	values := settings.Values{"text": "  keep = text\n", "count": 3, "enabled": true, "choice": "current", "many": []string{"current"}}
	if err := validateNativeNewValues(tpl, values); err != nil {
		t.Fatal(err)
	}
	resolved, err := settings.Resolve(tpl, values)
	if err != nil || resolved.Values["text"] != values["text"] || resolved.Values["count"] != 3 || resolved.Values["enabled"] != true {
		t.Fatalf("fresh typed answers changed: %+v %v", resolved, err)
	}
	if err := validateNativeNewValues(tpl, settings.Values{"choice": "", "many": []string{}}); err != nil {
		t.Fatalf("existing unselected zeros refused: %v", err)
	}
	for name, values := range map[string]settings.Values{
		"wrong-string": {"text": 3}, "wrong-int": {"count": "3"}, "wrong-toggle": {"enabled": "true"},
		"unknown-group": {"absent": true}, "unknown-option": {"choice": "absent"}, "planned-option": {"choice": "future"},
		"deprecated-option": {"choice": "retired"}, "deprecated-list": {"many": []string{"current", "retired"}},
		"deprecated-group": {"retiredGroup": "new answer"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateNativeNewValues(tpl, values); err == nil {
				t.Fatal("invalid fresh answer accepted")
			}
		})
	}
}
