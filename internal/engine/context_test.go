package engine

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

func testOptions() Options {
	return Options{
		Template: &manifest.Template{
			Metadata: manifest.TemplateMeta{Name: "single-basic", Version: "0.1.0"},
		},
		Resolved: settings.Resolved{
			ActiveValues: settings.Values{"database": "postgres", "brokers": []string{"kafka"}},
		},
		Project: manifest.ProjectInfo{
			Name:   "Demo Svc",
			Slug:   "demo_svc",
			Module: "git.example.test/demo_svc",
			System: "platform",
			Domain: "orders",
		},
		Runtime: manifest.ProjectRuntime{Port: 8080},
		Repo:    "https://github.com/tplAIter/tplaiter-fixtures.git",
	}
}

func TestNewContextDerivedFields(t *testing.T) {
	ctx := NewContext(testOptions())

	if ctx.Project.Name != "Demo Svc" || ctx.Project.Slug != "demo_svc" || ctx.Project.Module != "git.example.test/demo_svc" {
		t.Errorf("Project identity mismatch: %+v", ctx.Project)
	}
	if ctx.Project.System != "platform" || ctx.Project.Domain != "orders" {
		t.Errorf("Project System/Domain mismatch: %+v", ctx.Project)
	}
	if ctx.Project.Pascal != "DemoSvc" {
		t.Errorf("Project.Pascal = %q, want DemoSvc", ctx.Project.Pascal)
	}
	if ctx.Project.Camel != "demoSvc" {
		t.Errorf("Project.Camel = %q, want demoSvc", ctx.Project.Camel)
	}
	if ctx.Project.Kebab != "demo-svc" {
		t.Errorf("Project.Kebab = %q, want demo-svc", ctx.Project.Kebab)
	}
	if ctx.Project.Snake != "demo_svc" {
		t.Errorf("Project.Snake = %q, want demo_svc", ctx.Project.Snake)
	}
	if ctx.Template.Name != "single-basic" || ctx.Template.Version != "0.1.0" {
		t.Errorf("Template mismatch: %+v", ctx.Template)
	}
	if ctx.Template.Repo != "https://github.com/tplAIter/tplaiter-fixtures.git" {
		t.Errorf("Template.Repo = %q", ctx.Template.Repo)
	}
	if ctx.Runtime.Port != 8080 {
		t.Errorf("Runtime.Port = %d, want 8080", ctx.Runtime.Port)
	}
	if !ctx.Settings.Is("database", "postgres") {
		t.Error("Settings.Is(database, postgres) = false, want true")
	}
	if !ctx.Settings.Has("brokers", "kafka") {
		t.Error("Settings.Has(brokers, kafka) = false, want true")
	}
}

func TestContextLookup(t *testing.T) {
	ctx := NewContext(testOptions())
	cases := map[string]string{
		"Project.Name":   "Demo Svc",
		"Project.Slug":   "demo_svc",
		"Project.Module": "git.example.test/demo_svc",
		"Project.System": "platform",
		"Project.Domain": "orders",
		"Project.Pascal": "DemoSvc",
		"Project.Camel":  "demoSvc",
		"Project.Kebab":  "demo-svc",
		"Project.Snake":  "demo_svc",
		"Template.Name":  "single-basic",
		"Runtime.Port":   "8080",
	}
	for key, want := range cases {
		got, ok := ctx.lookup(key)
		if !ok {
			t.Errorf("lookup(%q) ok = false", key)
			continue
		}
		if got != want {
			t.Errorf("lookup(%q) = %q, want %q", key, got, want)
		}
	}
	if _, ok := ctx.lookup("Unknown.Key"); ok {
		t.Error("lookup(Unknown.Key) ok = true, want false")
	}
}

func TestCompilePostReplaceUnknownContextKey(t *testing.T) {
	ctx := NewContext(testOptions())
	_, err := compilePostReplace([]manifest.PostReplace{
		{Glob: "**/*.json", Placeholder: "__X__", ContextKey: "Nope"},
	}, ctx)
	if err == nil {
		t.Error("expected error for unknown contextKey")
	}
}
