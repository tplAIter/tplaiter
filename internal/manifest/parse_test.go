package manifest

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

const testdataDir = "../../testdata/manifest"

func fixture(name string) string { return filepath.Join(testdataDir, name) }

func TestLoadTemplate_Full(t *testing.T) {
	tpl, err := LoadTemplate(fixture("full.yaml"))
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	if tpl.Metadata.Name != "go-service" {
		t.Errorf("metadata.name = %q", tpl.Metadata.Name)
	}
	if tpl.Metadata.Version != "1.4.0" {
		t.Errorf("metadata.version = %q", tpl.Metadata.Version)
	}
	if len(tpl.Settings) != 3 {
		t.Fatalf("settings = %d, want 3", len(tpl.Settings))
	}
	if tpl.Settings[0].Group != "database" || tpl.Settings[0].Type != TypeSelect {
		t.Errorf("settings[0] = %+v", tpl.Settings[0])
	}
	// Nested idempotency group under the postgres option.
	pg := tpl.Settings[0].Options[1]
	if pg.ID != "postgres" || len(pg.Settings) != 1 || pg.Settings[0].Group != "idempotency" {
		t.Errorf("postgres option = %+v", pg)
	}
	if tpl.Settings[0].Options[2].Status != StatusPlanned {
		t.Errorf("mysql status = %q", tpl.Settings[0].Options[2].Status)
	}
	if tpl.Commands["migrate-up"].When != "database=postgres" {
		t.Errorf("migrate-up when = %q", tpl.Commands["migrate-up"].When)
	}
	if len(tpl.Hooks.PostCreate) != 3 {
		t.Errorf("postCreate hooks = %d", len(tpl.Hooks.PostCreate))
	}
}

func TestLoadRepository(t *testing.T) {
	repo, err := LoadRepository(fixture("repo.yaml"))
	if err != nil {
		t.Fatalf("LoadRepository: %v", err)
	}
	if repo.Metadata.Name != "example-templates" {
		t.Errorf("metadata.name = %q", repo.Metadata.Name)
	}
	if len(repo.Templates) != 3 || repo.Templates[0].Path != "go-service/" {
		t.Errorf("templates = %+v", repo.Templates)
	}
}

func TestLoadProject(t *testing.T) {
	p, err := LoadProject(fixture("project.yaml"))
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if p.Project.Slug != "billing-service" {
		t.Errorf("project.slug = %q", p.Project.Slug)
	}
	if p.Runtime.Port != 8081 {
		t.Errorf("runtime.port = %d", p.Runtime.Port)
	}
	if v, ok := p.Settings["database"].(string); !ok || v != "postgres" {
		t.Errorf("settings.database = %v", p.Settings["database"])
	}
	if v, ok := p.Settings["idempotency"].(bool); !ok || !v {
		t.Errorf("settings.idempotency = %v", p.Settings["idempotency"])
	}
}

func TestLoadTemplate_ForeignAPIVersion(t *testing.T) {
	_, err := LoadTemplate(fixture("invalid/foreign_apiversion.yaml"))
	if err == nil {
		t.Fatal("expected an error for a foreign apiVersion")
	}
	if !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedAPIVersion", err)
	}
	if !strings.Contains(err.Error(), "update tplaiter") {
		t.Errorf("message does not ask to update: %v", err)
	}
}

func TestLoadTemplate_UnknownField(t *testing.T) {
	_, err := LoadTemplate(fixture("invalid/unknown_field.yaml"))
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
	if !strings.Contains(err.Error(), "bogusField") {
		t.Errorf("error does not point to the unknown field: %v", err)
	}
}

func TestLoadTemplate_WrongKind(t *testing.T) {
	// project.yaml has kind Project; LoadTemplate must reject it.
	_, err := LoadTemplate(fixture("project.yaml"))
	if err == nil {
		t.Fatal("expected an invalid kind error")
	}
}

func TestCheckAPIVersion(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"tplater.dev/v1alpha1", false},
		{"tplater.dev/v1beta2", false},
		{"tplater.dev/v1", false},
		{"tplater.dev/v2alpha1", true},
		{"other.dev/v1alpha1", true},
		{"tplater.dev", true},
		{"", true},
		{"tplater.dev/alpha", true},
	}
	for _, tc := range tests {
		err := checkAPIVersion(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkAPIVersion(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

func TestDeprecatedDeclarationStrictBoolean(t *testing.T) {
	for _, where := range []string{"  deprecated: %s\n  type: toggle", "  type: select\n  options:\n    - id: old\n      deprecated: %s"} {
		for _, val := range []string{"null", "\"true\"", "1", "[]", "{}"} {
			raw := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nsettings:\n- group: feature\n" + fmt.Sprintf(where, val) + "\n")
			if _, err := ParseTemplate(raw); err == nil {
				t.Fatal("bad boolean accepted", val)
			}
		}
	}
	raw := []byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\nsettings:\n- group: feature\n  type: toggle\n  deprecated: true\n")
	tpl, err := ParseTemplate(raw)
	if err != nil || !tpl.Settings[0].Deprecated {
		t.Fatalf("bool rejected %v", err)
	}
	if _, err := ParseTemplate(append(raw, []byte("  unknown: true\n")...)); err == nil {
		t.Fatal("KnownFields bypassed")
	}
}

func TestDeprecatedMergedBooleanCannotBecomeFalse(t *testing.T) {
	for _, raw := range []string{
		"settings:\n - &base {group: a, type: toggle, deprecated: null}\n - {<<: *base, group: b}\n",
		"settings:\n - &base {group: a, type: toggle, deprecated: false}\n - {<<: *base, group: b, deprecated: null}\n",
	} {
		if _, err := ParseTemplate([]byte("apiVersion: tplater.dev/v1alpha1\nkind: Template\n" + raw)); err == nil {
			t.Fatal("merged null accepted")
		}
	}
}

func TestManagedReplacementDeclarationStrict(t *testing.T) {
	prefix := "apiVersion: tplater.dev/v1alpha1\nkind: Template\nmetadata: {name: example, version: 1.0.0}\nengine: {type: go-template, root: template}\n"
	valid := "managedBlocks:\n  version: 1\n  replacements:\n    - {path: x.go, provider: root, oldID: old, newID: next}\n"
	tpl, err := ParseTemplate([]byte(prefix + valid))
	if err != nil || tpl.ManagedBlocks == nil || tpl.Validate() != nil {
		t.Fatalf("signed replacement: %v", err)
	}
	for _, bad := range []string{"managedBlocks: null\n", "managedBlocks: {version: '1', replacements: []}\n", "managedBlocks: {version: 1, replacements: null}\n", "managedBlocks: {version: 1, replacements: [{path: x.go, provider: root, oldID: old, newID: next, extra: x}]}\n"} {
		if _, err := ParseTemplate([]byte(prefix + bad)); err == nil {
			t.Fatal("invalid declaration parsed")
		}
	}
}
