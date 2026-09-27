package manifest

import (
	"errors"
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
		t.Fatal("ожидалась ошибка для чужого apiVersion")
	}
	if !errors.Is(err, ErrUnsupportedAPIVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedAPIVersion", err)
	}
	if !strings.Contains(err.Error(), "обнови tplater") {
		t.Errorf("сообщение не содержит призыв обновиться: %v", err)
	}
}

func TestLoadTemplate_UnknownField(t *testing.T) {
	_, err := LoadTemplate(fixture("invalid/unknown_field.yaml"))
	if err == nil {
		t.Fatal("ожидалась ошибка для неизвестного поля")
	}
	if !strings.Contains(err.Error(), "bogusField") {
		t.Errorf("ошибка не указывает на неизвестное поле: %v", err)
	}
}

func TestLoadTemplate_WrongKind(t *testing.T) {
	// project.yaml has kind Project; LoadTemplate must reject it.
	_, err := LoadTemplate(fixture("project.yaml"))
	if err == nil {
		t.Fatal("ожидалась ошибка неверного kind")
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
