package settings

import (
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// loadFixture загружает и валидирует манифест-фикстуру пакета.
func loadFixture(t *testing.T, name string) *manifest.Template {
	t.Helper()
	tpl, err := manifest.LoadTemplate(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", name, err)
	}
	if err := tpl.Validate(); err != nil {
		t.Fatalf("фикстура %s невалидна: %v", name, err)
	}
	return tpl
}

// loadRepoFixture загружает фикстуру из общего testdata репозитория.
func loadRepoFixture(t *testing.T, name string) *manifest.Template {
	t.Helper()
	tpl, err := manifest.LoadTemplate(filepath.Join("..", "..", "testdata", "manifest", name))
	if err != nil {
		t.Fatalf("LoadTemplate(%s): %v", name, err)
	}
	return tpl
}
