package repo

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/state"
)

// newTestManager строит менеджер с временным home и записывает переданный
// индекс. runner/authStore не нужны для ResolveRef.
func newTestManager(t *testing.T, idx state.Index) (*Manager, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	if err := state.SaveIndex(home, idx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	var errBuf bytes.Buffer
	m := New(home, nil, nil, UI{Out: &bytes.Buffer{}, Err: &errBuf})
	return m, &errBuf
}

func sampleIndex() state.Index {
	idx := state.NewIndex(time.Now())
	idx.Repos["example"] = []state.TemplateEntry{
		{
			Name: "go-service", Version: "1.1.0", Path: "go-service", Ref: "main",
			Tags: []string{"go-service/v1.1.0", "go-service/v1.0.0"},
		},
		{
			Name: "python-service", Version: "0.1.0", Path: "python-service", Ref: "main",
		}, // без тегов
	}
	idx.Repos["contrib"] = []state.TemplateEntry{
		{
			Name: "go-service", Version: "2.0.0", Path: ".", Ref: "trunk",
			Tags: []string{"v2.0.0"},
		},
	}
	return idx
}

func TestResolveRef_FullForm(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	got, err := m.ResolveRef("example/go-service@v1.0.0")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got.RepoAlias != "example" || got.GitRef != "go-service/v1.0.0" || got.Version != "v1.0.0" {
		t.Errorf("got %+v", got)
	}
}

func TestResolveRef_ShortUnique(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	// python-service уникально → короткая форма разрешима, без тегов → latest.
	got, err := m.ResolveRef("python-service")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got.RepoAlias != "example" || got.Version != "latest" || got.GitRef != "main" {
		t.Errorf("got %+v", got)
	}
}

func TestResolveRef_ShortAmbiguous(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	_, err := m.ResolveRef("go-service")
	if err == nil {
		t.Fatal("ожидалась ошибка неоднозначности")
	}
	// В сообщении — оба кандидата.
	if !strings.Contains(err.Error(), "example/go-service") || !strings.Contains(err.Error(), "contrib/go-service") {
		t.Errorf("ошибка без списка кандидатов: %v", err)
	}
}

func TestResolveRef_DefaultHighestStable(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	got, err := m.ResolveRef("example/go-service")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	// Старший стабильный тег.
	if got.GitRef != "go-service/v1.1.0" || got.Version != "v1.1.0" {
		t.Errorf("got %+v, want v1.1.0", got)
	}
}

func TestResolveRef_Latest(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	got, err := m.ResolveRef("example/go-service@latest")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got.GitRef != "main" || got.Version != "latest" {
		t.Errorf("got %+v, want ref=main version=latest", got)
	}
}

func TestResolveRef_NoTagsWarns(t *testing.T) {
	m, errBuf := newTestManager(t, sampleIndex())
	got, err := m.ResolveRef("example/python-service")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	if got.GitRef != "main" || got.Version != "latest" {
		t.Errorf("got %+v", got)
	}
	if !strings.Contains(errBuf.String(), "не имеет стабильных тегов") {
		t.Errorf("ожидалось предупреждение об отсутствии тегов, got %q", errBuf.String())
	}
}

func TestResolveRef_UnknownVersion(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	_, err := m.ResolveRef("example/go-service@v9.9.9")
	if err == nil {
		t.Fatal("ожидалась ошибка отсутствующей версии")
	}
	if !strings.Contains(err.Error(), "v1.1.0") {
		t.Errorf("ошибка без списка доступных версий: %v", err)
	}
}

func TestResolveRef_UnknownRepo(t *testing.T) {
	m, _ := newTestManager(t, sampleIndex())
	if _, err := m.ResolveRef("nope/go-service"); err == nil {
		t.Fatal("ожидалась ошибка неизвестного репозитория")
	}
	if _, err := m.ResolveRef("does-not-exist"); err == nil {
		t.Fatal("ожидалась ошибка неизвестного имени")
	}
}
