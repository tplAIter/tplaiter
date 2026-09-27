package aiconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// TestGenFlowFromResolvedSettings воспроизводит путь `tplater ai gen`: разрешает
// настройки проекта (settings.Resolve), валидирует источник ai-config против
// манифеста шаблона и рендерит все таргеты в корень проекта, гейтя модули по
// ActiveValues. Библиотечный e2e — не зависит от пакета cmd.
func TestGenFlowFromResolvedSettings(t *testing.T) {
	tpl := fixtureTemplate()

	resolved, err := settings.Resolve(tpl, settings.Values{
		"database": "postgres",
		"brokers":  []string{"kafka"},
	})
	if err != nil {
		t.Fatalf("settings.Resolve: %v", err)
	}

	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := src.Validate(tpl); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	target := t.TempDir()
	res, err := src.Render(RenderOptions{
		TargetRoot: target,
		Values:     resolved.ActiveValues,
		Project:    manifest.ProjectInfo{Name: "Ai Svc", Slug: "ai_svc", Module: "git.example.test/ai_svc"},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(res.Written) == 0 {
		t.Fatal("no files written")
	}

	for _, rel := range []string{"CLAUDE.md", "GEMINI.md", "AGENTS.md", ".cursorrules"} {
		if _, err := os.Stat(filepath.Join(target, rel)); err != nil {
			t.Errorf("expected %s: %v", rel, err)
		}
	}
	// Гейтинг: postgres/kafka on -> модули присутствуют.
	if _, err := os.Stat(filepath.Join(target, ".cursor", "rules", "02-models.mdc")); err != nil {
		t.Errorf("02-models.mdc must exist (database=postgres): %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".cursor", "rules", "06-kafka.mdc")); err != nil {
		t.Errorf("06-kafka.mdc must exist (brokers contains kafka): %v", err)
	}
}

// TestGenFlowKafkaOff проверяет гейтинг в отрицательную сторону: без kafka в
// brokers модуль 06-kafka не должен рендериться.
func TestGenFlowKafkaOff(t *testing.T) {
	tpl := fixtureTemplate()
	resolved, err := settings.Resolve(tpl, settings.Values{"database": "none"})
	if err != nil {
		t.Fatalf("settings.Resolve: %v", err)
	}

	src, err := Load(writeSyntheticSource(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	target := t.TempDir()
	if _, err := src.Render(RenderOptions{
		TargetRoot: target,
		Values:     resolved.ActiveValues,
		Project:    manifest.ProjectInfo{Name: "Ai Svc", Slug: "ai_svc"},
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}

	if _, err := os.Stat(filepath.Join(target, ".cursor", "rules", "06-kafka.mdc")); err == nil {
		t.Error("06-kafka.mdc must NOT exist (kafka not selected)")
	}
	if _, err := os.Stat(filepath.Join(target, ".cursor", "rules", "02-models.mdc")); err == nil {
		t.Error("02-models.mdc must NOT exist (database=none)")
	}
}
