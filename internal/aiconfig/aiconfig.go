// Package aiconfig загружает централизованный источник AI-правил (каталог
// ai-config/) и рендерит из него per-tool артефакты (CLAUDE.md,
// .cursor/**, AGENTS.md, GEMINI.md) в корень проекта.
//
// Источник (перенос go-template WP-19, ставшего частью контракта tplater)
// состоит из:
//   - config.json          — язык, целевые инструменты, длина строки;
//   - modules/NN-*.json     — декларации модулей правил (активация, globs, when);
//   - rules/NN-*.md         — «быстрая справка» (компактные примеры);
//   - docs/*.md             — «толстые» доки с эталонным кодом;
//   - targets/*.tmpl        — text/template композиции под каждый инструмент.
//
// Главное отличие от go-template: гейтинг модуля — поле `when` в терминах
// мини-языка условий §3.2 (settings.Eval), а не булева `feature` из бинарного
// реестра фич. Как и в [gen], сам источник (каталог ai-config) — не встроенный
// в бинарник embed, а копия внутри проекта: [AIConfigRelPath] — контракт с
// связанными компонентами /, симметричный gen.GeneratorsRelPath.
package aiconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ConfigFileName — имя корневого конфига источника.
const ConfigFileName = "config.json"

// AIConfigRelPath — путь каталога-копии ai-config в сгенерированном проекте
// относительно его корня. `tplater new` копирует сюда каталог,
// на который указывает aiConfig.path манифеста шаблона (контракт с /).
const AIConfigRelPath = ".tplaiter/ai-config"

// Activation-типы модулей (соответствуют способам подключения правил в Cursor).
const (
	ActivationAlways   = "always"
	ActivationGlobs    = "globs"
	ActivationSemantic = "semantic"
)

// Config — модель config.json.
type Config struct {
	Language     string   `json:"language"`
	CodeLanguage string   `json:"code_language"`
	Targets      []string `json:"targets"`
	LineLength   int      `json:"line_length"`
}

// Module — декларация одного модуля правил (modules/NN-*.json). When — условие
// активации в терминах §3.2 (пусто — модуль безусловный); замена
// go-template'овского Feature *string.
type Module struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Activation  string   `json:"activation"`
	Globs       []string `json:"globs"`
	Description string   `json:"description"`
	When        string   `json:"when"`
	RuleFile    string   `json:"rule_file"`
	DocFile     string   `json:"doc_file"`
}

// LoadedModule — модуль с прочитанным содержимым rule/doc и производными именами.
type LoadedModule struct {
	Module

	// Rule — содержимое rule_file (быстрая справка).
	Rule string
	// Doc — содержимое doc_file (толстый док).
	Doc string
	// DocBase — базовое имя doc-файла с расширением (напр. "base.md").
	DocBase string
	// DocName — базовое имя doc-файла без расширения (напр. "base").
	DocName string
	// RuleName — базовое имя rule-файла без расширения (напр. "00-base").
	RuleName string
}

// Source — загруженный источник ai-config (конфиг + все модули).
type Source struct {
	// Dir — корневой каталог источника (ai-config/).
	Dir string
	// Config — прочитанный config.json.
	Config Config
	// Modules — все модули, отсортированные по ID.
	Modules []LoadedModule
}

// Load читает config.json и все модули из каталога dir, читает их rule/doc-файлы.
// Валидация схемы выполняется отдельно методом [Source.Validate].
func Load(dir string) (*Source, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	modules, err := loadModules(dir)
	if err != nil {
		return nil, err
	}
	return &Source{Dir: dir, Config: cfg, Modules: modules}, nil
}

// loadConfig читает и парсит config.json.
func loadConfig(dir string) (Config, error) {
	path := filepath.Join(dir, ConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("aiconfig: чтение %s: %w", path, err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("aiconfig: разбор %s: %w", path, err)
	}
	return cfg, nil
}

// loadModules читает modules/*.json, подтягивает содержимое rule/doc и сортирует по ID.
func loadModules(dir string) ([]LoadedModule, error) {
	modulesDir := filepath.Join(dir, "modules")
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return nil, fmt.Errorf("aiconfig: чтение каталога modules %s: %w", modulesDir, err)
	}

	modules := make([]LoadedModule, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		m, err := loadModule(dir, filepath.Join(modulesDir, e.Name()))
		if err != nil {
			return nil, err
		}
		modules = append(modules, m)
	}

	sort.Slice(modules, func(i, j int) bool { return modules[i].ID < modules[j].ID })
	return modules, nil
}

// loadModule парсит один module-json и читает связанные rule/doc-файлы.
func loadModule(root, path string) (LoadedModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LoadedModule{}, fmt.Errorf("aiconfig: чтение модуля %s: %w", path, err)
	}
	var m Module
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return LoadedModule{}, fmt.Errorf("aiconfig: разбор модуля %s: %w", path, err)
	}

	loaded := LoadedModule{Module: m}
	if m.RuleFile != "" {
		content, err := os.ReadFile(filepath.Join(root, m.RuleFile))
		if err != nil {
			return LoadedModule{}, fmt.Errorf("aiconfig: чтение rule %s (модуль %s): %w", m.RuleFile, m.ID, err)
		}
		loaded.Rule = string(content)
		loaded.RuleName = baseName(m.RuleFile)
	}
	if m.DocFile != "" {
		content, err := os.ReadFile(filepath.Join(root, m.DocFile))
		if err != nil {
			return LoadedModule{}, fmt.Errorf("aiconfig: чтение doc %s (модуль %s): %w", m.DocFile, m.ID, err)
		}
		loaded.Doc = string(content)
		loaded.DocBase = filepath.Base(m.DocFile)
		loaded.DocName = baseName(m.DocFile)
	}
	return loaded, nil
}

// baseName возвращает имя файла без каталога и расширения.
func baseName(p string) string {
	b := filepath.Base(p)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// Filter возвращает модули, применимые при заданных значениях настроек:
// безусловные (When == "") плюс те, чьё when истинно (settings.Eval, §3.2).
// Неразбираемое условие или ссылка на неизвестную группу — ошибка (аборт):
// такой module.when — баг ai-config, который должен ловить [Source.Validate]
// заранее, а не тихо исключать модуль из вывода молча (симметрично решению
// engine.compileFileRules для files-правил).
func (s *Source) Filter(values settings.Values) ([]LoadedModule, error) {
	out := make([]LoadedModule, 0, len(s.Modules))
	for _, m := range s.Modules {
		if m.When == "" {
			out = append(out, m)
			continue
		}
		ok, err := evalWhen(m.When, values)
		if err != nil {
			return nil, fmt.Errorf("aiconfig: модуль %s: when %q: %w", m.ID, m.When, err)
		}
		if ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// evalWhen разбирает и вычисляет условие when модуля (§3.2, конъюнкция через &&).
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}
