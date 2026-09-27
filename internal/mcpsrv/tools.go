package mcpsrv

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// Все описания tools и их параметров — НА РУССКОМ: их читают AI-агенты, для
// которых этот сервер и предназначен. Схемы типизированы (mcp.NewTypedToolHandler
// связывает JSON-аргументы со структурой).

// registerTools регистрирует ~20 tools поверх подкоманд tplater.
//
// Осознанно НЕ выставлены (см. решения в docs и финальном отчёте):
//   - auth_* / repo add с токеном: секреты через агента — плохая идея; токены
//     заводятся человеком заранее (`tplater repo add` с интерактивным auth или
//     --token-stdin). MCP-сервер stdin подпроцессам не подключает.
//   - upgrade / self-upgrade: git-push/MR и самообновление бинарника из агента
//     без явного подтверждения человека опасны.
func (s *Server) registerTools() {
	s.addRepoTools()
	s.addTemplateTools()
	s.addProjectTools()
	s.addSettingsTools()
	s.addGenTools()
	s.addWorkspaceTools()
	s.addTemplateAuthorTools()
	s.addMiscTools()
}

// ── repo ─────────────────────────────────────────────────────────────────

type repoAddArgs struct {
	Alias  string `json:"alias"`
	URL    string `json:"url"`
	Branch string `json:"branch"`
}

type repoUpdateArgs struct {
	Alias string `json:"alias"`
}

type repoRemoveArgs struct {
	Alias string `json:"alias"`
}

func (s *Server) addRepoTools() {
	s.mcp.AddTool(mcp.NewTool(
		"repo_add",
		mcp.WithDescription("Добавить git-репозиторий шаблонов (helm-модель). Токен НЕ передаётся через агента: приватные репозитории должен предварительно авторизовать человек."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Короткий алиас репозитория")),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL git-репозитория")),
		mcp.WithString("branch", mcp.Description("Ветка по умолчанию (опционально)")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoAddArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoAdd(a.Alias, a.URL, a.Branch), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_list",
		mcp.WithDescription("Список добавленных репозиториев шаблонов (алиас, URL, тип, число шаблонов, время обновления)."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_update",
		mcp.WithDescription("git fetch + переиндексация всех репозиториев шаблонов или одного по алиасу."),
		mcp.WithString("alias", mcp.Description("Алиас репозитория; пусто — обновить все")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoUpdateArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoUpdate(a.Alias), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"repo_remove",
		mcp.WithDescription("Удалить репозиторий шаблонов из локального состояния."),
		mcp.WithString("alias", mcp.Required(), mcp.Description("Алиас удаляемого репозитория")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a repoRemoveArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvRepoRemove(a.Alias), defaultTimeout), nil
	}))
}

// ── template ─────────────────────────────────────────────────────────────

type templateListArgs struct {
	Repo   string   `json:"repo"`
	Name   string   `json:"name"`
	Labels []string `json:"labels"`
}

type templateShowArgs struct {
	Ref string `json:"ref"`
}

func (s *Server) addTemplateTools() {
	s.mcp.AddTool(mcp.NewTool(
		"template_list",
		mcp.WithDescription("Каталог шаблонов добавленных репозиториев с фильтрами."),
		mcp.WithString("repo", mcp.Description("Фильтр по алиасу репозитория (точное совпадение)")),
		mcp.WithString("name", mcp.Description("Фильтр по подстроке имени шаблона")),
		mcp.WithArray("labels", mcp.Description("Фильтры по лейблам group=value (семантика AND)"),
			mcp.Items(map[string]any{"type": "string"})),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateListArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateList(a.Repo, a.Name, a.Labels), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"template_show",
		mcp.WithDescription("Метаданные, дерево настроек, команды и документация шаблона по ссылке ref (repo/name@version или короткая name)."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Ссылка на шаблон: repo/name@version или короткая name")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a templateShowArgs) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvTemplateShow(a.Ref), defaultTimeout), nil
	}))
}

// ── project (new / run / stats / update / doctor / ai) ─────────────────────

type projectNewArgs struct {
	Ref         string            `json:"ref"`
	Name        string            `json:"name"`
	Dir         string            `json:"dir"`
	Set         map[string]string `json:"set"`
	Defaults    bool              `json:"defaults"`
	NoHooks     bool              `json:"noHooks"`
	NoDepsCheck bool              `json:"noDepsCheck"`
	NoEnvSetup  bool              `json:"noEnvSetup"`
	Yes         bool              `json:"yes"`
	Port        int               `json:"port"`
}

type runArgs struct {
	Dir     string   `json:"dir"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type dirArgs struct {
	Dir string `json:"dir"`
}

type updateArgs struct {
	Dir    string `json:"dir"`
	To     string `json:"to"`
	DryRun bool   `json:"dryRun"`
	Check  bool   `json:"check"`
}

type doctorArgs struct {
	Dir string `json:"dir"`
}

func (s *Server) addProjectTools() {
	s.mcp.AddTool(mcp.NewTool(
		"project_new",
		mcp.WithDescription("Создать проект из шаблона (всегда неинтерактивно). Проект создаётся как <dir>/<slug>. При неполноте set сам инструмент вернёт ошибку про обязательные группы — либо задайте defaults=true."),
		mcp.WithString("ref", mcp.Required(), mcp.Description("Ссылка на шаблон: repo/name@version или короткая name")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя нового проекта")),
		mcp.WithString("dir", mcp.Description("Каталог, ВНУТРИ которого создаётся проект (должен существовать); по умолчанию — cwd сервера")),
		mcp.WithObject("set", mcp.Description("Значения настроек: группа→значение (сериализуются в --set пары)")),
		mcp.WithBoolean("defaults", mcp.Description("Взять значения по умолчанию для незаданных групп"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noHooks", mcp.Description("Пропустить hooks.postCreate (--no-hooks)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Пропустить проверку инструментов окружения (--no-deps-check)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noEnvSetup", mcp.Description("Не предлагать и не запускать env setup после создания (--no-env-setup)"), mcp.DefaultBool(false)),
		mcp.WithBoolean("yes", mcp.Description("Автоматически подтвердить действия CLI (--yes), включая установку недостающих инструментов и env setup"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Порт проекта (.Runtime.Port); 0 — не задавать")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a projectNewArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvProjectNew(a.Ref, a.Name, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.NoEnvSetup, a.Yes, a.Port), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"run",
		mcp.WithDescription("Исполнить команду манифеста шаблона в корне проекта (dir). ВНИМАНИЕ: долгоживущие команды (dev-серверы) прервутся по таймауту."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта (рабочий каталог)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("Имя команды манифеста")),
		mcp.WithArray("args", mcp.Description("Дополнительные аргументы, передаются команде после --"),
			mcp.Items(map[string]any{"type": "string"})),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a runArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		// Сборка/тесты на чистом Go cache легко выходят за 120 секунд:
		// manifest-команды получают тот же расширенный лимит, что new/update.
		return s.exec(ctx, cwd, argvRun(a.Command, a.Args), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"update",
		mcp.WithDescription("Обновить проект (dir) на новую версию шаблона по 3-way merge. Конфликты дают маркеры и ненулевой код возврата (isError)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithString("to", mcp.Description("Целевая версия шаблона; пусто — старший стабильный тег")),
		mcp.WithBoolean("dryRun", mcp.Description("Показать план без изменения файлов"), mcp.DefaultBool(false)),
		mcp.WithBoolean("check", mcp.Description("Проверить дерево на маркеры конфликта (код 1 при находке)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a updateArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvUpdate(a.To, a.DryRun, a.Check), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"stats",
		mcp.WithDescription("Отчёт дрейфа проекта (dir) от шаблона в машиночитаемом JSON (drift-score, статусы файлов, классы обновляемости)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.handleStats(ctx, cwd), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"doctor",
		mcp.WithDescription("Проверить окружение и инструменты активного шаблона. dir опционален (по умолчанию cwd сервера)."),
		mcp.WithString("dir", mcp.Description("Каталог проекта (опционально)")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a doctorArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvDoctor(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"ai_gen",
		mcp.WithDescription("Сгенерировать AI-артефакты (CLAUDE.md, .cursor/**, AGENTS.md, GEMINI.md) в корень проекта (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvAIGen(), defaultTimeout), nil
	}))
}

// handleStats исполняет `stats --json` и возвращает распарсенный (для
// валидации) и переформатированный JSON. Если stdout не парсится как JSON —
// отдаётся как есть.
func (s *Server) handleStats(ctx context.Context, cwd string) *mcp.CallToolResult {
	res, runErr := s.runCLI(ctx, cwd, argvStats(), defaultTimeout)
	if failed(res, runErr) {
		return mcp.NewToolResultError(formatFailure(res, runErr))
	}

	var parsed any
	if err := json.Unmarshal([]byte(res.Stdout), &parsed); err != nil {
		return mcp.NewToolResultText(res.Stdout)
	}
	pretty, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return mcp.NewToolResultText(res.Stdout)
	}
	return mcp.NewToolResultText(string(pretty))
}

// ── settings ───────────────────────────────────────────────────────────────

type settingsSetArgs struct {
	Dir    string            `json:"dir"`
	Values map[string]string `json:"values"`
}

func (s *Server) addSettingsTools() {
	s.mcp.AddTool(mcp.NewTool(
		"settings_list",
		mcp.WithDescription("Показать текущие значения настроек проекта (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvSettingsList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"settings_set",
		mcp.WithDescription("Изменить настройки проекта (dir) 3-way merge на текущей версии шаблона. Применяется без подтверждения (--yes)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithObject("values", mcp.Required(), mcp.Description("Новые значения: группа→значение")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a settingsSetArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvSettingsSet(a.Values), longTimeout), nil
	}))
}

// ── gen ──────────────────────────────────────────────────────────────────

type genArgs struct {
	Dir     string            `json:"dir"`
	Kind    string            `json:"kind"`
	Name    string            `json:"name"`
	Params  map[string]string `json:"params"`
	NoBuild bool              `json:"noBuild"`
}

type genBatchArgs struct {
	Dir        string              `json:"dir"`
	Operations []genBatchOperation `json:"operations"`
	NoBuild    bool                `json:"noBuild"`
}

func (s *Server) addGenTools() {
	s.mcp.AddTool(mcp.NewTool(
		"gen",
		mcp.WithDescription("Скаффолдер: создать файл(ы) вида kind с именем name по generators манифеста проекта (dir). После записи выполняется commands.build.run манифеста либо legacy Go fallback; ошибка откатывает изменения. noBuild=true пропускает build-gate и сохраняет изменения."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithString("kind", mcp.Required(), mcp.Description("Вид скаффолда (см. gen_list)")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя создаваемой сущности")),
		mcp.WithObject("params", mcp.Description("Параметры генератора: ключ→строковое значение (сериализуются в динамические CLI-флаги --<param>)")),
		mcp.WithBoolean("noBuild", mcp.Description("Пропустить build-gate после генерации (--no-build)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvGen(a.Kind, a.Name, a.Params, a.NoBuild), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_batch",
		mcp.WithDescription("Атомарно сгенерировать несколько scaffolds. Все операции планируются до записи, затем выполняется один build-gate из commands.build.run манифеста (legacy Go fallback: go build ./...); при ошибке изменения всего batch откатываются."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithArray(
			"operations",
			mcp.Required(),
			mcp.MinItems(1),
			mcp.Description("Операции {kind, name, params}; params — строковые значения параметров generator"),
			mcp.Items(map[string]any{
				"type":     "object",
				"required": []string{"kind", "name"},
				"properties": map[string]any{
					"kind": map[string]any{
						"type":        "string",
						"description": "Вид generator из template.manifest.yaml",
						"minLength":   1,
					},
					"name": map[string]any{
						"type":        "string",
						"description": "Имя создаваемой сущности/вертикали",
						"minLength":   1,
					},
					"params": map[string]any{
						"type":                 "object",
						"description":          "Параметры generator в строковом CLI-представлении",
						"additionalProperties": map[string]any{"type": "string"},
					},
				},
				"additionalProperties": false,
			}),
		),
		mcp.WithBoolean("noBuild", mcp.Description("Пропустить единственный финальный build-gate"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a genBatchArgs) (*mcp.CallToolResult, error) {
		if len(a.Operations) == 0 {
			return mcp.NewToolResultError("gen_batch: operations должен содержать хотя бы одну операцию"), nil
		}
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		argv := argvGenBatch(a.Operations, a.NoBuild)
		return s.exec(ctx, cwd, argv, longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"gen_list",
		mcp.WithDescription("Список доступных видов скаффолда манифеста шаблона проекта (dir)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a dirArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvGenList(), defaultTimeout), nil
	}))
}

// ── workspace ─────────────────────────────────────────────────────────────

type workspaceAddServiceArgs struct {
	Dir         string            `json:"dir"`
	Name        string            `json:"name"`
	Module      string            `json:"module"`
	Set         map[string]string `json:"set"`
	Defaults    bool              `json:"defaults"`
	NoHooks     bool              `json:"noHooks"`
	NoDepsCheck bool              `json:"noDepsCheck"`
	Port        int               `json:"port"`
}

func (s *Server) addWorkspaceTools() {
	s.mcp.AddTool(mcp.NewTool(
		"workspace_add_service",
		mcp.WithDescription("Добавить Temporal service-action в go-workspace проект и зарегистрировать его в go.work. Выполняется полностью неинтерактивно."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Корень workspace-проекта или вложенный каталог внутри него")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя нового сервиса-action")),
		mcp.WithString("module", mcp.Description("Go module сервиса; по умолчанию <module workspace>/services/<slug>")),
		mcp.WithObject("set", mcp.Description("Настройки шаблона сервиса: группа→значение; workflow=true форсируется CLI")),
		mcp.WithBoolean("defaults", mcp.Description("Взять значения по умолчанию для незаданных групп"), mcp.DefaultBool(true)),
		mcp.WithBoolean("noHooks", mcp.Description("Не запускать hooks.postCreate"), mcp.DefaultBool(false)),
		mcp.WithBoolean("noDepsCheck", mcp.Description("Не проверять инструменты окружения"), mcp.DefaultBool(false)),
		mcp.WithNumber("port", mcp.Description("Порт сервиса; 0 — использовать значение шаблона")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a workspaceAddServiceArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvWorkspaceAddService(a.Name, a.Module, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.Port), longTimeout), nil
	}))
}

// ── авторские tools шаблонов (lint / init-template) ─────────────────────────

type lintTemplateArgs struct {
	Path  string `json:"path"`
	Combo string `json:"combo"`
}

type initTemplateArgs struct {
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Multi bool   `json:"multi"`
}

func (s *Server) addTemplateAuthorTools() {
	s.mcp.AddTool(mcp.NewTool(
		"lint_template",
		mcp.WithDescription("Селфтест репозитория шаблона по угловым комбинациям настроек. Провал даёт ненулевой код возврата (isError)."),
		mcp.WithString("path", mcp.Required(), mcp.Description("Корень репозитория шаблона")),
		mcp.WithString("combo", mcp.Description("Фильтр по имени комбинации (точное совпадение)")),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a lintTemplateArgs) (*mcp.CallToolResult, error) {
		path, err := resolveWorkDir(a.Path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, "", argvLintTemplate(path, a.Combo), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"init_template",
		mcp.WithDescription("Создать репозиторий шаблона со всем инструментарием (манифест, files/, генераторы, ai-config, CI)."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Имя нового шаблона")),
		mcp.WithString("dir", mcp.Description("Целевой каталог репозитория (создаётся; по умолчанию ./<name>)")),
		mcp.WithBoolean("multi", mcp.Description("Multi-репозиторий (repo.manifest.yaml + шаблон в подкаталоге)"), mcp.DefaultBool(false)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a initTemplateArgs) (*mcp.CallToolResult, error) {
		dir, err := resolveTargetDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, "", argvInitTemplate(a.Name, dir, a.Multi), longTimeout), nil
	}))
}

// ── прочее (projects / env) ─────────────────────────────────────────────────

type envSetupArgs struct {
	Dir  string `json:"dir"`
	Name string `json:"name"`
	Yes  bool   `json:"yes"`
}

func (s *Server) addMiscTools() {
	s.mcp.AddTool(mcp.NewTool(
		"projects_list",
		mcp.WithDescription("Список проектов локального реестра (путь, шаблон, время, статус)."),
		mcp.WithReadOnlyHintAnnotation(true),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, error) {
		return s.exec(ctx, "", argvProjectsList(), defaultTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"env_setup",
		mcp.WithDescription("Запустить ansible-плейбук окружения проекта (dir). Установка ansible подтверждается автоматически (yes всегда true)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithString("name", mcp.Description("Имя плейбука (по умолчанию setup)")),
		mcp.WithBoolean("yes", mcp.Required(), mcp.Description("Форсирующее подтверждение — всегда true"), mcp.DefaultBool(true)),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a envSetupArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvEnvSetup(a.Name), longTimeout), nil
	}))
}

// exec — общий путь исполнения tool'а: запускает подпроцесс и транслирует
// результат в MCP-результат (провал → isError с полной диагностикой).
func (s *Server) exec(ctx context.Context, cwd string, argv []string, timeout time.Duration) *mcp.CallToolResult {
	res, runErr := s.runCLI(ctx, cwd, argv, timeout)
	return toolResult(res, runErr)
}
