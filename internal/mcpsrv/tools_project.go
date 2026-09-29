package mcpsrv

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mark3labs/mcp-go/mcp"
)

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
	DryRun      bool              `json:"dryRun"`
	SourceInput string            `json:"sourceInput"`
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
	Dir         string `json:"dir"`
	To          string `json:"to"`
	DryRun      bool   `json:"dryRun"`
	Check       bool   `json:"check"`
	SourceInput string `json:"sourceInput"`
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
		mcp.WithBoolean("dryRun", mcp.Description("Prepare a plan without changing files"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a projectNewArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvProjectNew(a.Ref, a.Name, a.Set, a.Defaults, a.NoHooks, a.NoDepsCheck, a.NoEnvSetup, a.Yes, a.Port, strconv.FormatBool(a.DryRun), a.SourceInput), longTimeout), nil
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
		// Building/testing with a clean Go cache easily exceeds 120 seconds, so
		// manifest commands receive the same longer timeout as new/update.
		return s.exec(ctx, cwd, argvRun(a.Command, a.Args), longTimeout), nil
	}))

	s.mcp.AddTool(mcp.NewTool(
		"update",
		mcp.WithDescription("Обновить проект (dir) на новую версию шаблона по 3-way merge. Конфликты дают маркеры и ненулевой код возврата (isError)."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Каталог проекта")),
		mcp.WithString("to", mcp.Description("Целевая версия шаблона; пусто — старший стабильный тег")),
		mcp.WithBoolean("dryRun", mcp.Description("Показать план без изменения файлов"), mcp.DefaultBool(false)),
		mcp.WithBoolean("check", mcp.Description("Проверить дерево на маркеры конфликта (код 1 при находке)"), mcp.DefaultBool(false)),
		mcp.WithString("sourceInput", mcp.Description("Path to the closed JSON source selection")),
	), mcp.NewTypedToolHandler(func(ctx context.Context, _ mcp.CallToolRequest, a updateArgs) (*mcp.CallToolResult, error) {
		cwd, err := resolveWorkDir(a.Dir)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return s.exec(ctx, cwd, argvUpdate(a.To, a.DryRun, a.Check, a.SourceInput), longTimeout), nil
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

// handleStats executes `stats --json` and returns parsed (for validation) and
// reformatted JSON. If stdout cannot be parsed as JSON, it is returned as is.
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
