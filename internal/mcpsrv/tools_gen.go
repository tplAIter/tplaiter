package mcpsrv

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

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
