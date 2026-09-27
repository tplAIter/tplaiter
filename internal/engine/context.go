package engine

import (
	"fmt"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Context — данные, доступные внутри шаблонов (`{{ . }}`) и при резолве
// contextKey правил postReplace. Замена go-template'овского Context: вместо
// .Features (map[string]bool из бинарного реестра фич) — .Settings (общий
// [settings.View] с хелперами Is/Has); проектные данные приходят
// не из внутреннего маркера, а от вызывающего (команда, держащая
// [settings.Resolved] и координаты проекта).
//
// Доступ в шаблонах: `{{ .Project.Slug }}`, `{{ .Settings.database }}`,
// `{{ .Runtime.Port }}`, `{{ .Template.Version }}`.
type Context struct {
	Template manifest.ProjectTemplate `json:"template"`
	Project  ProjectView              `json:"project"`
	Settings settings.View            `json:"settings"`
	Runtime  manifest.ProjectRuntime  `json:"runtime"`
}

// ProjectView — `.Project` в контексте рендера: поля идентификации проекта
// (перенос [manifest.ProjectInfo]) плюс производные case-варианты slug'а
// (перенос go-template'овских top-level SlugPascal/SlugCamel/SlugKebab/SlugSnake,
// здесь — вложенные под Project, т.к. .Project уже несёт Slug).
type ProjectView struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Module string `json:"module"`
	System string `json:"system,omitempty"`
	Domain string `json:"domain,omitempty"`

	// Производные case-варианты Slug.
	Pascal string `json:"pascal"`
	Camel  string `json:"camel"`
	Kebab  string `json:"kebab"`
	Snake  string `json:"snake"`
}

// NewContext строит контекст рендера из [Options]: проектных координат,
// разрешённых настроек (ActiveValues — производный набор с обнулёнными
// неактивными вложенными группами, см. [settings.Resolved]) и координат
// используемого шаблона.
func NewContext(opts Options) *Context {
	p := opts.Project
	return &Context{
		Template: manifest.ProjectTemplate{
			Repo:    opts.Repo,
			Name:    opts.Template.Metadata.Name,
			Version: opts.Template.Metadata.Version,
		},
		Project: ProjectView{
			Name:   p.Name,
			Slug:   p.Slug,
			Module: p.Module,
			System: p.System,
			Domain: p.Domain,
			Pascal: Pascal(p.Slug),
			Camel:  Camel(p.Slug),
			Kebab:  Kebab(p.Slug),
			Snake:  Snake(p.Slug),
		},
		Settings: settings.View(opts.Resolved.ActiveValues),
		Runtime:  opts.Runtime,
	}
}

// lookup резолвит строковое значение контекста по дотированному ключу (для
// postReplace.contextKey, например "Project.Slug" — см. пример ).
// Поддерживает поля Project/Template и Runtime.Port (число форматируется
// strconv.Itoa).
func (c *Context) lookup(key string) (string, bool) {
	switch key {
	case "Project.Name":
		return c.Project.Name, true
	case "Project.Slug":
		return c.Project.Slug, true
	case "Project.Module":
		return c.Project.Module, true
	case "Project.System":
		return c.Project.System, true
	case "Project.Domain":
		return c.Project.Domain, true
	case "Project.Pascal":
		return c.Project.Pascal, true
	case "Project.Camel":
		return c.Project.Camel, true
	case "Project.Kebab":
		return c.Project.Kebab, true
	case "Project.Snake":
		return c.Project.Snake, true
	case "Template.Name":
		return c.Template.Name, true
	case "Template.Version":
		return c.Template.Version, true
	case "Template.Repo":
		return c.Template.Repo, true
	case "Runtime.Port":
		return strconv.Itoa(c.Runtime.Port), true
	default:
		return "", false
	}
}

// compilePostReplace резолвит contextKey каждого правила postReplace
// (engine.postReplace манифеста) в конкретное значение контекста. Ошибка на
// неизвестном ключе — это ошибка автора манифеста, а не рантайм-предупреждение.
func compilePostReplace(rules []manifest.PostReplace, ctx *Context) ([]compiledPostReplace, error) {
	out := make([]compiledPostReplace, 0, len(rules))
	for _, rule := range rules {
		value, ok := ctx.lookup(rule.ContextKey)
		if !ok {
			return nil, fmt.Errorf("engine: postReplace: неизвестный contextKey %q", rule.ContextKey)
		}
		out = append(out, compiledPostReplace{
			matcher:     newGlobSet([]string{rule.Glob}),
			placeholder: rule.Placeholder,
			value:       value,
		})
	}
	return out, nil
}
