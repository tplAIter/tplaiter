package engine

import (
	"fmt"
	"strconv"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Context contains data available inside templates (`{{ . }}`) and when
// resolving the contextKey of postReplace rules. Unlike go-template's Context,
// it uses .Settings (a shared [settings.View] with Is/Has helpers) instead of
// .Features (map[string]bool from the binary feature registry); project data is
// supplied by the caller (the command holding [settings.Resolved] and project
// coordinates), rather than an internal marker.
//
// Template access: `{{ .Project.Slug }}`, `{{ .Settings.database }}`,
// `{{ .Runtime.Port }}`, `{{ .Template.Version }}`.
type Context struct {
	Template manifest.ProjectTemplate `json:"template"`
	Project  ProjectView              `json:"project"`
	Settings settings.View            `json:"settings"`
	Runtime  manifest.ProjectRuntime  `json:"runtime"`
}

// ProjectView is `.Project` in the render context: project identity fields
// (ported from [manifest.ProjectInfo]) plus derived slug case variants (the
// go-template top-level SlugPascal/SlugCamel/SlugKebab/SlugSnake port, nested
// under Project here because .Project already carries Slug).
type ProjectView struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Module string `json:"module"`
	System string `json:"system,omitempty"`
	Domain string `json:"domain,omitempty"`

	// Derived slug case variants.
	Pascal string `json:"pascal"`
	Camel  string `json:"camel"`
	Kebab  string `json:"kebab"`
	Snake  string `json:"snake"`
}

// NewContext builds the render context from [Options]: project coordinates,
// resolved settings (ActiveValues is a derived set with inactive nested groups
// zeroed out; see [settings.Resolved]), and the coordinates of the template in use.
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

// lookup resolves a context string value by dotted key (for
// postReplace.contextKey, such as "Project.Slug"; see the  example).
// It supports Project/Template fields and Runtime.Port (formatted with
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

// compilePostReplace resolves each postReplace rule's contextKey (from the
// manifest engine.postReplace) to a concrete context value. An unknown key is
// a manifest authoring error, not a runtime warning.
func compilePostReplace(rules []manifest.PostReplace, ctx *Context) ([]compiledPostReplace, error) {
	out := make([]compiledPostReplace, 0, len(rules))
	for _, rule := range rules {
		value, ok := ctx.lookup(rule.ContextKey)
		if !ok {
			return nil, fmt.Errorf("engine: postReplace: unknown contextKey %q", rule.ContextKey)
		}
		out = append(out, compiledPostReplace{
			matcher:     newGlobSet([]string{rule.Glob}),
			placeholder: rule.Placeholder,
			value:       value,
		})
	}
	return out, nil
}
