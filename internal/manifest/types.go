// Package manifest defines the contract between a template and the tplater CLI:
// manifest structures (Template/Repository/Project), their parser (yaml.v3 with
// KnownFields and an apiVersion gate), a template validator, a small condition
// language, and an offline manifest snapshot.
//
// The package does NOT evaluate conditions or resolve settings; that is the
// resolver's responsibility. It only contains [Condition]/[Atom] structure,
// syntax parsing, and reference validation against the group tree.
package manifest

// APIGroup is the contract group in the apiVersion field (`tplater.dev/v1alpha1`).
const APIGroup = "tplater.dev"

// SupportedMajor is the only supported major contract version. The parser rejects
// a manifest with another major version and asks the user to update tplater.
const SupportedMajor = 1

// APIVersion is the canonical apiVersion field value written by v1 templates.
const APIVersion = APIGroup + "/v1alpha1"

// Kind constants for permitted manifest kinds.
const (
	KindTemplate   = "Template"
	KindRepository = "Repository"
	KindProject    = "Project"
)

// Setting group types (SettingGroup.Type).
const (
	TypeSelect      = "select"
	TypeMultiselect = "multiselect"
	TypeToggle      = "toggle"
	TypeString      = "string"
	TypeInt         = "int"
)

// StatusPlanned makes an option visible in the catalog but unavailable for selection.
const StatusPlanned = "planned"

// Template is a manifest for one template (`template.manifest.yaml`).
type Template struct {
	APIVersion  string             `yaml:"apiVersion"`
	Kind        string             `yaml:"kind"`
	Metadata    TemplateMeta       `yaml:"metadata"`
	Engine      Engine             `yaml:"engine"`
	Requires    Requires           `yaml:"requires"`
	Settings    []SettingGroup     `yaml:"settings"`
	Files       []FileRule         `yaml:"files"`
	Constraints []Constraint       `yaml:"constraints"`
	Commands    map[string]Command `yaml:"commands"`
	Generators  []Generator        `yaml:"generators"`
	AIConfig    AIConfig           `yaml:"aiConfig"`
	Environment Environment        `yaml:"environment"`
	Hooks       Hooks              `yaml:"hooks"`
	Lint        LintConfig         `yaml:"lint"` // opt-in architecture-lint rules; see lint_types.go
}

// TemplateMeta is the template metadata section.
type TemplateMeta struct {
	Name        string              `yaml:"name"`
	DisplayName string              `yaml:"displayName"`
	Version     string              `yaml:"version"`
	Description string              `yaml:"description"`
	Maintainers []Maintainer        `yaml:"maintainers"`
	Labels      map[string][]string `yaml:"labels"`
	Docs        string              `yaml:"docs"`
	Notes       string              `yaml:"notes"`
}

// Maintainer maintains a template or repository.
type Maintainer struct {
	Name     string `yaml:"name"`
	Email    string `yaml:"email"`
	Telegram string `yaml:"telegram"`
}

// Engine contains rendering engine settings.
type Engine struct {
	Type              string        `yaml:"type"`
	Root              string        `yaml:"root"`
	CopyWithoutRender []string      `yaml:"copyWithoutRender"`
	PostReplace       []PostReplace `yaml:"postReplace"`
}

// PostReplace replaces a placeholder after rendering in files that are not copied through rendering.
type PostReplace struct {
	Glob        string `yaml:"glob"`
	Placeholder string `yaml:"placeholder"`
	ContextKey  string `yaml:"contextKey"`
}

// Requires describes template requirements for the CLI and environment.
type Requires struct {
	Tplaiter string `yaml:"tplaiter"`
	// Tplater is read-only compatibility for legacy manifests.
	Tplater string `yaml:"tplater"`
	Tools   []Tool `yaml:"tools"`
}

// Tool is a binary environment dependency.
type Tool struct {
	Name     string      `yaml:"name"`
	Version  string      `yaml:"version"`
	Required bool        `yaml:"required"`
	Install  ToolInstall `yaml:"install"`
}

// ToolInstall contains tool installation recipes.
type ToolInstall struct {
	Brew string `yaml:"brew"`
	Apt  string `yaml:"apt"`
	URL  string `yaml:"url"`
}

// SettingGroup is a node in the settings tree. Its value enters the rendering
// context as .Settings.<group>. Nested groups (Option.Settings) are flat by id;
// the validator enforces global uniqueness.
type SettingGroup struct {
	Group       string `yaml:"group"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	// Default is the default value; its concrete type depends on Type (string for
	// select/string, []any for multiselect, bool for toggle, int for int). The
	// validator checks consistency.
	Default any      `yaml:"default"`
	Pattern string   `yaml:"pattern"`
	Options []Option `yaml:"options"`
}

// Option is a choice within a select or multiselect group.
type Option struct {
	ID          string            `yaml:"id"`
	Title       string            `yaml:"title"`
	Description string            `yaml:"description"`
	Status      string            `yaml:"status"`
	Requires    []string          `yaml:"requires"`
	Settings    []SettingGroup    `yaml:"settings"`
	Vars        map[string]string `yaml:"vars"`
}

// FileRule maps settings to the file tree. Exactly one of When/AnyOf defines a
// condition; Paths adds paths and Remove removes them.
type FileRule struct {
	When   string   `yaml:"when"`
	AnyOf  []string `yaml:"anyOf"`
	Paths  []string `yaml:"paths"`
	Remove []string `yaml:"remove"`
}

// Constraint is an invariant across groups.
type Constraint struct {
	If      string `yaml:"if"`
	Require string `yaml:"require"`
	Message string `yaml:"message"`
}

// Command is a named project command for `tplater run`.
type Command struct {
	Run         string `yaml:"run"`
	Description string `yaml:"description"`
	When        string `yaml:"when"`
}

// Generator parameter types (Param.Type). A parameter value comes from the CLI
// (`tplater gen <kind> <Name> --<param> <value>`) and enters snippet rendering
// context as `.Params.<name>` (and as parsed `.Fields` for the fields type).
const (
	ParamTypeString = "string"
	ParamTypeBool   = "bool"
	ParamTypeInt    = "int"
	// ParamTypeFields is a special type: a "name:type,..." string is parsed into
	// []Field (see internal/gen). A generator normally has exactly one such parameter.
	ParamTypeFields = "fields"
	// ParamTypeList is a special type: an "a,b,c" string is parsed into []string.
	// The value is available to snippets as `.Params.<name>` ([]string), useful for
	// ranging over elements (for example, --activities "payments.Debit,notify.Send").
	ParamTypeList = "list"
)

// NumberedGoose is the Target.Numbered strategy: before rendering a target, the
// next goose migration number (`.MigrationSeq`, NNNNN) is derived from its directory.
const NumberedGoose = "goose"

// Generator is a scaffold kind for `tplater gen`.
//
// File form is mutually exclusive: either the single-file form (Snippet+Target,
// kept for backward compatibility) or the multi-file form (Targets[]). The
// validator requires exactly one form. Params declares CLI parameters (--fields
// and arbitrary --<name>) available to snippets as `.Params`/`.Fields`.
type Generator struct {
	Kind        string   `yaml:"kind"`
	Description string   `yaml:"description"`
	Snippet     string   `yaml:"snippet,omitempty"`
	Target      string   `yaml:"target,omitempty"`
	Params      []Param  `yaml:"params,omitempty"`
	Targets     []Target `yaml:"targets,omitempty"`
	Anchors     []Anchor `yaml:"anchors,omitempty"`
	When        []string `yaml:"when"`
}

// Param declares one generator parameter. Name is the CLI flag name (kebab case
// is allowed, for example with-list). Type comes from the allowlist
// ([ParamTypeString] etc.). Required without Default is mandatory (the CLI
// reports Description when absent). Default is used when the flag is omitted.
type Param struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Required bool   `yaml:"required,omitempty"`
	Default  any    `yaml:"default,omitempty"`
	// Pattern is an optional RE2-compatible regexp for the raw parameter value.
	// It is supported for string and int and is applied before generator rendering
	// through the shared ResolveParams path (CLI, batch, and MCP).
	Pattern     string `yaml:"pattern,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Target is one file in a multi-file generator. Snippet renders to the Target
// path. When gates it on project SETTINGS (an OR list like Generator.When): the
// target is skipped if unsatisfied (for example, activity only with
// workflow=temporal). Numbered is the numbering strategy ("" | [NumberedGoose]).
type Target struct {
	Snippet  string   `yaml:"snippet"`
	Target   string   `yaml:"target"`
	When     []string `yaml:"when,omitempty"`
	Numbered string   `yaml:"numbered,omitempty"`
}

// Anchor is the insertion point for generated code in an existing file.
type Anchor struct {
	File   string `yaml:"file"`
	Anchor string `yaml:"anchor"`
	Insert string `yaml:"insert"`
}

// AIConfig locates the ai-config directory within a template.
type AIConfig struct {
	Path string `yaml:"path"`
}

// Environment contains environment setup playbooks.
type Environment struct {
	Playbooks []Playbook `yaml:"playbooks"`
}

// Playbook is one Ansible environment playbook.
type Playbook struct {
	Name        string `yaml:"name"`
	File        string `yaml:"file"`
	Description string `yaml:"description"`
	When        string `yaml:"when"`
}

// Hooks contains project lifecycle hooks.
type Hooks struct {
	PostCreate []Hook `yaml:"postCreate"`
	PostUpdate []Hook `yaml:"postUpdate"`
}

// Hook is one hook step: exactly one of Run/Ansible. Optional=true downgrades a
// missing binary to a warning.
type Hook struct {
	Run      string `yaml:"run"`
	Ansible  string `yaml:"ansible"`
	Optional bool   `yaml:"optional"`
}

// Repository is a multi-template repository manifest.
type Repository struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   RepositoryMeta `yaml:"metadata"`
	Templates  []TemplateRef  `yaml:"templates"`
}

// RepositoryMeta is the repository metadata section.
type RepositoryMeta struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Maintainers []Maintainer `yaml:"maintainers"`
}

// TemplateRef references a directory containing template.manifest.yaml.
type TemplateRef struct {
	Path string `yaml:"path"`
}

// Project is the `.tplaiter/project.yaml` project marker.
type Project struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	ID         string          `yaml:"id"`
	Template   ProjectTemplate `yaml:"template"`
	Project    ProjectInfo     `yaml:"project"`
	Settings   map[string]any  `yaml:"settings"`
	Runtime    ProjectRuntime  `yaml:"runtime"`
	Baseline   string          `yaml:"baseline"`
}

// ProjectTemplate identifies the project's source template.
type ProjectTemplate struct {
	Repo    string `yaml:"repo"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// ProjectInfo identifies the project itself.
type ProjectInfo struct {
	Name   string `yaml:"name"`
	Slug   string `yaml:"slug"`
	Module string `yaml:"module"`
	System string `yaml:"system"`
	Domain string `yaml:"domain"`
}

// ProjectRuntime contains project runtime parameters.
type ProjectRuntime struct {
	Port int `yaml:"port"`
}
