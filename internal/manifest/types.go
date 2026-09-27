// Package manifest описывает контракт между шаблоном и CLI tplater: структуры
// манифестов (Template/Repository/Project), их парсер (yaml.v3 с KnownFields и
// apiVersion-гейтом), валидатор шаблона, мини-язык условий
// и офлайн-снимок манифеста.
//
// Пакет НЕ вычисляет условия и НЕ резолвит настройки — это ответственность
// резолвера . Здесь только структура [Condition]/[Atom] и её
// синтаксический разбор + ссылочная валидация относительно дерева групп.
package manifest

// APIGroup — группа контракта в поле apiVersion (`tplater.dev/v1alpha1`).
const APIGroup = "tplater.dev"

// SupportedMajor — единственная поддерживаемая major-версия контракта. Манифест
// с иным major отклоняется парсером с требованием обновить tplater.
const SupportedMajor = 1

// APIVersion — каноническое значение поля apiVersion, которое пишут шаблоны v1.
const APIVersion = APIGroup + "/v1alpha1"

// Kind-константы допустимых видов манифеста.
const (
	KindTemplate   = "Template"
	KindRepository = "Repository"
	KindProject    = "Project"
)

// Типы групп настроек (SettingGroup.Type).
const (
	TypeSelect      = "select"
	TypeMultiselect = "multiselect"
	TypeToggle      = "toggle"
	TypeString      = "string"
	TypeInt         = "int"
)

// StatusPlanned — опция видна в каталоге, но невыбираема (честность каталога).
const StatusPlanned = "planned"

// Template — манифест одного шаблона (`template.manifest.yaml`).
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
	Lint        LintConfig         `yaml:"lint"` // opt-in arch-lint правила, см. lint_types.go
}

// TemplateMeta — секция metadata шаблона.
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

// Maintainer — сопровождающий шаблона/репозитория.
type Maintainer struct {
	Name     string `yaml:"name"`
	Email    string `yaml:"email"`
	Telegram string `yaml:"telegram"`
}

// Engine — настройки движка рендера.
type Engine struct {
	Type              string        `yaml:"type"`
	Root              string        `yaml:"root"`
	CopyWithoutRender []string      `yaml:"copyWithoutRender"`
	PostReplace       []PostReplace `yaml:"postReplace"`
}

// PostReplace — пост-замена плейсхолдера в некопируемых через рендер файлах.
type PostReplace struct {
	Glob        string `yaml:"glob"`
	Placeholder string `yaml:"placeholder"`
	ContextKey  string `yaml:"contextKey"`
}

// Requires — требования шаблона к CLI и окружению.
type Requires struct {
	Tplaiter string `yaml:"tplaiter"`
	// Tplater is read-only compatibility for legacy manifests.
	Tplater string `yaml:"tplater"`
	Tools   []Tool `yaml:"tools"`
}

// Tool — бинарная зависимость окружения.
type Tool struct {
	Name     string      `yaml:"name"`
	Version  string      `yaml:"version"`
	Required bool        `yaml:"required"`
	Install  ToolInstall `yaml:"install"`
}

// ToolInstall — рецепты установки инструмента.
type ToolInstall struct {
	Brew string `yaml:"brew"`
	Apt  string `yaml:"apt"`
	URL  string `yaml:"url"`
}

// SettingGroup — узел дерева настроек. Значение попадает в контекст
// рендера как .Settings.<group>. Вложенные группы (Option.Settings) плоские по
// id — валидатор следит за глобальной уникальностью.
type SettingGroup struct {
	Group       string `yaml:"group"`
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	// Default — значение по умолчанию; его конкретный тип зависит от Type
	// (string для select/string, []any для multiselect, bool для toggle,
	// int для int). Валидатор сверяет согласованность.
	Default any      `yaml:"default"`
	Pattern string   `yaml:"pattern"`
	Options []Option `yaml:"options"`
}

// Option — вариант выбора внутри select/multiselect-группы.
type Option struct {
	ID          string            `yaml:"id"`
	Title       string            `yaml:"title"`
	Description string            `yaml:"description"`
	Status      string            `yaml:"status"`
	Requires    []string          `yaml:"requires"`
	Settings    []SettingGroup    `yaml:"settings"`
	Vars        map[string]string `yaml:"vars"`
}

// FileRule — правило маппинга настроек на дерево файлов. Ровно один
// из When/AnyOf задаёт условие; Paths добавляет, Remove удаляет пути.
type FileRule struct {
	When   string   `yaml:"when"`
	AnyOf  []string `yaml:"anyOf"`
	Paths  []string `yaml:"paths"`
	Remove []string `yaml:"remove"`
}

// Constraint — межгрупповой инвариант.
type Constraint struct {
	If      string `yaml:"if"`
	Require string `yaml:"require"`
	Message string `yaml:"message"`
}

// Command — именованная команда проекта для `tplater run`.
type Command struct {
	Run         string `yaml:"run"`
	Description string `yaml:"description"`
	When        string `yaml:"when"`
}

// Типы параметров генератора (Param.Type). Значение параметра приходит
// из CLI (`tplater gen <kind> <Name> --<param> <value>`) и попадает в контекст
// рендера сниппетов как `.Params.<name>` (для типа fields — дополнительно как
// разобранный `.Fields`).
const (
	ParamTypeString = "string"
	ParamTypeBool   = "bool"
	ParamTypeInt    = "int"
	// ParamTypeFields — спец-тип: строка "name:type,..." парсится в []Field
	// (см. internal/gen). Обычно ровно один такой параметр на генератор.
	ParamTypeFields = "fields"
	// ParamTypeList — спец-тип: строка "a,b,c" парсится в []string .
	// Значение доступно сниппетам как `.Params.<name>` ([]string) — удобно для
	// range по элементам (напр. --activities "payments.Debit,notify.Send").
	ParamTypeList = "list"
)

// NumberedGoose — стратегия нумерации Target.Numbered: перед рендером таргета
// вычисляется следующий goose-номер миграции (`.MigrationSeq`, NNNNN) по
// каталогу целевого файла.
const NumberedGoose = "goose"

// Generator — вид скаффолда для `tplater gen`.
//
// Форма файлов задаётся ВЗАИМОИСКЛЮЧАЮЩЕ: либо одиночная (Snippet+Target —
// обратно совместимая форма ), либо мультифайловая (Targets[] — проверку).
// Валидатор требует ровно одну из форм. Params декларирует параметры CLI
// (--fields и произвольные --<name>), доступные сниппетам как `.Params`/`.Fields`.
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

// Param — декларация одного параметра генератора . Name — имя флага CLI
// (kebab допустим, напр. with-list). Type — из allowlist ([ParamTypeString] и
// др.). Required без Default — обязателен (ошибка CLI с Description при
// отсутствии). Default используется, когда флаг не задан.
type Param struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Required bool   `yaml:"required,omitempty"`
	Default  any    `yaml:"default,omitempty"`
	// Pattern — необязательный RE2-совместимый regexp для сырого значения
	// параметра. Поддерживается для string и int; применяется до рендера
	// генератора единым путём ResolveParams (CLI, batch и MCP).
	Pattern     string `yaml:"pattern,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Target — один файл мультифайлового генератора . Snippet рендерится в
// Target-путь. When — гейт по НАСТРОЙКАМ проекта (OR-список, как Generator.When):
// таргет пропускается, если не выполнен (напр. activity только при
// workflow=temporal). Numbered — стратегия нумерации ("" | [NumberedGoose]).
type Target struct {
	Snippet  string   `yaml:"snippet"`
	Target   string   `yaml:"target"`
	When     []string `yaml:"when,omitempty"`
	Numbered string   `yaml:"numbered,omitempty"`
}

// Anchor — точка вставки сгенерированного кода в существующий файл.
type Anchor struct {
	File   string `yaml:"file"`
	Anchor string `yaml:"anchor"`
	Insert string `yaml:"insert"`
}

// AIConfig — расположение каталога ai-config внутри шаблона.
type AIConfig struct {
	Path string `yaml:"path"`
}

// Environment — плейбуки настройки окружения.
type Environment struct {
	Playbooks []Playbook `yaml:"playbooks"`
}

// Playbook — один ansible-плейбук окружения.
type Playbook struct {
	Name        string `yaml:"name"`
	File        string `yaml:"file"`
	Description string `yaml:"description"`
	When        string `yaml:"when"`
}

// Hooks — хуки жизненного цикла проекта.
type Hooks struct {
	PostCreate []Hook `yaml:"postCreate"`
	PostUpdate []Hook `yaml:"postUpdate"`
}

// Hook — один шаг хука: ровно один из Run/Ansible. Optional=true понижает
// отсутствие бинарника до предупреждения.
type Hook struct {
	Run      string `yaml:"run"`
	Ansible  string `yaml:"ansible"`
	Optional bool   `yaml:"optional"`
}

// Repository — манифест мульти-шаблонного репозитория.
type Repository struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   RepositoryMeta `yaml:"metadata"`
	Templates  []TemplateRef  `yaml:"templates"`
}

// RepositoryMeta — секция metadata репозитория.
type RepositoryMeta struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Maintainers []Maintainer `yaml:"maintainers"`
}

// TemplateRef — ссылка на каталог с template.manifest.yaml.
type TemplateRef struct {
	Path string `yaml:"path"`
}

// Project — проектный маркер `.tplaiter/project.yaml`.
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

// ProjectTemplate — координаты шаблона-источника проекта.
type ProjectTemplate struct {
	Repo    string `yaml:"repo"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// ProjectInfo — идентификация самого проекта.
type ProjectInfo struct {
	Name   string `yaml:"name"`
	Slug   string `yaml:"slug"`
	Module string `yaml:"module"`
	System string `yaml:"system"`
	Domain string `yaml:"domain"`
}

// ProjectRuntime — рантайм-параметры проекта.
type ProjectRuntime struct {
	Port int `yaml:"port"`
}
