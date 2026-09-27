package manifest

// LintRuleID-константы известных arch-lint правил (docs/research/clean-codegen.md
// §1 заимствование 4, §4 ). Список закрыт намеренно: opt-in секция lint не
// является общим движком статического анализа — это узкий набор инвариантов,
// которые движок [lintengine аналог] умеет проверять по AST рендера.
const (
	// LintRuleCtxFirst — экспортируемая функция/метод с параметрами обязана
	// принимать context.Context первым параметром (конструкторы New*
	// исключены).
	LintRuleCtxFirst = "ctx-first"
	// LintRuleNoInit — запрет func init() в paths.
	LintRuleNoInit = "no-init"
	// LintRuleGeneratedMarker — файлы по глобам обязаны нести маркер
	// «Code generated»/«DO NOT EDIT» в первых строках.
	LintRuleGeneratedMarker = "generated-marker"
	// LintRuleNoPanic — запрет panic() вне func main/func init.
	LintRuleNoPanic = "no-panic"
)

// knownLintRuleIDs — множество допустимых значений LintRule.ID.
var knownLintRuleIDs = map[string]bool{
	LintRuleCtxFirst:        true,
	LintRuleNoInit:          true,
	LintRuleGeneratedMarker: true,
	LintRuleNoPanic:         true,
}

// LintConfig — opt-in секция `lint` манифеста шаблона ( реализация проверку):
// шаблон сам декларирует свои архитектурные инварианты, которые
// `tplater lint-template` проверяет по AST пробного рендера. Пустая секция
// (Rules == nil) не меняет поведение lint-template — правил нет, проверок нет.
type LintConfig struct {
	Rules []LintRule `yaml:"rules"`
}

// LintRule — одно arch-lint правило: известный ID + глобы, к каким файлам
// рендера правило применяется (Paths — включение, Exclude — исключение из
// включённого множества). Язык глобов — тот же, что у files[].paths (
// §4): `*` в пределах сегмента, `**` как отдельный сегмент, `?` — один символ.
type LintRule struct {
	ID      string   `yaml:"id"`
	Paths   []string `yaml:"paths"`
	Exclude []string `yaml:"exclude"`
}
