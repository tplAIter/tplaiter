package manifest

// LintRuleID constants for known arch-lint rules (docs/research/clean-codegen.md
// §1 borrowing 4, §4 ). The list is intentionally closed: the opt-in lint
// section is not a general static-analysis engine, but a narrow set of
// invariants that the [lintengine analogue] can check in the render AST.
const (
	// LintRuleCtxFirst — an exported function/method with parameters must take
	// context.Context as its first parameter (New* constructors are excluded).
	LintRuleCtxFirst = "ctx-first"
	// LintRuleNoInit — prohibit func init() in paths.
	LintRuleNoInit = "no-init"
	// LintRuleGeneratedMarker — files matched by the globs must carry a
	// “Code generated”/“DO NOT EDIT” marker in their first lines.
	LintRuleGeneratedMarker = "generated-marker"
	// LintRuleNoPanic — prohibit panic() outside func main/func init.
	LintRuleNoPanic = "no-panic"
)

// knownLintRuleIDs is the set of allowed LintRule.ID values.
var knownLintRuleIDs = map[string]bool{
	LintRuleCtxFirst:        true,
	LintRuleNoInit:          true,
	LintRuleGeneratedMarker: true,
	LintRuleNoPanic:         true,
}

// LintConfig is the template manifest's opt-in `lint` section (the  check):
// the template declares its architectural invariants, which `tplater
// lint-template` checks against a trial render AST. An empty section
// (Rules == nil) does not change lint-template behavior: no rules, no checks.
type LintConfig struct {
	Rules []LintRule `yaml:"rules"`
}

// LintRule is one arch-lint rule: a known ID and globs selecting the rendered
// files to which it applies (Paths includes, Exclude removes from the included
// set). The glob language is the same as files[].paths (§4): `*` within a
// segment, `**` as a separate segment, and `?` for one character.
type LintRule struct {
	ID      string   `yaml:"id"`
	Paths   []string `yaml:"paths"`
	Exclude []string `yaml:"exclude"`
}
