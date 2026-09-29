package aiconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// knownTargets — target tools that the generator can render.
var knownTargets = map[string]bool{
	TargetCursor:   true,
	TargetClaude:   true,
	TargetAgentsMD: true,
	TargetGemini:   true,
}

// knownActivations — allowed module activation methods.
var knownActivations = map[string]bool{
	ActivationAlways:   true,
	ActivationGlobs:    true,
	ActivationSemantic: true,
}

// Validate checks the ai-config source against the tpl TEMPLATE manifest:
//   - config.targets is non-empty and contains only known tools;
//   - module IDs are unique and non-empty;
//   - activation is valid; a globs module has globs; semantic has description;
//   - rule_file/doc_file are declared and exist on disk;
//   - module.when (if set) is syntactically valid (§3.2) and references only
//     groups declared in the tpl manifest's settings tree, replacing
//     go-template's `feature` check against the feature registry.
//
// Returns an aggregate error containing all problems (in stable order).
func (s *Source) Validate(tpl *manifest.Template) error {
	var problems []string

	if len(s.Config.Targets) == 0 {
		problems = append(problems, "config.targets is empty")
	}
	for _, t := range s.Config.Targets {
		if !knownTargets[t] {
			problems = append(problems, fmt.Sprintf("config.targets: unknown target %q", t))
		}
	}
	if s.Config.LineLength <= 0 {
		problems = append(problems, fmt.Sprintf("config.line_length must be positive, got %d", s.Config.LineLength))
	}

	knownGroups := settings.DefaultValues(tpl)
	seen := make(map[string]bool, len(s.Modules))
	for _, m := range s.Modules {
		problems = append(problems, validateModule(s.Dir, knownGroups, seen, m)...)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("aiconfig: source is invalid:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// validateModule collects problems for one module.
func validateModule(root string, knownGroups settings.Values, seen map[string]bool, m LoadedModule) []string {
	var problems []string
	prefix := "module " + m.ID

	if m.ID == "" {
		problems = append(problems, "module with empty id")
		prefix = "module <empty>"
	}
	if seen[m.ID] {
		problems = append(problems, prefix+": duplicate id")
	}
	seen[m.ID] = true

	if m.Title == "" {
		problems = append(problems, prefix+": empty title")
	}
	if !knownActivations[m.Activation] {
		problems = append(problems, fmt.Sprintf("%s: unknown activation %q", prefix, m.Activation))
	}
	if m.Activation == ActivationGlobs && len(m.Globs) == 0 {
		problems = append(problems, prefix+": activation=globs requires non-empty globs")
	}
	if m.Activation == ActivationSemantic && strings.TrimSpace(m.Description) == "" {
		problems = append(problems, prefix+": activation=semantic requires description")
	}

	problems = append(problems, validateModuleFile(root, prefix, "rule_file", m.RuleFile)...)
	problems = append(problems, validateModuleFile(root, prefix, "doc_file", m.DocFile)...)

	if m.When != "" {
		problems = append(problems, validateWhen(prefix, knownGroups, m.When)...)
	}
	return problems
}

// validateWhen checks a module's when syntax and the referential integrity of
// its atoms against groups, the set of group IDs known to the manifest.
func validateWhen(prefix string, groups settings.Values, when string) []string {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return []string{fmt.Sprintf("%s: when %q: %v", prefix, when, err)}
	}
	var problems []string
	for _, atom := range cond.Atoms {
		if _, ok := groups[atom.Group]; !ok {
			problems = append(problems, fmt.Sprintf("%s: when references non-existent group %q", prefix, atom.Group))
		}
	}
	return problems
}

// validateModuleFile checks that a path is set and the file exists.
func validateModuleFile(root, prefix, field, rel string) []string {
	if rel == "" {
		return []string{fmt.Sprintf("%s: %s is empty", prefix, field)}
	}
	info, err := os.Stat(filepath.Join(root, rel))
	if err != nil || info.IsDir() {
		return []string{fmt.Sprintf("%s: %s %q does not exist", prefix, field, rel)}
	}
	return nil
}
