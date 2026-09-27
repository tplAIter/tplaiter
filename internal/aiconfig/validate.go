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

// knownTargets — целевые инструменты, которые умеет рендерить генератор.
var knownTargets = map[string]bool{
	TargetCursor:   true,
	TargetClaude:   true,
	TargetAgentsMD: true,
	TargetGemini:   true,
}

// knownActivations — допустимые способы активации модуля.
var knownActivations = map[string]bool{
	ActivationAlways:   true,
	ActivationGlobs:    true,
	ActivationSemantic: true,
}

// Validate проверяет консистентность источника ai-config против манифеста
// ШАБЛОНА tpl:
//   - config.targets непустой и содержит только известные инструменты;
//   - id модулей уникальны и непусты;
//   - activation допустимый; globs-модуль имеет globs; semantic — description;
//   - rule_file/doc_file объявлены и физически существуют;
//   - module.when (если задан) синтаксически корректен (§3.2) и ссылается
//     только на группы, объявленные в дереве settings манифеста tpl — замена
//     go-template'овской проверки `feature` против реестра фич.
//
// Возвращает агрегированную ошибку со всеми проблемами (стабильный порядок).
func (s *Source) Validate(tpl *manifest.Template) error {
	var problems []string

	if len(s.Config.Targets) == 0 {
		problems = append(problems, "config.targets пуст")
	}
	for _, t := range s.Config.Targets {
		if !knownTargets[t] {
			problems = append(problems, fmt.Sprintf("config.targets: неизвестный target %q", t))
		}
	}
	if s.Config.LineLength <= 0 {
		problems = append(problems, fmt.Sprintf("config.line_length должен быть положительным, получено %d", s.Config.LineLength))
	}

	knownGroups := settings.DefaultValues(tpl)
	seen := make(map[string]bool, len(s.Modules))
	for _, m := range s.Modules {
		problems = append(problems, validateModule(s.Dir, knownGroups, seen, m)...)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("aiconfig: источник невалиден:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// validateModule собирает проблемы одного модуля.
func validateModule(root string, knownGroups settings.Values, seen map[string]bool, m LoadedModule) []string {
	var problems []string
	prefix := "модуль " + m.ID

	if m.ID == "" {
		problems = append(problems, "модуль с пустым id")
		prefix = "модуль <пусто>"
	}
	if seen[m.ID] {
		problems = append(problems, prefix+": дублирующийся id")
	}
	seen[m.ID] = true

	if m.Title == "" {
		problems = append(problems, prefix+": пустой title")
	}
	if !knownActivations[m.Activation] {
		problems = append(problems, fmt.Sprintf("%s: неизвестная activation %q", prefix, m.Activation))
	}
	if m.Activation == ActivationGlobs && len(m.Globs) == 0 {
		problems = append(problems, prefix+": activation=globs требует непустые globs")
	}
	if m.Activation == ActivationSemantic && strings.TrimSpace(m.Description) == "" {
		problems = append(problems, prefix+": activation=semantic требует description")
	}

	problems = append(problems, validateModuleFile(root, prefix, "rule_file", m.RuleFile)...)
	problems = append(problems, validateModuleFile(root, prefix, "doc_file", m.DocFile)...)

	if m.When != "" {
		problems = append(problems, validateWhen(prefix, knownGroups, m.When)...)
	}
	return problems
}

// validateWhen проверяет синтаксис when модуля и ссылочную целостность его
// атомов относительно groups — множества id групп, известных манифесту.
func validateWhen(prefix string, groups settings.Values, when string) []string {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return []string{fmt.Sprintf("%s: when %q: %v", prefix, when, err)}
	}
	var problems []string
	for _, atom := range cond.Atoms {
		if _, ok := groups[atom.Group]; !ok {
			problems = append(problems, fmt.Sprintf("%s: when ссылается на несуществующую группу %q", prefix, atom.Group))
		}
	}
	return problems
}

// validateModuleFile проверяет, что путь задан и файл существует.
func validateModuleFile(root, prefix, field, rel string) []string {
	if rel == "" {
		return []string{fmt.Sprintf("%s: %s пуст", prefix, field)}
	}
	info, err := os.Stat(filepath.Join(root, rel))
	if err != nil || info.IsDir() {
		return []string{fmt.Sprintf("%s: %s %q не существует", prefix, field, rel)}
	}
	return nil
}
