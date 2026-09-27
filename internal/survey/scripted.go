package survey

import (
	"fmt"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ScriptedPrompter — тестовая реализация [Prompter] без TTY. Проигрывает
// заранее заданные ответы: на i-й вызов Ask берётся Answers[i] (карта id
// группы → значение), на i-й вызов Confirm — Confirms[i]. Активные группы
// (с учётом выбора родителей по проигранным ответам) вычисляются той же
// логикой, что и боевой опросник, а их порядок фиксируется в AskCalls для
// проверок «что реально спрашивалось».
type ScriptedPrompter struct {
	// Answers — очередь наборов ответов, по одному на вызов Ask.
	Answers []settings.Values
	// Confirms — очередь результатов подтверждения, по одному на вызов Confirm.
	Confirms []bool

	// AskCalls — записанные (в порядке опроса) id активных групп каждого Ask.
	AskCalls [][]string
	// Summaries — сводки, переданные в Confirm (для инспекции в тестах).
	Summaries []string

	askIdx  int
	confIdx int
}

// Ask проигрывает очередной набор ответов: обходит активные группы дерева
// (учитывая выбор родителей по проигранным значениям), фиксирует их id в
// AskCalls и возвращает значения этих групп.
func (s *ScriptedPrompter) Ask(groups []manifest.SettingGroup, current settings.Values) (settings.Values, error) {
	if s.askIdx >= len(s.Answers) {
		s.askIdx++
		return nil, fmt.Errorf("scripted: нет ответа для вызова Ask #%d", s.askIdx)
	}
	ans := s.Answers[s.askIdx]
	s.askIdx++

	valueOf := func(id string) any {
		if ans != nil {
			if v, ok := ans[id]; ok {
				return v
			}
		}
		return current[id]
	}

	out := make(settings.Values)
	var asked []string
	walkActive(groups, valueOf, func(g *manifest.SettingGroup) {
		asked = append(asked, g.Group)
		out[g.Group] = valueOf(g.Group)
	})
	s.AskCalls = append(s.AskCalls, asked)
	return out, nil
}

// Confirm возвращает очередной запланированный результат подтверждения
// (по исчерпании очереди — true, чтобы одиночный успешный сценарий не требовал
// явного Confirms).
func (s *ScriptedPrompter) Confirm(summary string) (bool, error) {
	s.Summaries = append(s.Summaries, summary)
	v := true
	if s.confIdx < len(s.Confirms) {
		v = s.Confirms[s.confIdx]
	}
	s.confIdx++
	return v, nil
}
