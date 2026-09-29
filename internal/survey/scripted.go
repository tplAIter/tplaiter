package survey

import (
	"fmt"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ScriptedPrompter — TTY-free test [Prompter]. It replays predefined answers:
// Ask call i uses Answers[i] (group ID → value), Confirm call i uses Confirms[i].
// Active groups (including parent choices from replayed answers) use the same
// logic as the production questionnaire, and order is recorded in AskCalls.
type ScriptedPrompter struct {
	// Answers — answer-set queue, one per Ask call.
	Answers []settings.Values
	// Confirms — confirmation-result queue, one per Confirm call.
	Confirms []bool

	// AskCalls — active-group IDs recorded for each Ask, in question order.
	AskCalls [][]string
	// Summaries — summaries passed to Confirm (for test inspection).
	Summaries []string

	askIdx  int
	confIdx int
}

// Ask replays the next answer set: traverses active groups (respecting parent
// choices from replayed values), records their IDs in AskCalls, and returns values.
func (s *ScriptedPrompter) Ask(groups []manifest.SettingGroup, current settings.Values) (settings.Values, error) {
	if s.askIdx >= len(s.Answers) {
		s.askIdx++
		return nil, fmt.Errorf("scripted: no answer for Ask call #%d", s.askIdx)
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

// Confirm returns the next planned confirmation result (true after the queue is
// exhausted, so a single successful scenario needs no explicit Confirms).
func (s *ScriptedPrompter) Confirm(summary string) (bool, error) {
	s.Summaries = append(s.Summaries, summary)
	v := true
	if s.confIdx < len(s.Confirms) {
		v = s.Confirms[s.confIdx]
	}
	s.confIdx++
	return v, nil
}
