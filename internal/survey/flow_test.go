package survey

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// plainPalette — палитра без цвета для детерминируемого вывода в тестах.
func plainPalette() ui.Palette { return ui.NewPalette(false) }

// runInteractive прогоняет AskFlow в интерактивном режиме с заданным опросником.
func runInteractive(t *testing.T, preset settings.Values, p Prompter) (settings.Resolved, string, error) {
	t.Helper()
	var buf bytes.Buffer
	res, err := AskFlow(testTemplate(), preset, FlowOptions{Interactive: true}, p, &buf, plainPalette())
	return res, buf.String(), err
}

func TestAskFlow_DefaultsMode_SkipsPrompter(t *testing.T) {
	// Опросник, паникующий при любом вызове — доказательство, что его не трогают.
	p := &panicPrompter{t: t}
	var buf bytes.Buffer
	res, err := AskFlow(testTemplate(), settings.Values{"database": "postgres"},
		FlowOptions{Defaults: true}, p, &buf, plainPalette())
	if err != nil {
		t.Fatalf("AskFlow defaults: %v", err)
	}
	if got := res.Values["database"]; got != "postgres" {
		t.Fatalf("database = %v, хотим postgres (preset применяется и в defaults)", got)
	}
	if got := res.Values["replicas"]; got != 3 {
		t.Fatalf("replicas = %v, хотим дефолт 3", got)
	}
}

func TestAskFlow_NonInteractive_DefaultForUnsetSelect(t *testing.T) {
	p := &panicPrompter{t: t}
	var buf bytes.Buffer
	// svc_name задаём (иначе required-ошибка), database не задаём — берётся дефолт.
	res, err := AskFlow(testTemplate(), settings.Values{"svc_name": "svc"},
		FlowOptions{Interactive: false}, p, &buf, plainPalette())
	if err != nil {
		t.Fatalf("AskFlow non-interactive: %v", err)
	}
	if got := res.Values["database"]; got != "none" {
		t.Fatalf("database = %v, хотим дефолт none", got)
	}
}

func TestAskFlow_NonInteractive_RequiredStringMissing(t *testing.T) {
	p := &panicPrompter{t: t}
	var buf bytes.Buffer
	_, err := AskFlow(testTemplate(), settings.Values{},
		FlowOptions{Interactive: false}, p, &buf, plainPalette())
	var missErr *MissingRequiredError
	if !errors.As(err, &missErr) {
		t.Fatalf("хотим *MissingRequiredError, получили %v", err)
	}
	if len(missErr.Groups) != 1 || missErr.Groups[0] != "svc_name" {
		t.Fatalf("Groups = %v, хотим [svc_name]", missErr.Groups)
	}
	if !strings.Contains(err.Error(), "--set") {
		t.Fatalf("сообщение должно подсказывать --set: %q", err.Error())
	}
}

func TestAskFlow_NonInteractive_NestedRequiredNotTriggeredWhenInactive(t *testing.T) {
	// kafka_topics (обязательная строка) активна только при выборе kafka.
	// Без брокеров она неактивна и не должна порождать required-ошибку.
	p := &panicPrompter{t: t}
	var buf bytes.Buffer
	_, err := AskFlow(testTemplate(), settings.Values{"svc_name": "svc"},
		FlowOptions{Interactive: false}, p, &buf, plainPalette())
	if err != nil {
		t.Fatalf("неактивная вложенная строка не должна быть обязательной: %v", err)
	}
}

func TestAskFlow_NonInteractive_NestedRequiredTriggeredWhenActive(t *testing.T) {
	// При preset brokers=kafka вложенная kafka_topics становится активной и
	// обязательной.
	p := &panicPrompter{t: t}
	var buf bytes.Buffer
	_, err := AskFlow(testTemplate(),
		settings.Values{"svc_name": "svc", "brokers": []string{"kafka"}},
		FlowOptions{Interactive: false}, p, &buf, plainPalette())
	var missErr *MissingRequiredError
	if !errors.As(err, &missErr) {
		t.Fatalf("хотим *MissingRequiredError для kafka_topics, получили %v", err)
	}
	if len(missErr.Groups) != 1 || missErr.Groups[0] != "kafka_topics" {
		t.Fatalf("Groups = %v, хотим [kafka_topics]", missErr.Groups)
	}
}

func TestAskFlow_Interactive_PresetBeatsPromptAndDefault(t *testing.T) {
	// preset фиксирует database=postgres; опрос его не спрашивает, но значение
	// побеждает. Прочие группы приходят из ответов (prompt), незаданные — дефолт.
	p := &ScriptedPrompter{
		Answers: []settings.Values{{
			"idempotency": true, // hoisted из postgres
			"brokers":     []string{},
			"auth":        []string{},
			"svc_name":    "myservice",
			"replicas":    5,
		}},
	}
	res, _, err := runInteractive(t, settings.Values{"database": "postgres"}, p)
	if err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if got := res.Values["database"]; got != "postgres" { // preset
		t.Fatalf("database = %v, хотим postgres (preset)", got)
	}
	if got := res.Values["svc_name"]; got != "myservice" { // prompt
		t.Fatalf("svc_name = %v, хотим myservice (prompt)", got)
	}
	if got := res.Values["replicas"]; got != 5 { // prompt переопределил дефолт 3
		t.Fatalf("replicas = %v, хотим 5 (prompt)", got)
	}
	// database не должна попадать в список опрошенных групп (она preset).
	for _, id := range p.AskCalls[0] {
		if id == "database" {
			t.Fatalf("preset-группа database не должна опрашиваться, AskCalls=%v", p.AskCalls[0])
		}
	}
}

func TestAskFlow_Interactive_NestedAskedOnlyWhenParentSelected(t *testing.T) {
	// Итерация 1: database=none → idempotency НЕ спрашивается.
	p := &ScriptedPrompter{
		Answers: []settings.Values{{
			"database": "none",
			"brokers":  []string{},
			"auth":     []string{},
			"svc_name": "svc",
			"replicas": 3,
		}},
	}
	if _, _, err := runInteractive(t, nil, p); err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if containsStr(p.AskCalls[0], "idempotency") {
		t.Fatalf("idempotency не должна опрашиваться при database=none: %v", p.AskCalls[0])
	}

	// database=postgres → idempotency спрашивается; kafka_* — нет (без kafka).
	p2 := &ScriptedPrompter{
		Answers: []settings.Values{{
			"database":    "postgres",
			"idempotency": false,
			"brokers":     []string{},
			"auth":        []string{},
			"svc_name":    "svc",
			"replicas":    3,
		}},
	}
	if _, _, err := runInteractive(t, nil, p2); err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if !containsStr(p2.AskCalls[0], "idempotency") {
		t.Fatalf("idempotency должна опрашиваться при database=postgres: %v", p2.AskCalls[0])
	}
	if containsStr(p2.AskCalls[0], "kafka_ssl") {
		t.Fatalf("kafka_ssl не должна опрашиваться без kafka: %v", p2.AskCalls[0])
	}
}

func TestAskFlow_Interactive_MultiselectRevealsNested(t *testing.T) {
	p := &ScriptedPrompter{
		Answers: []settings.Values{{
			"database":     "none",
			"brokers":      []string{"kafka"},
			"kafka_ssl":    true,
			"kafka_topics": "orders,events",
			"auth":         []string{},
			"svc_name":     "svc",
			"replicas":     3,
		}},
	}
	res, _, err := runInteractive(t, nil, p)
	if err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if !containsStr(p.AskCalls[0], "kafka_ssl") || !containsStr(p.AskCalls[0], "kafka_topics") {
		t.Fatalf("вложенные kafka_* должны опрашиваться при выборе kafka: %v", p.AskCalls[0])
	}
	if got := res.Values["kafka_topics"]; got != "orders,events" {
		t.Fatalf("kafka_topics = %v", got)
	}
}

func TestAskFlow_Interactive_SummaryPrinted(t *testing.T) {
	// Выбор auth=sso_provider согласован с самостоятельно выбранным database=postgres;
	// проверяем, что сводка печатается (доклад Implied проверяется напрямую в
	// summary_test.go, т.к. в полном опросе все активные группы явные).
	p := &ScriptedPrompter{
		Answers: []settings.Values{{
			"database": "postgres",
			"brokers":  []string{},
			"auth":     []string{"sso_provider"},
			"svc_name": "svc",
			"replicas": 3,
		}},
	}
	res, out, err := runInteractive(t, nil, p)
	if err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if got := res.Values["database"]; got != "postgres" {
		t.Fatalf("database = %v", got)
	}
	if !strings.Contains(out, "Сводка настроек") {
		t.Fatalf("вывод не содержит сводку:\n%s", out)
	}
}

func TestAskFlow_Interactive_ResolveConflictRepromptsSecondIteration(t *testing.T) {
	// preset auth=[sso_provider] требует database=postgres. Итерация 1 выбирает
	// database=none → конфликт с requires → переопрос. Итерация 2 выбирает
	// database=postgres → согласовано.
	p := &ScriptedPrompter{
		Answers: []settings.Values{
			{
				"database": "none",
				"brokers":  []string{},
				"svc_name": "svc",
				"replicas": 3,
			},
			{
				"database": "postgres",
				"brokers":  []string{},
				"svc_name": "svc",
				"replicas": 3,
			},
		},
	}
	res, out, err := runInteractive(t, settings.Values{"auth": []string{"sso_provider"}}, p)
	if err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if len(p.AskCalls) != 2 {
		t.Fatalf("ожидали 2 итерации опроса, было %d", len(p.AskCalls))
	}
	if got := res.Values["database"]; got != "postgres" {
		t.Fatalf("итог database = %v, хотим postgres", got)
	}
	if !strings.Contains(out, "не согласованы") {
		t.Fatalf("ожидали сообщение о рассогласовании:\n%s", out)
	}
}

func TestAskFlow_Interactive_ConfirmRejectReprompts(t *testing.T) {
	answer := settings.Values{
		"database": "none",
		"brokers":  []string{},
		"auth":     []string{},
		"svc_name": "svc",
		"replicas": 3,
	}
	p := &ScriptedPrompter{
		Answers:  []settings.Values{answer, answer},
		Confirms: []bool{false, true}, // сначала отказ, затем согласие
	}
	if _, _, err := runInteractive(t, nil, p); err != nil {
		t.Fatalf("AskFlow: %v", err)
	}
	if len(p.AskCalls) != 2 {
		t.Fatalf("отказ от подтверждения должен переопросить: было %d итераций", len(p.AskCalls))
	}
}

func TestAskFlow_Interactive_AbortPropagates(t *testing.T) {
	sentinel := errors.New("user aborted")
	p := &abortPrompter{err: sentinel}
	_, _, err := runInteractive(t, nil, p)
	if !errors.Is(err, sentinel) {
		t.Fatalf("ожидали проброс ошибки прерывания, получили %v", err)
	}
}

// --- вспомогательные опросники ---

// panicPrompter проваливает тест при любом вызове — доказывает, что Prompter
// не трогают (режимы defaults/non-interactive).
type panicPrompter struct{ t *testing.T }

func (p *panicPrompter) Ask([]manifest.SettingGroup, settings.Values) (settings.Values, error) {
	p.t.Fatalf("Prompter.Ask не должен вызываться в этом режиме")
	return nil, nil
}

func (p *panicPrompter) Confirm(string) (bool, error) {
	p.t.Fatalf("Prompter.Confirm не должен вызываться в этом режиме")
	return false, nil
}

// abortPrompter имитирует Ctrl+C на первом же Ask.
type abortPrompter struct{ err error }

func (p *abortPrompter) Ask([]manifest.SettingGroup, settings.Values) (settings.Values, error) {
	return nil, p.err
}

func (p *abortPrompter) Confirm(string) (bool, error) { return false, nil }

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
