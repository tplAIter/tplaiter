package survey

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestScriptedPrompter_AsksOnlyActiveGroups(t *testing.T) {
	tpl := testTemplate()
	p := &ScriptedPrompter{
		Answers: []settings.Values{{
			"database": "postgres", // activates idempotency
			"brokers":  []string{}, // no broker → kafka_* inactive
			"auth":     []string{},
			"svc_name": "svc",
			"replicas": 3,
		}},
	}
	got, err := p.Ask(tpl.Settings, settings.DefaultValues(tpl))
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	// idempotency active (postgres), kafka_* inactive.
	if _, ok := got["idempotency"]; !ok {
		t.Errorf("idempotency должна быть опрошена: %v", p.AskCalls[0])
	}
	if _, ok := got["kafka_ssl"]; ok {
		t.Errorf("kafka_ssl не должна быть опрошена: %v", p.AskCalls[0])
	}
	if got["database"] != "postgres" {
		t.Errorf("database = %v", got["database"])
	}
}

func TestScriptedPrompter_ExhaustedAsk(t *testing.T) {
	p := &ScriptedPrompter{}
	if _, err := p.Ask(nil, nil); err == nil {
		t.Fatalf("ожидали ошибку при пустой очереди ответов")
	}
}

func TestScriptedPrompter_ConfirmQueueAndDefault(t *testing.T) {
	p := &ScriptedPrompter{Confirms: []bool{false}}
	if ok, _ := p.Confirm("s1"); ok {
		t.Errorf("первый Confirm должен вернуть false")
	}
	if ok, _ := p.Confirm("s2"); !ok {
		t.Errorf("исчерпанная очередь Confirm должна давать true")
	}
	if len(p.Summaries) != 2 {
		t.Errorf("Summaries = %v, хотим 2 записи", p.Summaries)
	}
}
