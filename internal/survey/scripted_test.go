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
		t.Errorf("idempotency must be prompted: %v", p.AskCalls[0])
	}
	if _, ok := got["kafka_ssl"]; ok {
		t.Errorf("kafka_ssl must not be prompted: %v", p.AskCalls[0])
	}
	if got["database"] != "postgres" {
		t.Errorf("database = %v", got["database"])
	}
}

func TestScriptedPrompter_ExhaustedAsk(t *testing.T) {
	p := &ScriptedPrompter{}
	if _, err := p.Ask(nil, nil); err == nil {
		t.Fatalf("expected an error with an empty answer queue")
	}
}

func TestScriptedPrompter_ConfirmQueueAndDefault(t *testing.T) {
	p := &ScriptedPrompter{Confirms: []bool{false}}
	if ok, _ := p.Confirm("s1"); ok {
		t.Errorf("the first Confirm must return false")
	}
	if ok, _ := p.Confirm("s2"); !ok {
		t.Errorf("an exhausted Confirm queue must yield true")
	}
	if len(p.Summaries) != 2 {
		t.Errorf("Summaries = %v, want 2 entries", p.Summaries)
	}
}
