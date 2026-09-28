package survey

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestBuildSummary_SourcesAndImpliedMark(t *testing.T) {
	tpl := testTemplate()
	// Resolution with implication: auth=sso_provider pulls database=postgres.
	resolved, err := settings.Resolve(tpl, settings.Values{
		"auth":     []string{"sso_provider"},
		"svc_name": "mysvc",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resolved.Report.Implied) == 0 {
		t.Fatalf("ожидали довключение database=postgres")
	}

	preset := settings.Values{"svc_name": "mysvc"}
	asked := settings.Values{"replicas": 5} // as if asked
	summary := buildSummary(tpl, resolved, preset, asked,
		map[string]Source{"svc_name": SourceAnswer}, plainPalette())

	// database was implied → source implied.
	if !lineHas(summary, "database", "implied") {
		t.Fatalf("database должен иметь источник implied:\n%s", summary)
	}
	// svc_name from --answers.
	if !lineHas(summary, "svc_name", "answer") {
		t.Fatalf("svc_name должен иметь источник answer:\n%s", summary)
	}
	// replicas was "asked".
	if !lineHas(summary, "replicas", "prompt") {
		t.Fatalf("replicas должен иметь источник prompt:\n%s", summary)
	}
	// brokers untouched → default.
	if !lineHas(summary, "brokers", "default") {
		t.Fatalf("brokers должен иметь источник default:\n%s", summary)
	}
}

func TestPrintReport_ImpliedAndWarnings(t *testing.T) {
	var buf bytes.Buffer
	rep := settings.Report{
		Implied:  []settings.ImpliedValue{{Group: "database", Value: "postgres", RequiredBy: "sso_provider"}},
		Warnings: []string{"группа X неактивна"},
	}
	printReport(&buf, plainPalette(), rep)
	out := buf.String()
	if !strings.Contains(out, "Довключено") {
		t.Fatalf("нет заголовка довключений:\n%s", out)
	}
	if !strings.Contains(out, "database=postgres") || !strings.Contains(out, "sso_provider") {
		t.Fatalf("нет строки довключения:\n%s", out)
	}
	if !strings.Contains(out, "предупреждение") {
		t.Fatalf("нет предупреждения:\n%s", out)
	}
}

func TestFormatValue(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{[]string{"a", "b"}, "a,b"},
		{true, "true"},
		{7, "7"},
		{"x", "x"},
	}
	for _, c := range cases {
		if got := formatValue(c.in); got != c.want {
			t.Errorf("formatValue(%v) = %q, хотим %q", c.in, got, c.want)
		}
	}
}

// lineHas reports that the summary contains a line with both the ID and source label.
func lineHas(summary, id, source string) bool {
	for _, line := range strings.Split(summary, "\n") {
		if strings.Contains(line, id) && strings.Contains(line, source) {
			return true
		}
	}
	return false
}
