package engine

import (
	"strings"
	"testing"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/settings"
)

func TestCaseFuncs(t *testing.T) {
	cases := []struct {
		in                                     string
		snake, kebab, camel, pascal, slugified string
	}{
		{"Awesome Svc", "awesome_svc", "awesome-svc", "awesomeSvc", "AwesomeSvc", "awesome_svc"},
		{"awesome-svc", "awesome_svc", "awesome-svc", "awesomeSvc", "AwesomeSvc", "awesome_svc"},
		{"HTTPServer", "http_server", "http-server", "httpServer", "HttpServer", "http_server"},
		{"user_id", "user_id", "user-id", "userId", "UserId", "user_id"},
		{"orderV2", "order_v2", "order-v2", "orderV2", "OrderV2", "order_v2"},
		{"already", "already", "already", "already", "Already", "already"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := Snake(c.in); got != c.snake {
				t.Errorf("Snake(%q) = %q, want %q", c.in, got, c.snake)
			}
			if got := Kebab(c.in); got != c.kebab {
				t.Errorf("Kebab(%q) = %q, want %q", c.in, got, c.kebab)
			}
			if got := Camel(c.in); got != c.camel {
				t.Errorf("Camel(%q) = %q, want %q", c.in, got, c.camel)
			}
			if got := Pascal(c.in); got != c.pascal {
				t.Errorf("Pascal(%q) = %q, want %q", c.in, got, c.pascal)
			}
			if got := Slugify(c.in); got != c.slugified {
				t.Errorf("Slugify(%q) = %q, want %q", c.in, got, c.slugified)
			}
		})
	}
}

func TestStaticFuncMapKeys(t *testing.T) {
	fm := StaticFuncMap()
	for _, k := range []string{"slug", "snake", "camel", "pascal", "kebab", "upper", "lower", "quote", "split"} {
		if _, ok := fm[k]; !ok {
			t.Errorf("StaticFuncMap missing %q", k)
		}
	}
	for _, k := range []string{"is", "has"} {
		if _, ok := fm[k]; ok {
			t.Errorf("StaticFuncMap should not include %q (only FuncMap binds it)", k)
		}
	}
}

func TestSplitFunc(t *testing.T) {
	fn, ok := StaticFuncMap()["split"].(func(string, string) []string)
	if !ok {
		t.Fatalf("split has unexpected type %T", StaticFuncMap()["split"])
	}
	got := fn(".", "payments.DebitAccount")
	if len(got) != 2 || got[0] != "payments" || got[1] != "DebitAccount" {
		t.Errorf(`split(".", "payments.DebitAccount") = %#v`, got)
	}
	// Pipeline order: {{ "a,b" | split "," }} → split(",", "a,b").
	tmpl := template.Must(template.New("t").Funcs(StaticFuncMap()).
		Parse(`{{ index ("a.b.c" | split ".") 1 }}`))
	var buf strings.Builder
	if err := tmpl.Execute(&buf, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if buf.String() != "b" {
		t.Errorf("pipe split = %q, want b", buf.String())
	}
}

func TestFuncMapIsHas(t *testing.T) {
	view := settings.View{
		"database": "postgres",
		"brokers":  []string{"kafka"},
	}
	fm := FuncMap(view)

	is, ok := fm["is"].(func(string, string) bool)
	if !ok {
		t.Fatalf("FuncMap[\"is\"] has unexpected type %T", fm["is"])
	}
	if !is("database", "postgres") {
		t.Errorf(`is("database", "postgres") = false, want true`)
	}
	if is("database", "mysql") {
		t.Errorf(`is("database", "mysql") = true, want false`)
	}

	has, ok := fm["has"].(func(string, string) bool)
	if !ok {
		t.Fatalf("FuncMap[\"has\"] has unexpected type %T", fm["has"])
	}
	if !has("brokers", "kafka") {
		t.Errorf(`has("brokers", "kafka") = false, want true`)
	}
	if has("brokers", "rabbitmq") {
		t.Errorf(`has("brokers", "rabbitmq") = true, want false`)
	}

	// Static functions remain available in the full set.
	for _, k := range []string{"slug", "snake", "camel", "pascal", "kebab", "upper", "lower", "quote", "split"} {
		if _, ok := fm[k]; !ok {
			t.Errorf("FuncMap missing static %q", k)
		}
	}
}
