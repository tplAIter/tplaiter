package gen

import (
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

func genWithParams(params ...manifest.Param) *manifest.Generator {
	return &manifest.Generator{Kind: "crud", Params: params}
}

func TestResolveParams_RequiredMissing(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "fields", Type: manifest.ParamTypeFields, Required: true, Description: "entity fields"})
	_, _, err := ResolveParams(g, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "--fields is required") {
		t.Fatalf("expected required error, got %v", err)
	}
	if !strings.Contains(err.Error(), "entity fields") {
		t.Errorf("required error should include description: %v", err)
	}
}

func TestResolveParams_FieldsProvided(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "fields", Type: manifest.ParamTypeFields, Required: true})
	params, fields, err := ResolveParams(g, map[string]string{"fields": "a:string,b:int"})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("fields = %v", fields)
	}
	pf, ok := params["fields"].([]Field)
	if !ok || len(pf) != 2 {
		t.Errorf("params[fields] = %#v", params["fields"])
	}
}

func TestResolveParams_BoolDefault(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "with-list", Type: manifest.ParamTypeBool, Default: true})

	// Not set → default true.
	params, _, err := ResolveParams(g, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	if params["with-list"] != true {
		t.Errorf("default bool = %#v, want true", params["with-list"])
	}

	// Explicitly set → overrides default.
	params, _, err = ResolveParams(g, map[string]string{"with-list": "false"})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	if params["with-list"] != false {
		t.Errorf("explicit bool = %#v, want false", params["with-list"])
	}
}

func TestResolveParams_TypeConversions(t *testing.T) {
	g := genWithParams(
		manifest.Param{Name: "count", Type: manifest.ParamTypeInt},
		manifest.Param{Name: "table", Type: manifest.ParamTypeString},
	)
	params, _, err := ResolveParams(g, map[string]string{"count": "7", "table": "orders"})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	if params["count"] != 7 {
		t.Errorf("count = %#v, want 7", params["count"])
	}
	if params["table"] != "orders" {
		t.Errorf("table = %#v", params["table"])
	}
}

func TestResolveParams_InvalidInt(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "count", Type: manifest.ParamTypeInt})
	_, _, err := ResolveParams(g, map[string]string{"count": "notint"})
	if err == nil || !strings.Contains(err.Error(), "int") {
		t.Fatalf("expected int conversion error, got %v", err)
	}
}

func TestResolveParams_PatternRejectsProvidedValue(t *testing.T) {
	g := genWithParams(manifest.Param{
		Name: "table", Type: manifest.ParamTypeString, Required: true,
		Pattern: `^[a-z_][a-z0-9_]*$`,
	})
	for _, raw := range []string{"ride events", `rides; DROP TABLE rides`, `\"rides\"`, "rides--comment"} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := ResolveParams(g, map[string]string{"table": raw})
			if err == nil || !strings.Contains(err.Error(), "does not match pattern") {
				t.Fatalf("ResolveParams(%q): expected pattern rejection, got %v", raw, err)
			}
		})
	}
	params, _, err := ResolveParams(g, map[string]string{"table": "driver_locations"})
	if err != nil {
		t.Fatalf("valid identifier: %v", err)
	}
	if params["table"] != "driver_locations" {
		t.Errorf("table = %#v", params["table"])
	}
}

func TestResolveParams_PatternRejectsInvalidDefault(t *testing.T) {
	g := genWithParams(manifest.Param{
		Name: "port", Type: manifest.ParamTypeInt, Default: 0, Pattern: `^[1-9][0-9]*$`,
	})
	_, _, err := ResolveParams(g, nil)
	if err == nil || !strings.Contains(err.Error(), "(default)") || !strings.Contains(err.Error(), "does not match pattern") {
		t.Fatalf("invalid patterned default must fail, got %v", err)
	}
}

func TestResolveParams_RequiredWithDefaultOK(t *testing.T) {
	// required + default → missing flag is not an error (default is used).
	g := genWithParams(manifest.Param{Name: "table", Type: manifest.ParamTypeString, Required: true, Default: "t"})
	params, _, err := ResolveParams(g, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	if params["table"] != "t" {
		t.Errorf("table = %#v, want t", params["table"])
	}
}

func TestResolveParams_ListProvided(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "activities", Type: manifest.ParamTypeList, Required: true})
	params, _, err := ResolveParams(g, map[string]string{"activities": "payments.DebitAccount, notify.SendEmail ,"})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	list, ok := params["activities"].([]string)
	if !ok {
		t.Fatalf("params[activities] type = %T", params["activities"])
	}
	// Whitespace is trimmed and the trailing comma is discarded.
	if len(list) != 2 || list[0] != "payments.DebitAccount" || list[1] != "notify.SendEmail" {
		t.Errorf("list = %#v", list)
	}
}

func TestResolveParams_ListDefault(t *testing.T) {
	g := genWithParams(manifest.Param{Name: "activities", Type: manifest.ParamTypeList, Default: "a.Foo,b.Bar"})
	params, _, err := ResolveParams(g, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	list, ok := params["activities"].([]string)
	if !ok || len(list) != 2 {
		t.Errorf("default list = %#v", params["activities"])
	}
}

func TestResolveParams_ListEmptyOptional(t *testing.T) {
	// Optional list without a flag → nil []string, not an error.
	g := genWithParams(manifest.Param{Name: "tags", Type: manifest.ParamTypeList})
	params, _, err := ResolveParams(g, map[string]string{})
	if err != nil {
		t.Fatalf("ResolveParams: %v", err)
	}
	list, ok := params["tags"].([]string)
	if !ok || list != nil {
		t.Errorf("empty optional list = %#v", params["tags"])
	}
}

func TestParseList(t *testing.T) {
	if got := ParseList("  "); got != nil {
		t.Errorf("ParseList(blank) = %#v, want nil", got)
	}
	got := ParseList("x, y ,z")
	if len(got) != 3 || got[0] != "x" || got[2] != "z" {
		t.Errorf("ParseList = %#v", got)
	}
}
