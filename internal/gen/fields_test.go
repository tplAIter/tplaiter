package gen

import (
	"strings"
	"testing"
)

func TestParseFields_AllTypes(t *testing.T) {
	fields, err := ParseFields("customer:string,amount:float64,count:int,big:int64,active:bool,at:time.Time,id:uuid,tags:[]string")
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	want := []struct {
		snake, goType, sqlType, zero string
		isSlice                      bool
	}{
		{"customer", "string", "text", `""`, false},
		{"amount", "float64", "double precision", "0", false},
		{"count", "int", "bigint", "0", false},
		{"big", "int64", "bigint", "0", false},
		{"active", "bool", "boolean", "false", false},
		{"at", "time.Time", "timestamptz", "time.Time{}", false},
		{"id", "uuid.UUID", "uuid", "uuid.UUID{}", false},
		{"tags", "[]string", "jsonb", "nil", true},
	}
	if len(fields) != len(want) {
		t.Fatalf("got %d fields, want %d", len(fields), len(want))
	}
	for i, w := range want {
		f := fields[i]
		if f.Name.Snake != w.snake || f.GoType != w.goType || f.SQLType != w.sqlType || f.Zero != w.zero || f.IsSlice != w.isSlice {
			t.Errorf("field[%d] = %+v, want snake=%q go=%q sql=%q zero=%q slice=%v",
				i, f, w.snake, w.goType, w.sqlType, w.zero, w.isSlice)
		}
	}
}

func TestParseFields_NameDerivations(t *testing.T) {
	fields, err := ParseFields("OrderLine:string")
	if err != nil {
		t.Fatalf("ParseFields: %v", err)
	}
	f := fields[0]
	if f.NameRaw != "OrderLine" || f.Name.Pascal != "OrderLine" || f.Name.Camel != "orderLine" ||
		f.Name.Snake != "order_line" || f.Name.Kebab != "order-line" {
		t.Errorf("derivations = %+v", f.Name)
	}
}

func TestParseFields_Empty(t *testing.T) {
	fields, err := ParseFields("   ")
	if err != nil || fields != nil {
		t.Errorf("empty spec: fields=%v err=%v", fields, err)
	}
}

func TestParseFields_Errors(t *testing.T) {
	cases := []struct {
		spec, want string
	}{
		{"customer", "ожидается name:type"},
		{"customer:", "ожидается name:type"},
		{":string", "ожидается name:type"},
		{"amount:,x:int", "ожидается name:type"},
		{"a:int,,b:int", "пустой элемент"},
		{"1bad:string", "недопустимое имя"},
		{"x:decimal", "неизвестный тип"},
		{"x:[]decimal", "неизвестный тип элемента слайса"},
		{"amount:int,amount:string", "дублирующееся имя"},
	}
	for _, c := range cases {
		_, err := ParseFields(c.spec)
		if err == nil {
			t.Errorf("ParseFields(%q): expected error", c.spec)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("ParseFields(%q) error = %v, want substr %q", c.spec, err, c.want)
		}
	}
}

// TestParseFields_UnknownTypeListsAllowed: сообщение об ошибке перечисляет
// допустимые типы (в т.ч. форму []T).
func TestParseFields_UnknownTypeListsAllowed(t *testing.T) {
	_, err := ParseFields("x:decimal")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"string", "int64", "time.Time", "uuid", "[]T"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing allowed type %q", err, want)
		}
	}
}
