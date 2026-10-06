package engine

import (
	"go/format"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/settings"
)

// markerValues is the standard settings value set for marker tests: select,
// multiselect, and toggle groups covering all three matchValue comparisons in
// [settings.Eval].
func markerValues() settings.Values {
	return settings.Values{
		"database":   "postgres",
		"brokers":    []string{"kafka"},
		"migrations": true,
	}
}

func TestProcessMarkers_NoMarkers(t *testing.T) {
	in := "plain line\nanother line\n"
	out, err := processMarkers("f.txt", []byte(in), markerValues())
	if err != nil {
		t.Fatalf("processMarkers() = %v", err)
	}
	if string(out) != in {
		t.Errorf("output changed for marker-free content: %q", out)
	}
}

func TestProcessMarkers_TailIf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "slash-slash true kept, comment stripped",
			in:   "kafkaMode, // tplater:if brokers=kafka\n",
			want: "kafkaMode,\n",
		},
		{
			name: "slash-slash false dropped entirely",
			in:   "before\nkafkaMode, // tplater:if brokers=rabbitmq\nafter\n",
			want: "before\nafter\n",
		},
		{
			name: "hash style select match",
			in:   "line = 1  # tplater:if database=postgres\n",
			want: "line = 1\n",
		},
		{
			name: "hash style select mismatch dropped",
			in:   "line = 1  # tplater:if database=mysql\n",
			want: "",
		},
		{
			name: "html comment style true kept",
			in:   "<div>x</div> <!-- tplater:if brokers=kafka -->\n",
			want: "<div>x</div>\n",
		},
		{
			name: "html comment style false dropped",
			in:   "<div>x</div> <!-- tplater:if brokers=rabbitmq -->\n",
			want: "",
		},
		{
			name: "inversion true condition -> dropped",
			in:   "metrics := newMetrics() // tplater:if! migrations=true\n",
			want: "",
		},
		{
			name: "inversion false condition -> kept",
			in:   "metrics := newMetrics() // tplater:if! migrations=false\n",
			want: "metrics := newMetrics()\n",
		},
		{
			name: "block comment style with explicit close",
			in:   "x := 1 /* tplater:if database=postgres */\n",
			want: "x := 1\n",
		},
		{
			name: "semicolon comment style (asm/sql-like)",
			in:   "MOV AX, 1 ; tplater:if database=postgres\n",
			want: "MOV AX, 1\n",
		},
		{
			name: "comment-only line becomes empty, no trailing spaces",
			in:   "  // tplater:if database=postgres\n",
			want: "\n",
		},
		{
			name: "generic fallback without recognized comment prefix",
			in:   "keep-me tplater:if database=postgres\n",
			want: "keep-me\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := processMarkers("f.txt", []byte(tc.in), markerValues())
			if err != nil {
				t.Fatalf("processMarkers() = %v", err)
			}
			if string(out) != tc.want {
				t.Errorf("processMarkers() = %q, want %q", out, tc.want)
			}
		})
	}
}

func TestProcessMarkers_Block(t *testing.T) {
	in := "before\n// tplater:begin database=postgres\ninside\n// tplater:end\nafter\n"

	out, err := processMarkers("f.txt", []byte(in), markerValues())
	if err != nil {
		t.Fatalf("processMarkers() = %v", err)
	}
	want := "before\ninside\nafter\n"
	if string(out) != want {
		t.Errorf("true condition: got %q, want %q", out, want)
	}

	falseValues := markerValues()
	falseValues["database"] = "mysql"
	out, err = processMarkers("f.txt", []byte(in), falseValues)
	if err != nil {
		t.Fatalf("processMarkers() = %v", err)
	}
	want = "before\nafter\n"
	if string(out) != want {
		t.Errorf("false condition: got %q, want %q", out, want)
	}
}

func TestProcessMarkers_BlockHashStyle(t *testing.T) {
	in := "before\n# tplater:begin brokers=kafka\ninside\n# tplater:end\nafter\n"
	out, err := processMarkers("f.txt", []byte(in), markerValues())
	if err != nil {
		t.Fatalf("processMarkers() = %v", err)
	}
	want := "before\ninside\nafter\n"
	if string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestProcessMarkers_NestedBlocks(t *testing.T) {
	in := strings.Join([]string{
		"outer-before",
		"// tplater:begin database=postgres",
		"mid-before",
		"// tplater:begin brokers=kafka",
		"inner",
		"// tplater:end",
		"mid-after",
		"// tplater:end",
		"outer-after",
		"",
	}, "\n")

	t.Run("both true — everything kept", func(t *testing.T) {
		out, err := processMarkers("f.txt", []byte(in), markerValues())
		if err != nil {
			t.Fatalf("processMarkers() = %v", err)
		}
		want := "outer-before\nmid-before\ninner\nmid-after\nouter-after\n"
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("inner false — only inner line disappears", func(t *testing.T) {
		values := markerValues()
		values["brokers"] = []string{}
		out, err := processMarkers("f.txt", []byte(in), values)
		if err != nil {
			t.Fatalf("processMarkers() = %v", err)
		}
		want := "outer-before\nmid-before\nmid-after\nouter-after\n"
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})

	t.Run("outer false — entire block disappears regardless of inner", func(t *testing.T) {
		values := markerValues()
		values["database"] = "mysql"
		out, err := processMarkers("f.txt", []byte(in), values)
		if err != nil {
			t.Fatalf("processMarkers() = %v", err)
		}
		want := "outer-before\nouter-after\n"
		if string(out) != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})
}

func TestProcessMarkers_Errors(t *testing.T) {
	t.Run("end without begin", func(t *testing.T) {
		in := "one\ntwo\n// tplater:end\nfour\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "f.txt:3:") {
			t.Errorf("error missing file:line (f.txt:3): %v", err)
		}
	})

	t.Run("unpaired begin", func(t *testing.T) {
		in := "one\n// tplater:begin database=postgres\nthree\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "f.txt:2:") {
			t.Errorf("error missing begin line (f.txt:2): %v", err)
		}
	})

	t.Run("broken condition", func(t *testing.T) {
		in := "x := 1 // tplater:if database==postgres\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "f.txt:1:") {
			t.Errorf("error missing file:line: %v", err)
		}
	})

	t.Run("unknown group", func(t *testing.T) {
		in := "x := 1 // tplater:if nonexistent=true\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "unknown group") {
			t.Errorf("expected unknown-group error, got: %v", err)
		}
	})

	t.Run("unknown marker (typo)", func(t *testing.T) {
		in := "x := 1 // tplater:iff database=postgres\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "f.txt:1:") || !strings.Contains(err.Error(), "unknown tplater marker") {
			t.Errorf("expected unknown-marker error at f.txt:1, got: %v", err)
		}
	})

	t.Run("garbled marker keyword", func(t *testing.T) {
		in := "// tplater:begni database=postgres\n"
		_, err := processMarkers("f.txt", []byte(in), markerValues())
		if err == nil {
			t.Fatal("expected error for garbled marker keyword")
		}
	})
}

// TestProcessMarkers_GoFileGofmtClean checks the  requirement: a file with a
// trailing if marker remains gofmt-clean, including the edge case where marker
// removal leaves no code on the line (the line becomes empty without trailing
// spaces rather than retaining indentation).
func TestProcessMarkers_GoFileGofmtClean(t *testing.T) {
	src := strings.Join([]string{
		"package sample",
		"",
		"func f() {",
		"	kafkaMode := true // tplater:if brokers=kafka",
		"	// tplater:if brokers=kafka",
		"	_ = kafkaMode",
		"}",
		"",
	}, "\n")

	out, err := processMarkers("sample.go", []byte(src), markerValues())
	if err != nil {
		t.Fatalf("processMarkers() = %v", err)
	}

	for i, line := range strings.Split(string(out), "\n") {
		if strings.TrimRight(line, " \t") != line {
			t.Errorf("line %d has trailing whitespace: %q", i+1, line)
		}
	}

	formatted, err := format.Source(out)
	if err != nil {
		t.Fatalf("go/format.Source: %v (input:\n%s)", err, out)
	}
	if string(formatted) != string(out) {
		t.Errorf("output is not gofmt-clean:\ngot:\n%s\nformatted:\n%s", out, formatted)
	}
}

// TestRenderSingleBasicMarkers renders the single-basic fixture (the  implementation
// added markers to files/modes.txt.tmpl) and checks that markers are removed
// according to conditions under different settings without breaking existing
// fixture engine tests (TestRenderSingleBasicDefaults and others in engine_test.go).
func TestRenderSingleBasicMarkers(t *testing.T) {
	t.Run("defaults: database=none, brokers=[]", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "out")
		renderSingleBasic(t, dir, settings.Values{})
		modes := readFileString(t, filepath.Join(dir, "modes.txt"))

		if strings.Contains(modes, "tplater:") {
			t.Errorf("modes.txt still contains a tplater: marker:\n%s", modes)
		}
		if strings.Contains(modes, "kafka mode") {
			t.Errorf("kafka mode line should be cut (brokers empty):\n%s", modes)
		}
		if strings.Contains(modes, "postgres block content") {
			t.Errorf("postgres block should be cut (database=none):\n%s", modes)
		}
		if !strings.Contains(modes, "no-migrations notice") {
			t.Errorf("inverted marker line should be kept when migrations=false:\n%s", modes)
		}
	})

	t.Run("postgres+kafka+migrations", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "out")
		renderSingleBasic(t, dir, settings.Values{
			"database":   "postgres",
			"migrations": true,
			"brokers":    []string{"kafka"},
		})
		modes := readFileString(t, filepath.Join(dir, "modes.txt"))

		if strings.Contains(modes, "tplater:") {
			t.Errorf("modes.txt still contains a tplater: marker:\n%s", modes)
		}
		if !strings.Contains(modes, "kafka mode") {
			t.Errorf("kafka mode line should be kept (brokers has kafka):\n%s", modes)
		}
		if !strings.Contains(modes, "postgres block content") {
			t.Errorf("postgres block should be kept (database=postgres):\n%s", modes)
		}
		if strings.Contains(modes, "no-migrations notice") {
			t.Errorf("inverted marker line should be cut when migrations=true:\n%s", modes)
		}
	})
}

// TestRenderSingleBasicMarkersDeterministic checks that adding markers to the
// fixture does not break byte-deterministic rendering or baseline stability
// (the  requirement: “baseline is computed from final content; nothing should
// change”).
func TestRenderSingleBasicMarkersDeterministic(t *testing.T) {
	values := settings.Values{"database": "postgres", "migrations": true, "brokers": []string{"kafka", "rabbitmq"}}
	res1 := renderSingleBasic(t, filepath.Join(t.TempDir(), "a"), values)
	res2 := renderSingleBasic(t, filepath.Join(t.TempDir(), "b"), values)

	if res1.Baseline.Files["modes.txt"] != res2.Baseline.Files["modes.txt"] {
		t.Errorf("modes.txt baseline hash not stable: %q vs %q", res1.Baseline.Files["modes.txt"], res2.Baseline.Files["modes.txt"])
	}
}

func TestProcessMarkersManagedGoConditionalProjection(t *testing.T) {
	block := "// tplater:managed-begin id=body provider=root\nfunc f(){ }\n// tplater:managed-end id=body\n"
	input := "package fixture\n" + block
	output, err := processMarkers("main.go", []byte(input), markerValues())
	if err != nil || string(output) != input {
		t.Fatalf("literal managed bytes changed: %v", err)
	}
	for _, tc := range []struct{ condition, want string }{
		{"database=postgres", input}, {"database=mysql", "package fixture\n"},
	} {
		conditioned := "package fixture\n// tplater:begin " + tc.condition + "\n" + block + "// tplater:end\n"
		output, err := processMarkers("main.go", []byte(conditioned), markerValues())
		if err != nil || string(output) != tc.want {
			t.Fatalf("conditional managed projection: %v: %q", err, output)
		}
	}
	// The existing ordinary conditional projection keeps its exact byte domain.
	ordinary := "package fixture\nvar n = 1 // tplater:if database=postgres\n"
	output, err = processMarkers("main.go", []byte(ordinary), markerValues())
	if err != nil || string(output) != "package fixture\nvar n = 1\n" {
		t.Fatalf("ordinary projection changed: %v: %q", err, output)
	}
}

func TestProcessMarkersManagedGoRefusals(t *testing.T) {
	valid := "package fixture\n// tplater:managed-begin id=body provider=root\nfunc f(){ }\n// tplater:managed-end id=body\n"
	cases := map[string]string{
		"syntax":           strings.Replace(valid, "func f(){ }", "func f(", 1),
		"string":           "package fixture\nvar text = `// tplater:managed-begin id=body provider=root\nx\n// tplater:managed-end id=body`\n",
		"unpaired":         strings.Replace(valid, "// tplater:managed-end id=body\n", "", 1),
		"mismatched":       strings.Replace(valid, "managed-end id=body", "managed-end id=other", 1),
		"duplicate":        valid + "// tplater:managed-begin id=body provider=root\nfunc g(){}\n// tplater:managed-end id=body\n",
		"nested":           strings.Replace(valid, "func f(){ }", "// tplater:managed-begin id=inner provider=root\nfunc f(){}\n// tplater:managed-end id=inner", 1),
		"malformed":        strings.Replace(valid, "provider=root", "provider=", 1),
		"unknown-keyword":  strings.Replace(valid, "managed-begin", "managed-beginn", 1),
		"unknown-trailing": strings.Replace(valid, "provider=root", "provider=root tplater:iff database=postgres", 1),
		"unknown-body":     strings.Replace(valid, "func f(){ }", "var text = `tplater:iff database=postgres`", 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if output, err := processMarkers("main.go", []byte(input), markerValues()); err == nil || output != nil {
				t.Fatal("invalid managed source accepted")
			}
		})
	}
	for _, path := range []string{"main.rs", "main.txt", "main.go.tmpl"} {
		if _, err := processMarkers(path, []byte(valid), markerValues()); err == nil {
			t.Fatal("non-Go managed output accepted")
		}
	}
}
