package stateledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// stateLedgerSchemas are the schema files owned by the state ledger.
var stateLedgerSchemas = []string{
	"state-ledger-project.v2.schema.json",
	"state-ledger-migration-plan.v1.schema.json",
	"state-ledger-report.v1.schema.json",
	"state-ledger-new-transaction.v1.schema.json",
	"state-ledger-new-lock.v1.schema.json",
	"state-ledger-migrations.v1.schema.json",
	"ownership.v1.schema.json",
}

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	s, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

// validateWire validates raw JSON and then proves that the schema is closed:
// the same document with an unknown top-level field must fail.
func validateWire(t *testing.T, s *jsonschema.Schema, name string, raw []byte) {
	t.Helper()
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(instance); err != nil {
		t.Fatalf("%s rejected an emitted wire: %v\n%s", name, err, raw)
	}
	var open map[string]any
	if err := json.Unmarshal(raw, &open); err != nil {
		t.Fatal(err)
	}
	open["unexpected"] = true
	mutated, _ := json.Marshal(open)
	instance, err = jsonschema.UnmarshalJSON(bytes.NewReader(mutated))
	if err != nil {
		t.Fatal(err)
	}
	if s.Validate(instance) == nil {
		t.Fatalf("%s accepted an unknown field", name)
	}
}

func TestStateLedgerSchemasCompile(t *testing.T) {
	for _, name := range stateLedgerSchemas {
		compileSchema(t, name)
	}
}

func TestProjectIDSchemaAndRuntimeLexicalContract(t *testing.T) {
	plan, err := Plan(legacyProjectRoot(t), migrationOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	var marker ProjectV2
	if err := yaml.Unmarshal(plan.ProjectYAML, &marker); err != nil {
		t.Fatal(err)
	}
	schema := compileSchema(t, "state-ledger-project.v2.schema.json")
	cases := []struct {
		name, id string
		valid    bool
	}{
		{"uuid", marker.ID, true},
		{"native", "project-t5f", true},
		{"punctuation", "project.test:1", true},
		{"dot", ".", true},
		{"dotdot", "..", true},
		{"unicode", "项目-é", true},
		{"nonASCIIspace", "a\u00a0b", true},
		{"empty", "", false},
		{"space", "a b", false},
		{"slash", "a/b", false},
		{"backslash", "a\\b", false},
		{"nul", "a\x00b", false},
		{"cr", "a\rb", false},
		{"lf", "a\nb", false},
		{"trailingLF", "a\n", false},
		{"tab", "a\tb", false},
		{"invalidUTF8", string([]byte{0xff}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := marker
			p.ID = tc.id
			if got := validateV2(p) == nil; got != tc.valid {
				t.Fatalf("runtime accepted=%v want=%v", got, tc.valid)
			}
			// JSON represents Unicode strings; Marshal replaces invalid UTF-8.
			// Test the original invalid bytes at the runtime boundary above.
			if !utf8.ValidString(tc.id) {
				return
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if got := schema.Validate(value) == nil; got != tc.valid {
				t.Fatalf("schema accepted=%v want=%v", got, tc.valid)
			}
		})
	}
}

func TestLegacyProjectIDMigrationPreservesUUIDAndRefusesInvalidTokens(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		valid    bool
	}{
		{"lowerUUID", "123e4567-e89b-42d3-a456-426614174000", true},
		{"upperUUID", "123E4567-E89B-42D3-A456-426614174000", true},
		{"empty", "", false},
		{"space", "legacy project", false},
		{"slash", "legacy/project", false},
		{"backslash", "legacy\\project", false},
		{"nul", "legacy\x00project", false},
		{"cr", "legacy\rproject", false},
		{"lf", "legacy\nproject", false},
		{"tab", "legacy\tproject", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := legacyProjectRoot(t)
			path := filepath.Join(root, StateDir, "project.yaml")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var old legacyProject
			if err := yaml.Unmarshal(raw, &old); err != nil {
				t.Fatal(err)
			}
			old.ID = tc.id
			raw, err = yaml.Marshal(old)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			opts := migrationOptions(t)
			plan, err := Plan(root, opts)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid legacy ID admitted")
				}
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(raw, after) {
					t.Fatal("refused legacy marker changed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var p ProjectV2
			if err := yaml.Unmarshal(plan.ProjectYAML, &p); err != nil {
				t.Fatal(err)
			}
			if plan.ProjectID != tc.id || p.ID != tc.id {
				t.Fatal("migration regenerated ID")
			}
			wire, _ := json.Marshal(p)
			validateWire(t, compileSchema(t, "state-ledger-project.v2.schema.json"), "migrated project", wire)
			if _, err := ApplyPlan(root, opts, plan.PlanSHA256); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, plan.ProjectYAML) {
				t.Fatal("applied marker differs from exact migration plan")
			}
		})
	}
}

func TestEmittedLedgerWiresMatchSchemas(t *testing.T) {
	root := legacyProjectRoot(t)
	plan, err := Plan(root, migrationOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	planJSON, _ := json.Marshal(plan)
	validateWire(t, compileSchema(t, "state-ledger-migration-plan.v1.schema.json"), "plan", planJSON)

	var marker map[string]any
	if err := yaml.Unmarshal(plan.ProjectYAML, &marker); err != nil {
		t.Fatal(err)
	}
	markerJSON, _ := json.Marshal(marker)
	validateWire(t, compileSchema(t, "state-ledger-project.v2.schema.json"), "project", markerJSON)

	reportJSON, _ := json.Marshal(mustSealedReport(t))
	validateWire(t, compileSchema(t, "state-ledger-report.v1.schema.json"), "report", reportJSON)

	migrations, err := os.ReadFile(fixtureDir("project", StateDir, "migrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	validateWire(t, compileSchema(t, "state-ledger-migrations.v1.schema.json"), "migrations", migrations)

	ownership, err := os.ReadFile(fixtureDir("project", StateDir, "ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	validateWire(t, compileSchema(t, "ownership.v1.schema.json"), "ownership", ownership)

	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	tx, err := beginNewOwnerFixture(t, home, target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Abort() }()
	journal, err := os.ReadFile(filepath.Join(home, "transactions", "new", "tx-"+tx.ID(), "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	validateWire(t, compileSchema(t, "state-ledger-new-transaction.v1.schema.json"), "journal", journal)
	lock, err := os.ReadFile(filepath.Join(home, "transactions", "new.lock"))
	if err != nil {
		t.Fatal(err)
	}
	validateWire(t, compileSchema(t, "state-ledger-new-lock.v1.schema.json"), "new lock", lock)
}

func TestProjectSchemaRejectsNonStandardPointers(t *testing.T) {
	root := legacyProjectRoot(t)
	plan, err := Plan(root, migrationOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	var marker map[string]any
	if err := yaml.Unmarshal(plan.ProjectYAML, &marker); err != nil {
		t.Fatal(err)
	}
	marker["state"].(map[string]any)["rootLock"] = "../escape.json"
	raw, _ := json.Marshal(marker)
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if compileSchema(t, "state-ledger-project.v2.schema.json").Validate(instance) == nil {
		t.Fatal("schema accepted a non-standard state pointer")
	}
}
