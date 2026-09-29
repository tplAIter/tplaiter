package stateledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/newtransaction"
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
	tx, err := newtransaction.Begin(home, target)
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
