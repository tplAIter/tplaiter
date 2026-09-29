package migrations

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestLatestBranchLockIsUnversionedNotAnError pins the fix for a moving
// selector: an @latest lock on a branch passes "main" or "latest" as a
// version. Planning must not fail on it; it reports an unversioned plan that
// selects nothing and keeps the ledger bytes.
func TestLatestBranchLockIsUnversionedNotAnError(t *testing.T) {
	ledger := []byte("{\"version\":1,\"applied\":[]}\n")
	for _, tc := range []struct{ current, target string }{
		{"v1.0.0", "latest"}, {"1.0.0", "main"}, {"main", "v2.0.0"}, {"", "v2.0.0"},
	} {
		plan, err := Build(testMigrations(), Options{CurrentVersion: tc.current, TargetVersion: tc.target, LedgerBytes: ledger})
		if err != nil {
			t.Fatalf("%s -> %s: %v", tc.current, tc.target, err)
		}
		if !plan.Unversioned || plan.Reason == "" || len(plan.Before)+len(plan.After) != 0 {
			t.Fatalf("%s -> %s: plan=%+v", tc.current, tc.target, plan)
		}
		if !bytes.Equal(plan.Ledger.Before, ledger) || !bytes.Equal(plan.Ledger.After, ledger) {
			t.Fatalf("unversioned plan changed the ledger: %+v", plan.Ledger)
		}
	}
	// Integrity is still enforced for an unversioned project.
	if _, err := Build(testMigrations(), Options{CurrentVersion: "main", TargetVersion: "main", LedgerBytes: []byte(`{"version":1}`)}); err == nil {
		t.Fatal("unversioned plan accepted a malformed ledger")
	}
}

func TestTagRefSelectorsAreVersions(t *testing.T) {
	plan, err := Build(testMigrations(), Options{CurrentVersion: "refs/tags/v1.5.0", TargetVersion: "refs/tags/v3.0.0", Authorize: func([]PlannedMigration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Unversioned || len(plan.Before) != 2 || len(plan.After) != 1 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestAuthorizerSeesOnlyExecutableMigrations(t *testing.T) {
	migrations := []Migration{
		{ID: "rename", From: "1.0.0", To: "2.0.0", Phase: "before", Settings: MigrationSettings{Rename: map[string]string{"a": "b"}}},
		{ID: "script", From: "1.0.0", To: "2.0.0", Phase: "after", Steps: []MigrationStep{{Run: "./migrate.sh"}}},
	}
	settingsOnly, err := Build(migrations[:1], Options{CurrentVersion: "1.0.0", TargetVersion: "2.0.0"})
	if err != nil || len(settingsOnly.Before) != 1 {
		t.Fatalf("settings-only migration needs no execution authority: plan=%+v err=%v", settingsOnly, err)
	}
	var seen []string
	if _, err := Build(migrations, Options{CurrentVersion: "1.0.0", TargetVersion: "2.0.0", Authorize: func(ms []PlannedMigration) error {
		for _, m := range ms {
			seen = append(seen, m.ID)
		}
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "script" {
		t.Fatalf("authorizer saw %v", seen)
	}
	denied := errors.New("permit refused")
	if _, err := Build(migrations, Options{CurrentVersion: "1.0.0", TargetVersion: "2.0.0", Authorize: func([]PlannedMigration) error { return denied }}); !errors.Is(err, ErrExecutionUnauthorized) || !errors.Is(err, denied) {
		t.Fatalf("denial error=%v", err)
	}
}

func TestEmittedLedgerMatchesSchema(t *testing.T) {
	plan, err := Build(testMigrations(), trustedOptions("1.0.0", "3.0.0", nil))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "state-ledger-migrations.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(plan.Ledger.After))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("emitted ledger rejected: %v\n%s", err, plan.Ledger.After)
	}
	if LedgerRelPath != ".tplaiter/migrations.json" {
		t.Fatalf("ledger path=%s", LedgerRelPath)
	}
}
