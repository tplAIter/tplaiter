package migrations

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testMigrations() []Migration {
	return []Migration{
		{
			ID: "prepare-v2", From: "1.0.0", To: "2.0.0", Phase: "before",
			Steps: []MigrationStep{{Run: "./scripts/prepare-v2.sh"}},
		},
		{
			ID: "finish-v2", From: "1.0.0", To: "2.0.0", Phase: "after",
			Steps: []MigrationStep{{Ansible: "playbooks/finish-v2.yaml", Optional: true}},
		},
		{
			ID: "prepare-v3", From: "2.0.0", To: "3.0.0", Phase: "before",
			Steps: []MigrationStep{{Run: "./scripts/prepare-v3.sh"}},
		},
	}
}

func trustedOptions(current, target string, ledger []byte) Options {
	return Options{
		CurrentVersion: current,
		TargetVersion:  target,
		LedgerBytes:    ledger,
		Authorize:      func([]PlannedMigration) error { return nil },
	}
}

func TestBuildSelectsSemverBoundariesDeterministically(t *testing.T) {
	migrations := testMigrations()
	plan, err := Build(migrations, trustedOptions("1.5.0", "3.0.0", nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := migrationIDs(plan.Before); strings.Join(got, ",") != "prepare-v2,prepare-v3" {
		t.Fatalf("before IDs = %v", got)
	}
	if got := migrationIDs(plan.After); strings.Join(got, ",") != "finish-v2" {
		t.Fatalf("after IDs = %v", got)
	}
	if plan.Ledger.Path != LedgerRelPath || plan.Ledger.Before != nil {
		t.Fatalf("unexpected ledger mutation: %#v", plan.Ledger)
	}
	var ledger Ledger
	if err := json.Unmarshal(plan.Ledger.After, &ledger); err != nil {
		t.Fatalf("ledger JSON: %v", err)
	}
	if ledger.Version != LedgerVersion || len(ledger.Applied) != 3 {
		t.Fatalf("ledger = %#v", ledger)
	}
	for i, entry := range ledger.Applied {
		if entry.Order != i || entry.ID != migrations[i].ID || len(entry.Digest) != 64 {
			t.Fatalf("ledger entry %d = %#v", i, entry)
		}
	}

	again, err := Build(migrations, trustedOptions("1.5.0", "3.0.0", nil))
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if !bytes.Equal(plan.Ledger.After, again.Ledger.After) {
		t.Fatalf("ledger bytes are not deterministic:\n%s\n%s", plan.Ledger.After, again.Ledger.After)
	}
}

func TestBuildReplayIsNoOpAndPreservesLedgerBytes(t *testing.T) {
	migrations := testMigrations()
	initial, err := Build(migrations, trustedOptions("1.0.0", "3.0.0", nil))
	if err != nil {
		t.Fatalf("initial Build: %v", err)
	}
	replay, err := Build(migrations, trustedOptions("1.0.0", "3.0.0", initial.Ledger.After))
	if err != nil {
		t.Fatalf("replay Build: %v", err)
	}
	if len(replay.Before) != 0 || len(replay.After) != 0 {
		t.Fatalf("replay planned applied migrations: %#v", replay)
	}
	if !bytes.Equal(replay.Ledger.Before, initial.Ledger.After) || !bytes.Equal(replay.Ledger.After, initial.Ledger.After) {
		t.Fatalf("replay changed ledger bytes:\nbefore=%s\nafter=%s", replay.Ledger.Before, replay.Ledger.After)
	}
}

func TestBuildUsesOpenClosedSemverInterval(t *testing.T) {
	plan, err := Build(testMigrations(), trustedOptions("2.0.0", "3.1.0", nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := migrationIDs(plan.Before); strings.Join(got, ",") != "prepare-v3" {
		t.Fatalf("before IDs = %v; boundary at current version must be excluded", got)
	}
	if len(plan.After) != 0 {
		t.Fatalf("after = %v", migrationIDs(plan.After))
	}
}

func TestBuildRejectsDowngradeAndSameVersion(t *testing.T) {
	for _, target := range []string{"2.0.0", "1.9.9"} {
		t.Run(target, func(t *testing.T) {
			_, err := Build(testMigrations(), trustedOptions("2.0.0", target, nil))
			if err == nil || !strings.Contains(err.Error(), "target version must be greater") {
				t.Fatalf("want downgrade rejection, got %v", err)
			}
		})
	}
}

func TestBuildAllowsEqualManifestBoundaries(t *testing.T) {
	plan, err := Build(testMigrations()[:2], trustedOptions("1.0.0", "2.0.0", nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Before) != 1 || len(plan.After) != 1 {
		t.Fatalf("equal boundary phases not planned: %#v", plan)
	}
}

func TestBuildNoSelectionPreservesAbsentLedgerAndNeedsNoTrust(t *testing.T) {
	plan, err := Build(testMigrations()[:2], Options{
		CurrentVersion: "2.0.0",
		TargetVersion:  "3.0.0",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(plan.Before) != 0 || len(plan.After) != 0 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if plan.Ledger.Before != nil || plan.Ledger.After != nil {
		t.Fatalf("no-op created a ledger mutation: %#v", plan.Ledger)
	}
}

func TestBuildRejectsChangedReorderedAndMissingAppliedMigration(t *testing.T) {
	migrations := testMigrations()
	initial, err := Build(migrations, trustedOptions("1.0.0", "3.0.0", nil))
	if err != nil {
		t.Fatalf("initial Build: %v", err)
	}
	ledger := initial.Ledger.After

	changed := testMigrations()
	changed[0].Steps[0].Run = "./scripts/changed.sh"
	assertBuildErrorContains(t, changed, ledger, "changed or reordered")

	reordered := testMigrations()
	reordered[0], reordered[1] = reordered[1], reordered[0]
	assertBuildErrorContains(t, reordered, ledger, "changed or reordered")

	missing := testMigrations()[1:]
	assertBuildErrorContains(t, missing, ledger, "changed or reordered")
}

func TestBuildRejectsDuplicateMigrationAndInvalidLedger(t *testing.T) {
	duplicate := testMigrations()
	duplicate = append(duplicate, duplicate[0])
	assertBuildErrorContains(t, duplicate, nil, "duplicate migration id")

	validDigest := strings.Repeat("a", 64)
	tests := []struct {
		name   string
		ledger string
		want   string
	}{
		{"duplicate id", `{"version":1,"applied":[{"id":"a","digest":"` + validDigest + `","order":0},{"id":"a","digest":"` + validDigest + `","order":1}]}`, "duplicate ledger id"},
		{"reordered entries", `{"version":1,"applied":[{"id":"a","digest":"` + validDigest + `","order":1},{"id":"b","digest":"` + validDigest + `","order":0}]}`, "strictly increasing"},
		{"bad digest", `{"version":1,"applied":[{"id":"a","digest":"nope","order":0}]}`, "invalid digest"},
		{"missing applied", `{"version":1}`, "applied must be present and non-null"},
		{"null applied", `{"version":1,"applied":null}`, "applied must be present and non-null"},
		{"duplicate top-level key", `{"version":1,"applied":[],"applied":[]}`, `duplicate JSON key "applied"`},
		{"aliased version key", `{"version":1,"Version":1,"applied":[]}`, `duplicate JSON key "Version" aliases "version"`},
		{"aliased applied key", `{"version":1,"applied":[],"Applied":[]}`, `duplicate JSON key "Applied" aliases "applied"`},
		{"duplicate entry key", `{"version":1,"applied":[{"id":"a","id":"b","digest":"` + validDigest + `","order":0}]}`, `duplicate JSON key "id"`},
		{"aliased entry key", `{"version":1,"applied":[{"id":"a","ID":"b","digest":"` + validDigest + `","order":0}]}`, `duplicate JSON key "ID" aliases "id"`},
		{"unknown field", `{"version":1,"applied":[],"extra":true}`, "unknown field"},
		{"trailing value", `{"version":1,"applied":[]} {}`, "trailing JSON value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build(testMigrations(), trustedOptions("1.0.0", "3.0.0", []byte(tc.ledger)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestBuildRejectsDecreasingManifestBoundaries(t *testing.T) {
	migrations := testMigrations()
	migrations[0].To = "3.0.0"
	migrations[1].To = "2.0.0"
	_, err := Build(migrations, trustedOptions("1.0.0", "3.0.0", nil))
	if err == nil || !strings.Contains(err.Error(), "lower than previous boundary") {
		t.Fatalf("want decreasing boundary error, got %v", err)
	}
}

func TestBuildRejectsNonStrictMigrationSemver(t *testing.T) {
	migrations := testMigrations()
	migrations[0].From = "01.0.0"
	_, err := Build(migrations, trustedOptions("1.0.0", "3.0.0", nil))
	if err == nil || !strings.Contains(err.Error(), "from") {
		t.Fatalf("want strict SemVer error, got %v", err)
	}
}

func TestMigrationDigestSensitiveToAllContractFields(t *testing.T) {
	base := testMigrations()[0]
	want, err := migrationDigest(base)
	if err != nil {
		t.Fatalf("base digest: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Migration)
	}{
		{"id", func(m *Migration) { m.ID = "other" }},
		{"from", func(m *Migration) { m.From = "0.9.0" }},
		{"to", func(m *Migration) { m.To = "2.1.0" }},
		{"phase", func(m *Migration) { m.Phase = "after" }},
		{"run", func(m *Migration) { m.Steps[0].Run = "./other.sh" }},
		{"ansible", func(m *Migration) { m.Steps[0] = MigrationStep{Ansible: "other.yaml"} }},
		{"optional", func(m *Migration) { m.Steps[0].Optional = true }},
		{"step order", func(m *Migration) {
			m.Steps = append(m.Steps, MigrationStep{Run: "./second.sh"})
			m.Steps[0], m.Steps[1] = m.Steps[1], m.Steps[0]
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.Steps = append([]MigrationStep(nil), base.Steps...)
			tc.edit(&candidate)
			got, err := migrationDigest(candidate)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if got == want {
				t.Fatalf("digest did not change for %s", tc.name)
			}
		})
	}
}

func TestBuildGoldenLedgerBytes(t *testing.T) {
	plan, err := Build(testMigrations()[:1], trustedOptions("1.0.0", "2.0.0", nil))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := "{\n" +
		"  \"version\": 1,\n" +
		"  \"applied\": [\n" +
		"    {\n" +
		"      \"id\": \"prepare-v2\",\n" +
		"      \"digest\": \"7cc4ab07eac5ce449ee297b62f2de6996b6a315f30d31b26added6f528396ddc\",\n" +
		"      \"order\": 0\n" +
		"    }\n" +
		"  ]\n" +
		"}\n"
	if string(plan.Ledger.After) != want {
		t.Fatalf("ledger golden mismatch:\nwant:\n%s\ngot:\n%s", want, plan.Ledger.After)
	}
}

func TestApplySettingsRenameDeleteIsDeterministic(t *testing.T) {
	plan := &Plan{Before: []PlannedMigration{{
		ID: "settings-v2", Order: 0,
		Settings: MigrationSettings{
			Rename: map[string]string{"old_b": "new_b", "old_a": "new_a"},
			Delete: []string{"removed"},
		},
	}}}
	input := map[string]any{"old_a": "a", "old_b": "b", "removed": true, "keep": 7}
	got, err := ApplySettings(plan, input)
	if err != nil {
		t.Fatalf("ApplySettings: %v", err)
	}
	want := map[string]any{"new_a": "a", "new_b": "b", "keep": 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings = %#v, want %#v", got, want)
	}
	if _, exists := input["old_a"]; !exists {
		t.Fatal("ApplySettings mutated caller input")
	}
}

func TestApplySettingsRejectsRenameOverwrite(t *testing.T) {
	plan := &Plan{Before: []PlannedMigration{{
		ID: "settings-v2", Order: 0,
		Settings: MigrationSettings{Rename: map[string]string{"old": "new"}},
	}}}
	_, err := ApplySettings(plan, map[string]any{"old": 1, "new": 2})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want overwrite rejection, got %v", err)
	}
}

func TestBuildUntrustedExecutableFailsWithoutMutation(t *testing.T) {
	ledger := []byte("{\"version\":1,\"applied\":[]}\n")
	original := append([]byte(nil), ledger...)
	plan, err := Build(testMigrations(), Options{
		CurrentVersion: "1.0.0",
		TargetVersion:  "2.0.0",
		LedgerBytes:    ledger,
	})
	if plan != nil {
		t.Fatalf("untrusted Build returned a journal-ready plan: %#v", plan)
	}
	if !errors.Is(err, ErrExecutionUnauthorized) {
		t.Fatalf("want ErrExecutionUnauthorized, got %v", err)
	}
	if !bytes.Equal(ledger, original) {
		t.Fatalf("input ledger mutated: %q", ledger)
	}
}

func TestBuildPreservesExactLedgerBeforeBytes(t *testing.T) {
	before := []byte("{\n  \"version\": 1,\n  \"applied\": []\n}\n")
	plan, err := Build(testMigrations(), trustedOptions("2.0.0", "3.0.0", before))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(plan.Ledger.Before, before) {
		t.Fatalf("before bytes changed: %q != %q", plan.Ledger.Before, before)
	}
	before[0] = '!'
	if plan.Ledger.Before[0] != '{' {
		t.Fatal("plan aliases caller-owned ledger bytes")
	}
}

func migrationIDs(plan []PlannedMigration) []string {
	ids := make([]string, len(plan))
	for i := range plan {
		ids[i] = plan[i].ID
	}
	return ids
}

func assertBuildErrorContains(t *testing.T, migrations []Migration, ledger []byte, want string) {
	t.Helper()
	_, err := Build(migrations, trustedOptions("1.0.0", "3.1.0", ledger))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want error containing %q, got %v", want, err)
	}
}
