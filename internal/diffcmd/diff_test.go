package diffcmd

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/migrations"
	"github.com/tplAIter/tplaiter/internal/stateledger"

	"github.com/tplAIter/tplaiter/internal/ownership"
)

const pair = "head\n// tplater:managed-begin id=one provider=source\na\n// tplater:managed-end id=one\ngap\n// tplater:managed-begin id=two provider=source\nb\n// tplater:managed-end id=two\ntail\n"

func TestIndependentSameFileBlocks(t *testing.T) {
	current := strings.ReplaceAll(strings.ReplaceAll(pair, "\na\n", "\nchanged a\n"), "\nb\n", "\nchanged b\n")
	changes, n, err := compare("a.go", []byte(pair), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: fs.FileMode(0o644), Data: []byte(current)})
	if err != nil || n != 2 || len(changes) != 2 || changes[0].BlockID != "one" || changes[1].BlockID != "two" {
		t.Fatalf("independent: %v %d %#v", err, n, changes)
	}
	for _, c := range changes {
		if c.Path != "a.go" || c.Action != "modify" || c.BeforeSHA256 == c.AfterSHA256 {
			t.Fatal(c)
		}
	}
}

func TestMalformedOrForeignBlocksRefused(t *testing.T) {
	for _, raw := range []string{strings.ReplaceAll(pair, "id=two", "id=one"), strings.Replace(pair, "provider=source", "provider=foreign", 1), strings.ReplaceAll(pair, "id=two", "id=extra"), strings.Replace(pair, "// tplater:managed-end id=one\n", "", 1)} {
		if _, _, err := compare("a.go", []byte(pair), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: 0o644, Data: []byte(raw)}); err == nil {
			t.Fatal("ambiguous topology accepted")
		}
	}
}

func TestOrdinaryAndSkeletonDrift(t *testing.T) {
	for _, tc := range []struct {
		expected, current string
		action            string
	}{{"base", "changed", "modify"}, {pair, strings.Replace(pair, "gap\n", "new gap\n", 1), "skeleton"}} {
		c, _, e := compare("a.txt", []byte(tc.expected), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: 0o644, Data: []byte(tc.current)})
		if e != nil || len(c) != 1 || c[0].Action != tc.action || c[0].BlockID != "" {
			t.Fatalf("%v %#v", e, c)
		}
	}
	c, _, e := compare("a.go", []byte(pair), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: 0o644, Data: []byte(pair)})
	if e != nil || len(c) != 0 {
		t.Fatalf("clean: %v %#v", e, c)
	}
}

func TestMarkerBudgetBeforeParsing(t *testing.T) {
	raw := []byte(strings.Repeat("tplater:managed-\n", 8193))
	_, _, err := compare("a.go", []byte(pair), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: 0o644, Data: raw})
	if !errors.Is(err, stateledger.ErrUnsafe) {
		t.Fatalf("unbounded marker input: %v", err)
	}
}

func TestOrderedGapBoundaries(t *testing.T) {
	current := strings.Replace(pair, "head\n", "head\ngap\n", 1)
	current = strings.Replace(current, "id=one\ngap\n", "id=one\n", 1)
	changes, count, err := compare("a.go", []byte(pair), ownership.State{Exists: true, Kind: ownership.KindFile, Mode: 0o644, Data: []byte(current)})
	if err != nil || count != 2 || len(changes) != 1 || changes[0].Action != "skeleton" || changes[0].BlockID != "" || changes[0].BeforeSHA256 == changes[0].AfterSHA256 {
		t.Fatalf("gap movement hidden: %v %d %#v", err, count, changes)
	}
}

func TestDiffSignedMigrationHistory(t *testing.T) {
	tpl := &manifest.Template{Metadata: manifest.TemplateMeta{Version: "2.0.0"}, Migrations: []migrations.Migration{{ID: "rename", From: "1.0.0", To: "2.0.0", Phase: "before", Settings: migrations.MigrationSettings{Rename: map[string]string{"old": "new"}}}}}
	plan, err := migrations.Build(tpl.Migrations, migrations.Options{CurrentVersion: "1.0.0", TargetVersion: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMigrationHistory(tpl, plan.Ledger.After); err != nil {
		t.Fatal(err)
	}
	tpl.Metadata.Version = "1.0.0"
	if err := validateMigrationHistory(tpl, plan.Ledger.After); err == nil || !strings.Contains(err.Error(), StateCode) {
		t.Fatalf("future history not typed diff state refusal: %v", err)
	}
	tpl.Metadata.Version = "2.0.0"
	tpl.Migrations = nil
	if validateMigrationHistory(tpl, plan.Ledger.After) == nil {
		t.Fatal("missing declaration accepted")
	}
}
