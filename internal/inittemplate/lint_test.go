package inittemplate

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const singleBasicFixture = "../../testdata/fixtures/single-basic"

func TestLint_SingleBasicFixtureGreen(t *testing.T) {
	res, err := Lint(LintOptions{Path: singleBasicFixture, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if res.Failed {
		t.Fatalf("single-basic must be green:\n%s", failDetails(res))
	}
	// Expect corner combos from two groups (select database + multiselect brokers)
	// plus defaults/all-on/max.
	combos := map[string]bool{}
	for _, r := range res.Rows {
		combos[r.Combo] = true
	}
	for _, want := range []string{"defaults", "database=postgres", "brokers=kafka", "all-on", "max"} {
		if !combos[want] {
			t.Errorf("expected combo %q in the results", want)
		}
	}
}

func TestLint_ComboFilter(t *testing.T) {
	res, err := Lint(LintOptions{Path: singleBasicFixture, ComboName: "database=postgres", Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	// validate row plus exactly one combo row.
	comboRows := 0
	for _, r := range res.Rows {
		if r.Combo == "database=postgres" {
			comboRows++
		}
		if r.Combo != "validate" && r.Combo != "database=postgres" {
			t.Errorf("filter let through an extra combo %q", r.Combo)
		}
	}
	if comboRows != 1 {
		t.Errorf("expected one database=postgres row, got %d", comboRows)
	}
}

func TestLint_UnknownComboErrors(t *testing.T) {
	res, err := Lint(LintOptions{Path: singleBasicFixture, ComboName: "no-such-combo", Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !res.Failed {
		t.Fatal("an unknown combo must fail")
	}
}

// TestLint_BrokenConditionRed copies the fixture and corrupts a files condition
// (conditional segment referencing a nonexistent group); lint must fail clearly
// (the engine catches the broken condition during rendering).
func TestLint_BrokenConditionRed(t *testing.T) {
	broken := copyTree(t, singleBasicFixture)
	// __if_ghost__ references nonexistent group ghost.
	dir := filepath.Join(broken, "files", "__if_ghost__")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("boom\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Lint(LintOptions{Path: broken, Out: io.Discard})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	if !res.Failed {
		t.Fatal("a broken files condition must fail")
	}
	found := false
	for _, r := range res.Rows {
		if !r.OK && strings.Contains(r.Detail, "ghost") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a message about unknown group ghost; rows: %s", failDetails(res))
	}
}

// copyTree copies src into a new temporary directory and returns its path.
func copyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	if err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	return dst
}
