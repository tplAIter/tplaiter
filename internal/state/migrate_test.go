package state

import "testing"

func TestCheckAndMigrate_SameVersionIsNoop(t *testing.T) {
	data := []byte("version: 1\nfoo: bar\n")
	got, err := checkAndMigrate(kindConfig, data, 1, 1)
	if err != nil {
		t.Fatalf("checkAndMigrate() error = %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("checkAndMigrate() same-version mutated data: got %q, want %q", got, data)
	}
}

func TestCheckAndMigrate_NewerThanCurrentErrors(t *testing.T) {
	_, err := checkAndMigrate(kindConfig, []byte("version: 2\n"), 2, 1)
	if err == nil {
		t.Fatal("checkAndMigrate() version(2) > current(1) = nil error, want error")
	}
}

func TestCheckAndMigrate_OlderWithoutRegisteredMigrationErrors(t *testing.T) {
	_, err := checkAndMigrate(kindConfig, []byte("version: 0\n"), 0, 1)
	if err == nil {
		t.Fatal("checkAndMigrate() version(0) < current(1) without registered migration = nil error, want error")
	}
}

func TestCheckAndMigrate_AppliesRegisteredMigrationChain(t *testing.T) {
	const testKind fileKind = "test-kind"
	// The registry is a package-level var; register and clean up after ourselves
	// so the change does not leak into other package tests.
	migrations[testKind] = map[int]migrationFunc{
		0: func(data []byte) ([]byte, error) { return append(data, []byte("-migrated-to-1")...), nil },
		1: func(data []byte) ([]byte, error) { return append(data, []byte("-migrated-to-2")...), nil },
	}
	defer delete(migrations, testKind)

	got, err := checkAndMigrate(testKind, []byte("version: 0"), 0, 2)
	if err != nil {
		t.Fatalf("checkAndMigrate() error = %v", err)
	}
	want := "version: 0-migrated-to-1-migrated-to-2"
	if string(got) != want {
		t.Errorf("checkAndMigrate() = %q, want %q", got, want)
	}
}
