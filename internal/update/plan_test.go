package update

import (
	"os"
	"path/filepath"
	"testing"
)

// writeWork creates a work-tree file.
func writeWork(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// findAction finds an action by path.
func findAction(t *testing.T, p *Plan, rel string) Action {
	t.Helper()
	for _, a := range p.Actions {
		if a.Path == rel {
			return a
		}
	}
	t.Fatalf("no action for %s (actions: %+v)", rel, p.Actions)
	return Action{}
}

func TestComputeUnmodifiedUpdated(t *testing.T) {
	// (a) work == baseline, template changed the file -> overwrite target.
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "v1\n")
	base := map[string][]byte{"a.txt": []byte("v1\n")}
	target := map[string][]byte{"a.txt": []byte("v2\n")}
	baseline := map[string]string{"a.txt": sha256Hex([]byte("v1\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "a.txt")
	if a.Op != OpWrite || string(a.Content) != "v2\n" || a.Conflict {
		t.Errorf("rule (a): got %+v", a)
	}
}

func TestComputeTemplateUnchangedKeepsUserEdit(t *testing.T) {
	// (b) base == target (template unchanged), work user-edited -> keep.
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "user-edit\n")
	base := map[string][]byte{"a.txt": []byte("v1\n")}
	target := map[string][]byte{"a.txt": []byte("v1\n")}
	baseline := map[string]string{"a.txt": sha256Hex([]byte("v1\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "a.txt")
	if a.Op != OpKeep {
		t.Errorf("rule (b): expected keep, got %+v", a)
	}
}

func TestComputeThreeWayMergeClean(t *testing.T) {
	// (c) all three differ, non-overlapping edits -> clean merge.
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "USER\nb\nc\n") // user changed line 1
	base := map[string][]byte{"a.txt": []byte("a\nb\nc\n")}
	target := map[string][]byte{"a.txt": []byte("a\nb\nTPL\n")} // template changed line 3
	baseline := map[string]string{"a.txt": sha256Hex([]byte("a\nb\nc\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "a.txt")
	if a.Op != OpWrite || a.Conflict || string(a.Content) != "USER\nb\nTPL\n" {
		t.Errorf("rule (c) clean merge: got op=%v conflict=%v content=%q", a.Op, a.Conflict, a.Content)
	}
}

func TestComputeThreeWayConflict(t *testing.T) {
	// (c) overlapping edits -> conflict.
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "a\nUSER\nc\n")
	base := map[string][]byte{"a.txt": []byte("a\nb\nc\n")}
	target := map[string][]byte{"a.txt": []byte("a\nTPL\nc\n")}
	baseline := map[string]string{"a.txt": sha256Hex([]byte("a\nb\nc\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "a.txt")
	if a.Op != OpWrite || !a.Conflict {
		t.Errorf("rule (c) conflict: got %+v", a)
	}
	if got := p.Conflicts(); len(got) != 1 || got[0] != "a.txt" {
		t.Errorf("Conflicts() = %v", got)
	}
}

func TestComputeNewFileCreate(t *testing.T) {
	// (d) file exists only in target, work absent -> create.
	dir := t.TempDir()
	base := map[string][]byte{}
	target := map[string][]byte{"new.txt": []byte("hello\n")}

	p, err := Compute(base, target, map[string]string{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "new.txt")
	if a.Op != OpWrite || string(a.Content) != "hello\n" || a.Conflict {
		t.Errorf("rule (d) create: got %+v", a)
	}
}

func TestComputeNewFileConflict(t *testing.T) {
	// (d) target file exists, work exists and differs -> conflict.
	dir := t.TempDir()
	writeWork(t, dir, "new.txt", "local\n")
	base := map[string][]byte{}
	target := map[string][]byte{"new.txt": []byte("upstream\n")}

	p, err := Compute(base, target, map[string]string{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "new.txt")
	if a.Op != OpWrite || !a.Conflict {
		t.Errorf("rule (d) conflict: got %+v", a)
	}
}

func TestComputeRemovedCleanDeletes(t *testing.T) {
	// (e) file deleted in target, work == baseline -> delete.
	dir := t.TempDir()
	writeWork(t, dir, "gone.txt", "v1\n")
	base := map[string][]byte{"gone.txt": []byte("v1\n")}
	target := map[string][]byte{}
	baseline := map[string]string{"gone.txt": sha256Hex([]byte("v1\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "gone.txt")
	if a.Op != OpDelete {
		t.Errorf("rule (e) delete: got %+v", a)
	}
}

func TestComputeRemovedModifiedKept(t *testing.T) {
	// (e) file deleted in target, work edited -> keep + warning.
	dir := t.TempDir()
	writeWork(t, dir, "gone.txt", "user-changed\n")
	base := map[string][]byte{"gone.txt": []byte("v1\n")}
	target := map[string][]byte{}
	baseline := map[string]string{"gone.txt": sha256Hex([]byte("v1\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	a := findAction(t, p, "gone.txt")
	if a.Op != OpKeep {
		t.Errorf("rule (e) keep-modified: got %+v", a)
	}
	if len(p.Warnings) == 0 {
		t.Errorf("expected warning for kept-modified removed file")
	}
}

func TestComputeNoOpWhenIdentical(t *testing.T) {
	// base==target, work==baseline -> keep unchanged (repeat update).
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "v1\n")
	base := map[string][]byte{"a.txt": []byte("v1\n")}
	target := map[string][]byte{"a.txt": []byte("v1\n")}
	baseline := map[string]string{"a.txt": sha256Hex([]byte("v1\n"))}

	p, err := Compute(base, target, baseline, dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.HasChanges() {
		t.Errorf("expected no changes, got %+v", p.Actions)
	}
}
