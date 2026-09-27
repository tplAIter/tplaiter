package update

import (
	"os"
	"path/filepath"
	"testing"
)

// writeWork создаёт файл рабочего дерева.
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

// findAction ищет действие по пути.
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
	// (a) work == baseline, шаблон изменил файл → перезапись target.
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
	// (b) base == target (шаблон не менял), work изменён пользователем → keep.
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
	// (c) все три различны, непересекающиеся правки → merge без конфликта.
	dir := t.TempDir()
	writeWork(t, dir, "a.txt", "USER\nb\nc\n") // пользователь изменил строку 1
	base := map[string][]byte{"a.txt": []byte("a\nb\nc\n")}
	target := map[string][]byte{"a.txt": []byte("a\nb\nTPL\n")} // шаблон изменил строку 3
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
	// (c) пересекающиеся правки → конфликт.
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
	// (d) файл есть только в target, work отсутствует → create.
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
	// (d) файл в target, work существует и отличается → конфликт.
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
	// (e) файл удалён в target, work == baseline → delete.
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
	// (e) файл удалён в target, work изменён → keep + warning.
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
	// base==target, work==baseline → keep без изменений (повторный update).
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
