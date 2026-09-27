package update

import (
	"strings"
	"testing"
)

func TestDiff3NonOverlapping(t *testing.T) {
	base := []byte("a\nb\nc\n")
	ours := []byte("A\nb\nc\n")   // изменена первая строка
	theirs := []byte("a\nb\nC\n") // изменена последняя строка
	got, conflict := merge3(base, ours, theirs)
	if conflict {
		t.Fatalf("unexpected conflict: %q", got)
	}
	if string(got) != "A\nb\nC\n" {
		t.Errorf("merge = %q, want %q", got, "A\nb\nC\n")
	}
}

func TestDiff3IdenticalEdit(t *testing.T) {
	base := []byte("a\nb\nc\n")
	edit := []byte("a\nZ\nc\n")
	got, conflict := merge3(base, edit, edit)
	if conflict {
		t.Fatalf("identical edits must not conflict: %q", got)
	}
	if string(got) != "a\nZ\nc\n" {
		t.Errorf("merge = %q", got)
	}
}

func TestDiff3OnlyOneSideChanges(t *testing.T) {
	base := []byte("a\nb\nc\n")
	ours := []byte("a\nb\nc\n")   // без изменений
	theirs := []byte("a\nX\nc\n") // изменил только шаблон
	got, conflict := merge3(base, ours, theirs)
	if conflict || string(got) != "a\nX\nc\n" {
		t.Errorf("expected theirs taken: got=%q conflict=%v", got, conflict)
	}
}

func TestDiff3OverlappingConflict(t *testing.T) {
	base := []byte("a\nb\nc\n")
	ours := []byte("a\nX\nc\n")
	theirs := []byte("a\nY\nc\n")
	got, conflict := merge3(base, ours, theirs)
	if !conflict {
		t.Fatalf("expected conflict, got %q", got)
	}
	s := string(got)
	for _, marker := range []string{markerOurs, "X", markerSeparator, "Y", markerTheirs} {
		if !strings.Contains(s, marker) {
			t.Errorf("conflict output missing %q:\n%s", marker, s)
		}
	}
	// Стабильные строки сохранены.
	if !strings.HasPrefix(s, "a\n") || !strings.HasSuffix(s, "c\n") {
		t.Errorf("stable lines lost:\n%s", s)
	}
}

func TestDiff3EmptyBaseNewFile(t *testing.T) {
	got, conflict := merge3(nil, []byte("local\n"), []byte("upstream\n"))
	if !conflict {
		t.Fatalf("differing new file must conflict: %q", got)
	}
	if !strings.Contains(string(got), "local") || !strings.Contains(string(got), "upstream") {
		t.Errorf("both sides must appear:\n%s", got)
	}
}

func TestDiff3EmptyInputs(t *testing.T) {
	got, conflict := merge3(nil, nil, nil)
	if conflict || len(got) != 0 {
		t.Errorf("empty merge = %q conflict=%v", got, conflict)
	}
}

func TestDiff3NoTrailingNewline(t *testing.T) {
	base := []byte("a\nb")
	ours := []byte("a\nB") // без финального \n
	theirs := []byte("a\nb")
	got, conflict := merge3(base, ours, theirs)
	if conflict {
		t.Fatalf("unexpected conflict: %q", got)
	}
	if string(got) != "a\nB" {
		t.Errorf("merge = %q, want %q (trailing newline must be preserved as-is)", got, "a\nB")
	}
}

func TestSplitJoinRoundTrip(t *testing.T) {
	for _, in := range []string{"", "a", "a\n", "a\nb", "a\nb\n", "\n", "\n\n"} {
		if got := string(joinLines(splitLines([]byte(in)))); got != in {
			t.Errorf("round-trip %q = %q", in, got)
		}
	}
}

func TestDiff3InsertionBothSides(t *testing.T) {
	// ours вставляет строку в начале, theirs — в конце: непересекающиеся.
	base := []byte("mid\n")
	ours := []byte("top\nmid\n")
	theirs := []byte("mid\nbottom\n")
	got, conflict := merge3(base, ours, theirs)
	if conflict {
		t.Fatalf("independent insertions must merge: %q", got)
	}
	if string(got) != "top\nmid\nbottom\n" {
		t.Errorf("merge = %q", got)
	}
}
