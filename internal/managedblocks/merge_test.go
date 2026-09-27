package managedblocks

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func managed(id, provider, body string) []byte {
	return []byte("// tplater:managed-begin id=" + id + " provider=" + provider + "\n" + body + "// tplater:managed-end id=" + id + "\n")
}

func managedEOL(id, provider, body, eol string) []byte {
	return []byte("// tplater:managed-begin id=" + id + " provider=" + provider + eol + body + "// tplater:managed-end id=" + id + eol)
}

func matrixBaseline(t *testing.T, base []byte) FileBaseline {
	t.Helper()
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b.Files["a.go"]
}

func assertExactTopologyFallback(t *testing.T, p FilePlan, ours []byte, baseline FileBaseline) {
	t.Helper()
	if !bytes.Equal(p.Candidate, ours) || len(p.Conflicts) != 1 || p.Conflicts[0].ID != "" || !equalBaseline(p.Baseline, baseline) || len(p.RenameAliases) != 0 {
		t.Fatalf("topology fallback candidate=%q conflicts=%#v baseline=%#v aliases=%#v", p.Candidate, p.Conflicts, p.Baseline, p.RenameAliases)
	}
}

func TestPlanFileGapMatrixG06G07G09G10G15G16G18G19G20G21G22(t *testing.T) {
	t.Run("G06 moved suppressed anchor", func(t *testing.T) {
		base := []byte("head\n" + string(managed("a", "root", "old\n")) + "tail\n")
		ours := []byte("head local\ntail\n")
		theirs := append(managed("a", "root", "new\n"), []byte("head\ntail\n")...)
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || !bytes.Equal(p.Candidate, ours) || len(p.Conflicts) != 0 || p.Baseline.Blocks["a"].State != StateLocalDeleted {
			t.Fatalf("G06=%q %#v %v", p.Candidate, p, err)
		}
	})
	t.Run("G07 rename before suppression", func(t *testing.T) {
		base := []byte("head\n" + string(managed("a", "root", "old\n")) + "tail\n")
		ours := []byte("head local\ntail\n")
		theirs := append(managed("n", "root", "new\n"), []byte("head\ntail\n")...)
		inputBaseline := matrixBaseline(t, base)
		original := inputBaseline.Blocks["a"]
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: inputBaseline, Renames: map[string]string{"n": "a"}})
		if err != nil || !bytes.Equal(p.Candidate, ours) || len(p.Conflicts) != 0 || p.Baseline.Blocks["n"].State != StateLocalDeleted || p.Baseline.Blocks["n"].Tombstone == nil || p.RenameAliases["a"] != "n" {
			t.Fatalf("G07=%q %#v %v", p.Candidate, p, err)
		}
		migrated := p.Baseline.Blocks["n"]
		if migrated.Provider != original.Provider || !reflect.DeepEqual(migrated.Source, original.Source) || migrated.BodySHA256 != original.BodySHA256 || migrated.Tombstone.Provider != original.Provider || !reflect.DeepEqual(migrated.Tombstone.Source, original.Source) || migrated.Tombstone.BodySHA256 != original.BodySHA256 {
			t.Fatalf("G07 identity changed: original=%#v migrated=%#v", original, migrated)
		}
	})
	t.Run("G09 consecutive deletions", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + "X\n" + string(managed("b", "root", "b\n")) + "Y\n" + string(managed("c", "root", "c\n")) + "Z\n")
		ours := []byte("H local\nX\nY\n" + string(managed("c", "root", "c\n")) + "Z\n")
		theirs := []byte("H\n" + string(managed("a", "root", "a2\n")) + "X\n" + string(managed("b", "root", "b2\n")) + "Y\n" + string(managed("c", "root", "c2\n")) + "Z\n")
		want := []byte("H local\nX\nY\n" + string(managed("c", "root", "c2\n")) + "Z\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, want) {
			t.Fatalf("G09=%q want=%q %#v %v", p.Candidate, want, p, err)
		}
		if strings.Count(string(p.Candidate), "X\n") != 1 || strings.Count(string(p.Candidate), "Y\n") != 1 {
			t.Fatal("G09 duplicated coalesced sentinels")
		}
	})
	t.Run("G10 nonconsecutive deletions", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + "X\n" + string(managed("b", "root", "b\n")) + "Y\n" + string(managed("c", "root", "c\n")) + "Z\n")
		ours := []byte("H local\nX\n" + string(managed("b", "root", "b\n")) + "Y\nZ\n")
		theirs := []byte("H\n" + string(managed("a", "root", "a2\n")) + "X\n" + string(managed("b", "root", "b2\n")) + "Y\nfooter\n")
		want := []byte("H local\nX\n" + string(managed("b", "root", "b2\n")) + "Y\nfooter\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, want) {
			t.Fatalf("G10=%q want=%q %#v %v", p.Candidate, want, p, err)
		}
	})
	t.Run("G15 clean upstream deletion", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + "X\n" + string(managed("b", "root", "b\n")) + "Z\n")
		ours := []byte("H local\n" + string(managed("a", "root", "a\n")) + "X\n" + string(managed("b", "root", "b\n")) + "Z\n")
		theirs := []byte("H\nX\n" + string(managed("b", "root", "b2\n")) + "Z\n")
		want := []byte("H local\nX\n" + string(managed("b", "root", "b2\n")) + "Z\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, want) {
			t.Fatalf("G15=%q want=%q %#v %v", p.Candidate, want, p, err)
		}
	})
	t.Run("G16 explicit drop never drops neighboring gap", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + "LOCAL\n" + string(managed("b", "root", "b\n")) + "Z\n")
		ours := []byte("H local\n" + string(managed("a", "root", "a\n")) + "LOCAL edit\n" + string(managed("b", "root", "b-local\n")) + "Z\n")
		theirs := []byte("H\n" + string(managed("a", "root", "a2\n")) + "LOCAL\nZ\n")
		before := matrixBaseline(t, base)
		inputBefore := cloneFileBaseline(before)
		resolutions := map[string]DeleteResolution{"b": DeleteDrop}
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: before, DeleteResolutions: resolutions})
		want := []byte("H local\n" + string(managed("a", "root", "a2\n")) + "LOCAL edit\nZ\n")
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, want) || !equalBaseline(before, inputBefore) || len(p.Baseline.Blocks) != 1 || p.Baseline.Blocks["b"].State != "" || p.Baseline.Blocks["a"].Body != "a2\n" {
			t.Fatalf("G16 candidate=%q want=%q conflicts=%#v baseline=%#v", p.Candidate, want, p.Conflicts, p.Baseline)
		}
		if !reflect.DeepEqual(resolutions, map[string]DeleteResolution{"b": DeleteDrop}) {
			t.Fatal("G16 setup map changed")
		}
	})
	t.Run("G18 missing versus present zero-byte gap", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + string(managed("b", "root", "b\n")) + "Z\n")
		ours := append([]byte(nil), base...)
		theirs := []byte("H\n" + string(managed("b", "root", "b2\n")) + "Z\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, theirs) {
			t.Fatalf("G18 zero-byte gap=%q %#v %v", p.Candidate, p, err)
		}
		base = []byte("H\n" + string(managed("a", "root", "a\n")) + "NONEMPTY\n" + string(managed("b", "root", "b\n")) + "Z\n")
		ours = []byte("H\n" + string(managed("a", "root", "a\n")) + string(managed("b", "root", "b\n")) + "Z\n")
		theirs = []byte("H\n" + string(managed("b", "root", "b2\n")) + string(managed("a", "root", "a2\n")) + "Z\n")
		baseline := matrixBaseline(t, base)
		p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: baseline})
		assertExactTopologyFallback(t, p, ours, baseline)
	})
	t.Run("G19 alias topology rollback", func(t *testing.T) {
		base := []byte("H\n" + string(managed("a", "root", "a\n")) + "X\n" + string(managed("b", "root", "b\n")) + "Z\n")
		ours := []byte("H\n" + string(managed("a", "root", "a\n")) + "X local\n" + string(managed("b", "root", "b\n")) + "Z\n")
		theirs := []byte("H\n" + string(managed("b", "root", "b2\n")) + string(managed("n", "root", "n\n")) + "Z\n")
		inputBaseline := matrixBaseline(t, base)
		inputRenames := map[string]string{"n": "a"}
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: inputBaseline, Renames: inputRenames})
		if err != nil {
			t.Fatal(err)
		}
		assertExactTopologyFallback(t, p, ours, inputBaseline)
		if !reflect.DeepEqual(inputRenames, map[string]string{"n": "a"}) {
			t.Fatal("G19 mutated renames")
		}
	})
	t.Run("G20 exact sentinels and deterministic fallback", func(t *testing.T) {
		base := []byte("BOF-A\n" + string(managed("a", "root", "a\n")) + "GAP-A\n" + string(managed("b", "root", "b\n")) + "GAP-B")
		ours := []byte("BOF-O\n" + string(managed("a", "root", "a\n")) + "GAP-O\n" + string(managed("b", "root", "b\n")) + "GAP-B")
		theirs := []byte("BOF-T\n" + string(managed("b", "root", "b2\n")) + "GAP-T\n" + string(managed("a", "root", "a2\n")) + "GAP-B")
		baseline := matrixBaseline(t, base)
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: baseline})
		if err != nil {
			t.Fatal(err)
		}
		assertExactTopologyFallback(t, p, ours, baseline)
		if strings.Count(string(p.Candidate), "GAP-O") != 1 || strings.Count(string(p.Candidate), "GAP-B") != 1 {
			t.Fatal("G20 sentinel loss/duplication")
		}
	})
	t.Run("G21 no anchors clean whole-file deletion", func(t *testing.T) {
		base, ours, theirs := []byte("plain\n"), []byte{}, []byte("plain\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: matrixBaseline(t, base)})
		if err != nil || len(p.Conflicts) != 0 || len(p.Candidate) != 0 {
			t.Fatalf("G21=%q %#v %v", p.Candidate, p, err)
		}
		p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: []byte("local\n"), Theirs: []byte("upstream\n"), Baseline: matrixBaseline(t, base)})
		want := []byte("<<<<<<< ours\nlocal\n=======\nupstream\n>>>>>>> template\n")
		if err != nil || len(p.Conflicts) != 1 || p.Conflicts[0].ID != "" || !bytes.Equal(p.Candidate, want) {
			t.Fatalf("G21 whole-gap merge=%q want=%q %#v %v", p.Candidate, want, p, err)
		}
		managedBase := managed("a", "root", "old\n")
		p, err = PlanFile(PlanInput{Path: "a.go", Base: managedBase, Ours: []byte{}, Theirs: managed("a", "root", "new\n"), Baseline: matrixBaseline(t, managedBase)})
		if err != nil || len(p.Conflicts) != 0 || len(p.Candidate) != 0 {
			t.Fatalf("G21 all-suppressed=%q %#v %v", p.Candidate, p, err)
		}
	})
	t.Run("G22 returned ownership", func(t *testing.T) {
		base := []byte("plain\n")
		inputBaseline := matrixBaseline(t, base)
		input := PlanInput{Path: "a.go", Base: base, Ours: base, Theirs: base, Baseline: inputBaseline, Renames: map[string]string{}}
		before := cloneFileBaseline(input.Baseline)
		p, err := PlanFile(input)
		if err != nil {
			t.Fatal(err)
		}
		p.Candidate[0] = 'X'
		p.Baseline.Blocks["missing"] = BlockBaseline{}
		if !equalBaseline(input.Baseline, before) || len(input.Renames) != 0 {
			t.Fatal("G22 input ownership mutated")
		}
	})
}
func TestPlanFileTombstoneAndDeleteResolution(t *testing.T) {
	base := managed("a", "root", "old\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: []byte{}, Theirs: managed("a", "root", "new\n"), Baseline: b.Files["a.go"]})
	if err != nil {
		t.Fatal(err)
	}
	if p.Baseline.Blocks["a"].State != StateLocalDeleted || p.Baseline.Blocks["a"].Tombstone == nil {
		t.Fatal("missing local tombstone")
	}
	ours := managed("a", "root", "local\n")
	p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: []byte{}, Baseline: b.Files["a.go"]})
	if err != nil || len(p.Conflicts) != 1 {
		t.Fatalf("conflict %v %#v", err, p)
	}
	if p.Baseline.Blocks["a"].State != StatePresent {
		t.Fatal("conflict advanced baseline")
	}
	p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: []byte{}, Baseline: b.Files["a.go"], DeleteResolutions: map[string]DeleteResolution{"a": DeleteKeep}})
	if err != nil || p.Baseline.Blocks["a"].State != StateUpstreamDeletedLocalRetained {
		t.Fatal("keep failed")
	}
}
func TestMerge3OverlapDeterministic(t *testing.T) {
	a, c := Merge3([]byte("a\nb\n"), []byte("a\nours\n"), []byte("a\ntheirs\n"))
	if !c || len(a) == 0 {
		t.Fatal("overlap conflict missing")
	}
}
func TestPlanFileRenameResolutionAndCRLF(t *testing.T) {
	base := managed("old", "root", "old\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := managed("new", "root", "new\n")
	p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: base, Theirs: target, Baseline: b.Files["a.go"], Renames: map[string]string{"new": "old"}})
	if err != nil || p.Baseline.Blocks["new"].Body != "new\n" || p.Baseline.Blocks["old"].Body != "" {
		t.Fatalf("rename=%#v %v", p, err)
	}
	_, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: managed("old", "root", "local\n"), Theirs: []byte{}, Baseline: b.Files["a.go"], DeleteResolutions: map[string]DeleteResolution{"old": "stale"}})
	if err == nil {
		t.Fatal("stale resolution accepted")
	}
	cr := []byte("x\r\n// tplater:managed-begin id=a provider=root\r\nold\r\n// tplater:managed-end id=a\r\n")
	b, err = BuildBaseline(map[string][]byte{"a.go": cr}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err = PlanFile(PlanInput{Path: "a.go", Base: cr, Ours: cr, Theirs: cr, Baseline: b.Files["a.go"]})
	if err != nil || bytes.Contains(p.Candidate, []byte("\r\n// tplater:managed-begin id=a provider=root\n")) {
		t.Fatal("CRLF lost")
	}
}

func TestPlanFilePreservesTargetLayoutAndCRLFConflicts(t *testing.T) {
	base := []byte("head\n" + string(managed("z", "root", "old-z\n")) + "between\n" + string(managed("a", "root", "old-a\n")) + "tail\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	theirs := []byte("head changed\n" + string(managed("z", "root", "new-z\n")) + "between target\n" + string(managed("a", "root", "old-a\n")) + "tail\n")
	p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: base, Theirs: theirs, Baseline: b.Files["a.go"]})
	if err != nil || !bytes.Equal(p.Candidate, theirs) {
		t.Fatalf("layout changed: %q err=%v", p.Candidate, err)
	}
	cr := managedEOL("a", "root", "old\r\n", "\r\n")
	b, err = BuildBaseline(map[string][]byte{"a.go": cr}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err = PlanFile(PlanInput{Path: "a.go", Base: cr, Ours: managedEOL("a", "root", "ours\r\n", "\r\n"), Theirs: managedEOL("a", "root", "theirs\r\n", "\r\n"), Baseline: b.Files["a.go"]})
	if err != nil || !bytes.Contains(p.Candidate, []byte("<<<<<<< ours\r\n")) || bytes.Contains(p.Candidate, []byte("<<<<<<< ours\n")) {
		t.Fatalf("CRLF conflict changed: %q err=%v", p.Candidate, err)
	}
}

func TestPlanFileManagedOnlyCRLFAndRenameCollision(t *testing.T) {
	cr := managedEOL("a", "root", "body\r\n", "\r\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": cr}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanFile(PlanInput{Path: "a.go", Base: cr, Ours: cr, Theirs: cr, Baseline: b.Files["a.go"]})
	if err != nil || !bytes.Equal(p.Candidate, cr) {
		t.Fatalf("managed-only CRLF changed: %q err=%v", p.Candidate, err)
	}
	base := append(managed("old", "root", "old\n"), managed("new", "root", "new\n")...)
	b, err = BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ours := managed("old", "root", "old\n")
	theirs := managed("new", "root", "new\n")
	p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"], Renames: map[string]string{"new": "old"}})
	if err == nil || !equalBaseline(p.Baseline, b.Files["a.go"]) {
		t.Fatalf("rename collision accepted: %#v err=%v", p, err)
	}
}

func TestPlanFileRejectsInvalidRenameGraphsWithoutBaselineAdvance(t *testing.T) {
	base := managed("old", "root", "old\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, renames := range map[string]map[string]string{
		"missing source": {"new": "missing"},
		"chain":          {"middle": "old", "new": "middle"},
		"cycle":          {"old": "new", "new": "old"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: base, Theirs: managed("new", "root", "new\n"), Baseline: b.Files["a.go"], Renames: renames})
			if err == nil || !equalBaseline(p.Baseline, b.Files["a.go"]) {
				t.Fatalf("invalid rename advanced baseline: %#v err=%v", p, err)
			}
		})
	}
}

func TestPlanFileUsesMovedTargetAnchorAndMigratesLocalTombstone(t *testing.T) {
	base := append(managed("a", "root", "old-a\n"), managed("z", "root", "old-z\n")...)
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := append(managed("z", "root", "old-z\n"), managed("a", "root", "old-a\n")...)
	ours := append(managed("a", "root", "local-a\n"), managed("z", "root", "old-z\n")...)
	p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: target, Baseline: b.Files["a.go"]})
	if err != nil || !bytes.Equal(p.Candidate, append(managed("z", "root", "old-z\n"), managed("a", "root", "local-a\n")...)) {
		t.Fatalf("moved target anchor not retained: %q err=%v", p.Candidate, err)
	}
	deleted := b.Files["a.go"]
	old := deleted.Blocks["a"]
	old.State = StateLocalDeleted
	old.Tombstone = &Tombstone{Side: TombstoneLocal, Provider: old.Provider, Source: old.Source, BodySHA256: old.BodySHA256}
	deleted.Blocks["a"] = old
	p, err = PlanFile(PlanInput{Path: "a.go", Base: base, Ours: managed("z", "root", "old-z\n"), Theirs: append(managed("z", "root", "old-z\n"), managed("renamed", "root", "old-a\n")...), Baseline: deleted, Renames: map[string]string{"renamed": "a"}})
	if err != nil || p.Baseline.Blocks["renamed"].State != StateLocalDeleted || p.Baseline.Blocks["renamed"].Tombstone == nil {
		t.Fatalf("tombstone rename failed: %#v err=%v", p, err)
	}
}

func TestPlanFileLayoutChangeRetainsIndependentLocalSkeletonEdit(t *testing.T) {
	base := []byte("head\n" + string(managed("a", "root", "old-a\n")) + "between\n" + string(managed("b", "root", "old-b\n")) + "tail\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ours := []byte("head\n" + string(managed("a", "root", "old-a\n")) + "between local\n" + string(managed("b", "root", "old-b\n")) + "tail\n")
	theirs := []byte("head target\n" + string(managed("b", "root", "new-b\n")) + "between target\n" + string(managed("a", "root", "new-a\n")) + "tail target\n")
	p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"]})
	if err != nil || len(p.Conflicts) == 0 {
		t.Fatalf("layout/skeleton conflict missing: %#v err=%v", p, err)
	}
	if !bytes.Equal(p.Candidate, ours) {
		t.Fatalf("topology conflict did not retain exact ours: %q", p.Candidate)
	}
	if !equalBaseline(p.Baseline, b.Files["a.go"]) {
		t.Fatal("skeleton conflict advanced baseline")
	}
	t.Run("unchanged neighboring IDs merge without conflict", func(t *testing.T) {
		oursHeader := []byte("head local\n" + string(managed("a", "root", "old-a\n")) + "between\n" + string(managed("b", "root", "old-b\n")) + "tail\n")
		targetWithAddedBlock := []byte("head\n" + string(managed("a", "root", "new-a\n")) + "between target\n" + string(managed("b", "root", "new-b\n")) + string(managed("x", "root", "new-x\n")) + "tail target\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: oursHeader, Theirs: targetWithAddedBlock, Baseline: b.Files["a.go"]})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Contains(p.Candidate, []byte("head local\n")) {
			t.Fatalf("matched skeleton gap did not merge: %q %#v err=%v", p.Candidate, p.Conflicts, err)
		}
	})
}

func TestPlanFileDeleteKeepRequiresUniqueNeighborAnchor(t *testing.T) {
	base := append(append(managed("a", "root", "old-a\n"), managed("b", "root", "old-b\n")...), managed("c", "root", "old-c\n")...)
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ours := append(append(managed("a", "root", "old-a\n"), managed("b", "root", "local-b\n")...), managed("c", "root", "old-c\n")...)
	t.Run("reordered neighbors conflict without baseline advance", func(t *testing.T) {
		theirs := append(managed("c", "root", "new-c\n"), managed("a", "root", "new-a\n")...)
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"], DeleteResolutions: map[string]DeleteResolution{"b": DeleteKeep}})
		if err != nil || len(p.Conflicts) == 0 {
			t.Fatalf("reordered delete keep was accepted: %#v err=%v", p, err)
		}
		if !equalBaseline(p.Baseline, b.Files["a.go"]) {
			t.Fatal("invalid retained-block anchor advanced baseline")
		}
	})
	t.Run("adjacent surviving neighbors retain local block", func(t *testing.T) {
		theirs := append(managed("a", "root", "new-a\n"), managed("c", "root", "new-c\n")...)
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"], DeleteResolutions: map[string]DeleteResolution{"b": DeleteKeep}})
		if err != nil || len(p.Conflicts) != 0 {
			t.Fatalf("valid retained-block anchor conflicted: %#v err=%v", p, err)
		}
		want := append(append(managed("a", "root", "new-a\n"), managed("b", "root", "local-b\n")...), managed("c", "root", "new-c\n")...)
		if !bytes.Equal(p.Candidate, want) || p.Baseline.Blocks["b"].State != StateUpstreamDeletedLocalRetained {
			t.Fatalf("retained block = %q baseline=%#v", p.Candidate, p.Baseline.Blocks["b"])
		}
	})
}

func TestPlanFileProjectsApprovedLocalDeletionAcrossAllGapViews(t *testing.T) {
	base := []byte("head\n" + string(managed("a", "root", "old\n")) + "tail\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ours := []byte("head local\ntail\n")
	t.Run("coalesced local gap succeeds", func(t *testing.T) {
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: []byte("head\n" + string(managed("a", "root", "new\n")) + "tail\n"), Baseline: b.Files["a.go"]})
		if err != nil || len(p.Conflicts) != 0 || !bytes.Equal(p.Candidate, ours) || p.Baseline.Blocks["a"].State != StateLocalDeleted {
			t.Fatalf("coalesced deletion = %#v err=%v", p, err)
		}
	})
	t.Run("concurrent projected skeleton edit conflicts", func(t *testing.T) {
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: []byte("head upstream\n" + string(managed("a", "root", "new\n")) + "tail\n"), Baseline: b.Files["a.go"]})
		if err != nil || len(p.Conflicts) != 1 || !bytes.Contains(p.Candidate, []byte("head local\n")) || !bytes.Contains(p.Candidate, []byte("head upstream\n")) || !equalBaseline(p.Baseline, b.Files["a.go"]) {
			t.Fatalf("projected gap conflict = %#v err=%v", p, err)
		}
	})
}

func TestPlanFileTopologyConflictReturnsExactOurs(t *testing.T) {
	base := []byte("H\n" + string(managed("a", "root", "old-a\n")) + "X\n" + string(managed("b", "root", "old-b\n")) + "Z\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("target split of edited slot", func(t *testing.T) {
		ours := []byte("H\n" + string(managed("a", "root", "old-a\n")) + "X local\n" + string(managed("b", "root", "old-b\n")) + "Z\n")
		theirs := []byte("H\n" + string(managed("a", "root", "new-a\n")) + string(managed("n", "root", "new-n\n")) + "X\n" + string(managed("b", "root", "new-b\n")) + "Z\n")
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"]})
		if err != nil || len(p.Conflicts) != 1 || p.Conflicts[0].ID != "" || !bytes.Equal(p.Candidate, ours) || !equalBaseline(p.Baseline, b.Files["a.go"]) || len(p.RenameAliases) != 0 {
			t.Fatalf("topology fallback = %#v err=%v", p, err)
		}
	})
	t.Run("unexplained local block", func(t *testing.T) {
		ours := append(append([]byte(nil), base...), managed("n", "root", "local-n\n")...)
		p, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: base, Baseline: b.Files["a.go"]})
		if err != nil || len(p.Conflicts) != 1 || !bytes.Equal(p.Candidate, ours) || !equalBaseline(p.Baseline, b.Files["a.go"]) {
			t.Fatalf("unexplained local block = %#v err=%v", p, err)
		}
	})
}

func TestPlanFileTopologyFallbackIsDeterministicAndDefensive(t *testing.T) {
	base := []byte("H\n" + string(managed("a", "root", "old-a\n")) + "X\n" + string(managed("b", "root", "old-b\n")) + "Z\n")
	b, err := BuildBaseline(map[string][]byte{"a.go": base}, []ProviderSource{{Provider: "root", Source: baselineSource()}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ours := []byte("H\n" + string(managed("a", "root", "old-a\n")) + "X local\n" + string(managed("b", "root", "old-b\n")) + "Z\n")
	theirs := []byte("H\n" + string(managed("a", "root", "new-a\n")) + string(managed("n", "root", "new-n\n")) + "X\n" + string(managed("b", "root", "new-b\n")) + "Z\n")
	first, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"]})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		got, err := PlanFile(PlanInput{Path: "a.go", Base: base, Ours: ours, Theirs: theirs, Baseline: b.Files["a.go"]})
		if err != nil || !bytes.Equal(got.Candidate, first.Candidate) || !equalBaseline(got.Baseline, first.Baseline) || len(got.Conflicts) != len(first.Conflicts) {
			t.Fatalf("nondeterministic topology fallback %d: %#v err=%v", i, got, err)
		}
	}
	first.Candidate[0] ^= 1
	if bytes.Equal(first.Candidate, ours) || !bytes.Equal(ours, []byte("H\n"+string(managed("a", "root", "old-a\n"))+"X local\n"+string(managed("b", "root", "old-b\n"))+"Z\n")) {
		t.Fatal("topology fallback aliases input bytes")
	}
}

func equalBaseline(a, b FileBaseline) bool {
	if a.Skeleton != b.Skeleton || len(a.Blocks) != len(b.Blocks) {
		return false
	}
	for id, block := range a.Blocks {
		if b.Blocks[id] != block {
			return false
		}
	}
	return true
}
