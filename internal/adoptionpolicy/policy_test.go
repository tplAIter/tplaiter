package adoptionpolicy

import (
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"strings"
	"testing"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, e := New(Origin{ProjectID: "project", SourceRootLockSHA256: evidencecas.Digest([]byte("signed lock")), SourceCommit: strings.Repeat("a", 40), RendererVersion: "dev", RenderInputsSHA256: evidencecas.Digest([]byte("inputs")), DecisionAt: "2026-10-05T00:00:00Z", Exclusions: []Exclusion{{Path: "go.mod", SourceSHA256: evidencecas.Digest([]byte("signed")), SourceMode: 0o644, InitialState: "modified", Observed: Observation{Exists: true, Mode: 0o640, Device: 1, Inode: 2, SHA256: evidencecas.Digest([]byte("ours"))}}, {Path: "missing.txt", SourceSHA256: evidencecas.Digest([]byte("signed missing")), SourceMode: 0o644, InitialState: "missing", Observed: Observation{SHA256: evidencecas.Digest(nil)}}}})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestClosedPolicyRefusesContradictionsAndStaleDecisions(t *testing.T) {
	cases := map[string]func(*Policy){"source-tamper": func(p *Policy) { p.Origin.SourceCommit = strings.Repeat("b", 40) }, "mode": func(p *Policy) { p.Origin.Exclusions[0].Observed.Mode = 0o4644 }, "missing-identity": func(p *Policy) { p.Origin.Exclusions[1].Observed.Inode = 1 }, "duplicate": func(p *Policy) { p.Origin.Exclusions[1].Path = "go.mod" }, "foreign-state": func(p *Policy) { p.Origin.Exclusions[0].Path = ".tplaiter/ownership.json" }, "glob": func(p *Policy) { p.Origin.Exclusions[0].Path = "*.go" }, "case-collision": func(p *Policy) { p.Origin.Exclusions[1].Path = "GO.MOD" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := testPolicy(t)
			mutate(p)
			if p.Validate() == nil {
				t.Fatal("invalid policy accepted")
			}
			p.DecisionSHA256, _ = Digest(p.Origin)
			if name != "source-tamper" && p.Validate() == nil {
				t.Fatal("rehashing contradiction accepted")
			}
		})
	}
	p := testPolicy(t)
	m, e := p.Map()
	if e != nil {
		t.Fatal(e)
	}
	m["exclude"] = []string{"go.mod"}
	if _, e = Parse(m); e == nil {
		t.Fatal("open policy accepted")
	}
}
func TestOriginRejectsIrrelevantCleanChoices(t *testing.T) {
	p := testPolicy(t)
	files := map[string][]byte{"go.mod": []byte("signed"), "missing.txt": []byte("signed missing")}
	obs := map[string]Observation{"go.mod": p.Origin.Exclusions[0].Observed}
	if e := ValidateOrigin(p, files, obs); e != nil {
		t.Fatal(e)
	}
	obs["go.mod"] = Observation{Exists: true, Mode: 0o644, Device: 1, Inode: 2, SHA256: evidencecas.Digest(files["go.mod"])}
	if ValidateOrigin(p, files, obs) == nil {
		t.Fatal("irrelevant choice accepted")
	}
	delete(files, "missing.txt")
	if ValidateOrigin(p, files, nil) == nil {
		t.Fatal("unsigned exclusion accepted")
	}
}
