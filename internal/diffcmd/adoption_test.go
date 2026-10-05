package diffcmd

import (
	"github.com/tplAIter/tplaiter/internal/adoptionpolicy"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"testing"
)

func TestExcludedDiffNamesIndependentCurrentOrOriginReference(t *testing.T) {
	origin := []byte("original signed\n")
	next := []byte("upstream changed\n")
	ours := []byte("user owned\n")
	p := &adoptionpolicy.Policy{Origin: adoptionpolicy.Origin{SourceCommit: "original-commit", Exclusions: []adoptionpolicy.Exclusion{{Path: "go.mod", SourceSHA256: evidencecas.Digest(origin)}}}}
	actual := ownership.State{Exists: true, Data: ours, Mode: 0o640, Kind: ownership.KindFile}
	x := exclusionObservation("go.mod", map[string][]byte{"go.mod": next}, p, provenance.RootSubject{Commit: "current-commit"}, actual)
	if !x.Drift || x.ReferenceScope != "current-signed-source" || x.ReferenceCommit != "current-commit" || x.ExpectedSHA256 != evidencecas.Digest(next) || x.ExpectedSHA256 == x.CurrentSHA256 {
		t.Fatalf("local baseline substituted %#v", x)
	}
	x = exclusionObservation("go.mod", map[string][]byte{}, p, provenance.RootSubject{Commit: "current-commit"}, actual)
	if !x.Drift || x.ReferenceScope != "adoption-origin" || x.ReferenceCommit != "original-commit" || x.ExpectedSHA256 != evidencecas.Digest(origin) {
		t.Fatalf("false current reference %#v", x)
	}
	x = exclusionObservation("go.mod", map[string][]byte{}, p, provenance.RootSubject{Commit: "current-commit"}, ownership.State{})
	if !x.Drift || x.Present || x.CurrentSHA256 != "" {
		t.Fatalf("missing exclusion labeled clean %#v", x)
	}
}
