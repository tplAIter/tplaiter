package resultdto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGraphDomainRegistrationAndClosedData(t *testing.T) {
	for _, op := range []Operation{OperationGraphSource, OperationGraphExports, OperationGraphAST, OperationGraphStats} {
		if _, e := KindForOperation(op); e != nil {
			t.Fatal(e)
		}
	}
	d := GraphData{APIVersion: "tplaiter.dev/graph-query-result/v1", Layer: "ast", QueryDigest: "sha256:" + strings.Repeat("1", 64), InputDigests: []string{}, FullGraphDigest: "sha256:" + strings.Repeat("2", 64), GraphStatus: "ok", CacheState: "disabled", ObservationBasis: "installed-project-syntax", VerificationLevel: "syntax-go-and-approximate-rust-outline", Records: []GraphRecord{}, Page: GraphPage{Representation: "whole", Digest: "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}}
	b, e := json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeGraphData(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"layer":`, `"trusted":true,"layer":`, 1), strings.Replace(string(b), `"layer":`, `"layer":"a","layer":`, 1), strings.Replace(string(b), `"returnedRecords":0`, `"returnedRecords":1`, 1)} {
		if _, e = DecodeGraphData([]byte(bad)); e == nil {
			t.Fatal("accepted malformed result")
		}
	}
}
