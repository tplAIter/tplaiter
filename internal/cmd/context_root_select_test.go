package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func rootB2Request(selectors ...string) contextcmd.RootSelectionRequest {
	r := contextcmd.RootSelectionRequest{Selections: []exports.Selection{}}
	for _, s := range selectors {
		r.Selections = append(r.Selections, exports.Selection{APIVersion: exports.SelectionAPIVersion, Selector: s, Bindings: []exports.ScalarParameter{}})
	}
	return r
}
func rootB2JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestRootB2StrictInputAndFrameBoundary(t *testing.T) {
	valid := string(rootB2JSON(t, rootB2Request("base.skill.review")))
	if _, err := decodeRootRequest(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", `{}`, `null`, strings.Replace(valid, `"selections":`, `"Selections":`, 1), strings.Replace(valid, `"selections":`, `"trusted":true,"selections":`, 1), strings.Replace(valid, `"selections":`, `"maxBytes":1,"maxBytes":2,"selections":`, 1), strings.Replace(valid, `"selections":`, `"maxBytes":32769,"selections":`, 1), valid + valid} {
		if _, err := decodeRootRequest(raw); err == nil {
			t.Fatalf("accepted invalid input %s", raw)
		}
	}
	env := resultdto.New(resultdto.OperationContextQuery, "test")
	env.Project = &resultdto.Project{ID: "fixture", Root: "/public/<path>&\\escaped"}
	body := resultdto.ContextRootSelectionData{Body: resultdto.RootContextBody{Files: []resultdto.RootContextFile{{Content: []byte{0, 255, 10, '<', '&', '"'}, TargetPath: "context/skill.md"}}}}
	if err := env.SetData(body); err != nil {
		t.Fatal(err)
	}
	full, err := rootResultFrame(env, 32768)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(full, []byte(`\u003c`)) || !bytes.Contains(full, []byte(`AP8KPCYi`)) || full[len(full)-1] != '\n' {
		t.Fatal("escaping/base64/newline absent")
	}
	at, err := rootResultFrame(env, len(full))
	if err != nil || !bytes.Equal(at, full) {
		t.Fatal("exact frame boundary")
	}
	if _, err = rootResultFrame(env, len(full)-1); err == nil {
		t.Fatal("accepted complete frame over ceiling")
	}
	t.Logf("complete CLI frame=%d including escaping/base64/newline", len(full))
}

type rootShortWriter struct{}

func (rootShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type rootBrokenWriter struct{}

func (rootBrokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestRootB2WritesDoNotHideBrokenOrPartialFrames(t *testing.T) {
	if !errors.Is(writeRootFrame(rootShortWriter{}, []byte("whole\n")), io.ErrShortWrite) {
		t.Fatal("short write accepted")
	}
	if !errors.Is(writeRootFrame(rootBrokenWriter{}, []byte("whole\n")), io.ErrClosedPipe) {
		t.Fatal("broken pipe accepted")
	}
	token := strings.Repeat("ab", 32)
	if !validRootDeliveryToken(token) || validRootDeliveryToken(strings.ToUpper(token)) || validRootDeliveryToken("true") {
		t.Fatal("delivery correlation format")
	}
}
