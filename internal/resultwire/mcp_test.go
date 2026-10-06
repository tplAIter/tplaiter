package resultwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"strings"
	"testing"
)

func TestSDKFrameEncodingAndClosedLayout(t *testing.T) {
	env := resultdto.New(resultdto.OperationGraphStats, "test")
	env.Project = &resultdto.Project{ID: "p", Root: "/public/<root>\\\"&é"}
	_ = env.SetData(map[string]any{"text": "<\\\"&\n"})
	for _, id := range []any{"short", "<\\\"&\n\té", strings.Repeat("<\\\"&", 1500), float64(42)} {
		encoded, _ := json.Marshal(id)
		l := GraphFrameLayout{GraphFrameVersion, encoded, 32768}
		s, err := EncodeGraphFrame(l)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeGraphFrame(s)
		if err != nil || !bytes.Equal(back.ID, encoded) {
			t.Fatal("closed roundtrip", err)
		}
		result := Structured(env, false)
		actual, err := Frame(back.RequestID(), result)
		if err != nil {
			t.Fatal(err)
		}
		sdk, err := json.Marshal(mcp.NewJSONRPCResultResponse(mcp.NewRequestId(id), result))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, append(sdk, '\n')) {
			t.Fatal("different actual SDK serializer")
		}
	}
	for _, raw := range []string{`{"apiVersion":"bad","normalizedID":"x","ceiling":32768}`, `{"apiVersion":"tplaiter.dev/graph-mcp-frame/v1","normalizedID":null,"ceiling":32768}`, `{"apiVersion":"tplaiter.dev/graph-mcp-frame/v1","normalizedID":"x","ceiling":32769}`, `{"apiVersion":"tplaiter.dev/graph-mcp-frame/v1","normalizedID":"x","ceiling":32768,"authority":true}`} {
		if _, err := DecodeGraphFrame(base64.RawURLEncoding.EncodeToString([]byte(raw))); err == nil {
			t.Fatal("invalid closed layout accepted", raw)
		}
	}
}
