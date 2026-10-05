package trustload

import (
	"context"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"strings"
	"testing"
)

func TestToolchainRequiresLiveVerifiedRuntime(t *testing.T) {
	var r *Runtime
	if _, e := r.ResolveGoToolchain(context.Background(), nil); e != ErrToolchain {
		t.Fatalf("nil runtime admitted: %v", e)
	}
	var c *GoToolchain
	if c.Driver() != nil || c.IndexBytes() != nil || c.Version() != "" {
		t.Fatal("zero capability material")
	}
	if e := c.Recheck(context.Background()); e != ErrToolchain {
		t.Fatal(e)
	}
}

func TestToolchainIndexClosedAdmission(t *testing.T) {
	index := ToolchainIndex{APIVersion: ToolchainIndexVersion, GoVersion: "go1.27.1", GOOS: "darwin", GOARCH: "arm64"}
	for _, name := range []string{"VERSION", "bin/go", "pkg/tool/darwin_arm64/asm", "pkg/tool/darwin_arm64/compile", "pkg/tool/darwin_arm64/link", "src/runtime/runtime.go"} {
		mode := "100644"
		if name == "bin/go" || strings.HasPrefix(name, "pkg/tool/") {
			mode = "100755"
		}
		index.Files = append(index.Files, ToolchainFile{Path: name, Mode: mode, Size: 1, SHA256: evidencecas.Digest([]byte("inert")), Chunks: []string{evidencecas.Digest([]byte("inert CAS reference only"))}})
	}
	raw, _ := json.Marshal(index)
	if e := ValidateGoToolchainIndex(raw); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"unknown-version", "unknown-field", "parent-path", "absolute-path", "traversal", "wrong-mode", "bad-digest", "bad-chunk", "oversized-file", "missing-driver", "duplicate-path"} {
		t.Run(name, func(t *testing.T) {
			b := index
			b.Files = append([]ToolchainFile(nil), index.Files...)
			b.Files[0].Chunks = append([]string(nil), b.Files[0].Chunks...)
			switch name {
			case "unknown-version":
				b.APIVersion = "unknown"
			case "parent-path":
				b.Files[0].Path = ".."
			case "absolute-path":
				b.Files[0].Path = "/outside"
			case "traversal":
				b.Files[0].Path = "../outside"
			case "wrong-mode":
				b.Files[0].Mode = "120000"
			case "bad-digest":
				b.Files[0].SHA256 = "caller-label"
			case "bad-chunk":
				b.Files[0].Chunks[0] = "caller-label"
			case "oversized-file":
				b.Files[0].Size = (64 << 20) + 1
			case "missing-driver":
				b.Files = append(b.Files[:1], b.Files[2:]...)
			case "duplicate-path":
				b.Files = append([]ToolchainFile{b.Files[0]}, b.Files...)
			}
			raw, _ := json.Marshal(b)
			if name == "unknown-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"shell":true}`)...)
			}
			if e := ValidateGoToolchainIndex(raw); e != ErrToolchain {
				t.Fatalf("bad index not typed refused: %v", e)
			}
		})
	}
}
