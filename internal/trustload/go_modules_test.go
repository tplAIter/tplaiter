package trustload

import (
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"strings"
	"testing"
)

func TestGoModuleIndexRefusesUnsafeClosure(t *testing.T) {
	digest := evidencecas.Digest([]byte("synthetic validator-only data"))
	sum := "h1:" + strings.Repeat("A", 43) + "="
	v := GoModuleIndex{APIVersion: GoModuleIndexVersion, GoModSHA256: digest, GoSumSHA256: digest, Modules: []GoModulePin{{Path: "example.com/module", Version: "v1.0.0", Sum: sum, GoModSum: sum}}, Files: []ToolchainFile{{Path: "example.com/module@v1.0.0/source.go", Mode: "100644", SHA256: digest, Size: 1, Chunks: []string{digest}}}}
	raw, _ := json.Marshal(v)
	if ValidateGoModuleIndex(raw) != nil {
		t.Fatal("valid bounded declaration refused")
	}
	for _, name := range []string{"traversal", "absolute", "symlink-mode", "executable-mode", "extra-root", "bad-version", "bad-sum", "bad-digest", "bad-chunk", "oversize", "duplicate-file", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			b := v
			b.Files = append([]ToolchainFile(nil), v.Files...)
			b.Files[0].Chunks = append([]string(nil), v.Files[0].Chunks...)
			b.Modules = append([]GoModulePin(nil), v.Modules...)
			switch name {
			case "traversal":
				b.Files[0].Path = "example.com/module@v1.0.0/../outside"
			case "absolute":
				b.Files[0].Path = "/outside"
			case "symlink-mode":
				b.Files[0].Mode = "120000"
			case "executable-mode":
				b.Files[0].Mode = "100755"
			case "extra-root":
				b.Files[0].Path = "example.com/other@v1.0.0/source.go"
			case "bad-version":
				b.Modules[0].Version = "main"
			case "bad-sum":
				b.Modules[0].Sum = "caller-asserted"
			case "bad-digest":
				b.GoModSHA256 = "caller-asserted"
			case "bad-chunk":
				b.Files[0].Chunks[0] = "caller-asserted"
			case "oversize":
				b.Files[0].Size = (32 << 20) + 1
			case "duplicate-file":
				b.Files = append(b.Files, b.Files[0])
			}
			raw, _ := json.Marshal(b)
			if name == "unknown-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"helper":"sh"}`)...)
			}
			if ValidateGoModuleIndex(raw) != ErrGoModules {
				t.Fatal("unsafe closure admitted")
			}
		})
	}
}
func TestGoModuleProjectDigestBindsDependencies(t *testing.T) {
	first := []byte("module example.com/first\n\ngo 1.26\nrequire go.temporal.io/sdk v1.29.1\n")
	second := []byte(strings.Replace(string(first), "example.com/first", "example.com/second", 1))
	if GoModuleProjectDigest(first) == "" || GoModuleProjectDigest(first) != GoModuleProjectDigest(second) {
		t.Fatal("module identity should stay independently bound by raw project input")
	}
	third := []byte(strings.Replace(string(first), "v1.29.1", "v1.29.2", 1))
	if GoModuleProjectDigest(first) == GoModuleProjectDigest(third) {
		t.Fatal("dependency drift not bound")
	}
	if GoModuleProjectDigest([]byte("not go.mod")) != "" {
		t.Fatal("malformed module admitted")
	}
}
