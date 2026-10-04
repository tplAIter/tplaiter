package ossinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
)

// Sign each test's exact manifest/contract closure. The gate must narrow only
// inert generator metadata, while preserving every previous validation check.
func TestNativeGeneratorEnrollmentGate(t *testing.T) {
	for _, name := range []string{"inert", "tool", "post-create", "post-update", "command", "environment", "ai", "missing", "reserved", "case-collision", "manifest-pin", "dependencies", "duplicate-manifest"} {
		t.Run(name, func(t *testing.T) {
			o := enrollmentOptions(t)
			publisher, pkg := signedPackage(t, "https://example.test/generator-gate", func(files map[string][]byte) {
				manifestRaw := files["template.manifest.yaml"]
				declaration := "generators:\n  - kind: entity\n    snippet: snippet.tmpl\n    target: entity.go\n"
				files["snippet.tmpl"] = []byte("{{ .Name }} inert only\n")
				switch name {
				case "tool":
					declaration += "requires:\n  tools:\n    - name: git\n"
				case "post-create":
					declaration += "hooks:\n  postCreate:\n    - run: echo forbidden\n"
				case "post-update":
					declaration += "hooks:\n  postUpdate:\n    - run: echo forbidden\n"
				case "command":
					declaration += "commands:\n  probe:\n    run: echo forbidden\n"
				case "environment":
					declaration += "environment:\n  playbooks:\n    - name: setup\n      file: setup.yml\n"
				case "ai":
					declaration += "aiConfig:\n  path: ai\n"
				case "missing":
					delete(files, "snippet.tmpl")
				case "reserved":
					declaration = strings.ReplaceAll(declaration, "snippet.tmpl", ".tplaiter/resources.lock.json")
				case "case-collision":
					declaration = "generators:\n  - kind: entity\n    targets:\n      - snippet: snippet.tmpl\n        target: a.go\n      - snippet: SNIPPET.tmpl\n        target: b.go\n"
					files["SNIPPET.tmpl"] = []byte("case collision")
				case "duplicate-manifest":
					declaration += "metadata:\n  name: duplicated\n  version: 1.0.0\n"
				}
				manifestRaw = append(manifestRaw, []byte(declaration)...)
				files["template.manifest.yaml"] = manifestRaw
				contract := operationtrust.NativeContract{APIVersion: operationtrust.NativeContractAPIVersion, Kind: operationtrust.NativeContractKind, ManifestPath: "template.manifest.yaml", ManifestSHA256: evidencecas.Digest(manifestRaw), Dependencies: []string{}}
				if name == "manifest-pin" {
					contract.ManifestSHA256 = evidencecas.Digest(nil)
				}
				if name == "dependencies" {
					contract.Dependencies = []string{"unsupported"}
				}
				raw, err := json.Marshal(contract)
				if err != nil {
					t.Fatal(err)
				}
				files["template.contract.json"] = raw
			})
			o.Publishers = []Publisher{publisher}
			o.SourcePackages = []SourcePackage{pkg}
			o.ProjectContexts = o.ProjectContexts[:1]
			result, err := GenerateWithContext(context.Background(), o)
			if name == "inert" {
				if err != nil || result.PublicationState != "committed" {
					t.Fatalf("valid inert source refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid/action-bearing source enrolled")
			}
			if name != "duplicate-manifest" && !errors.Is(err, operationtrust.ErrSourceAdapterUnsupported) {
				t.Fatalf("expected typed unsupported refusal: %v", err)
			}
			if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused source published installation: %v", err)
			}
		})
	}
}
