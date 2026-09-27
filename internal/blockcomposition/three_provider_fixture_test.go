package blockcomposition

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
)

func threeProviderInput(language, layout string) Input {
	ext := ".go"
	prefix := "package fixture\n"
	if language == "rust" {
		ext, prefix = ".rs", "// fixture\n"
	}
	paths := []string{"src/controller/controllers" + ext, "src/repository/repositories" + ext, "src/service/services" + ext}
	providers := []Provider{
		provider("root", 'a', map[string][]byte{}),
		provider("security", 'b', map[string][]byte{}),
		provider("telemetry", 'c', map[string][]byte{}),
	}
	exports := make([]blockexport.BlockExport, 0, len(providers))
	skeletons := make(map[string][]byte, len(paths))
	for _, target := range paths {
		skeletons[target] = []byte(prefix)
	}
	for providerIndex := range providers {
		p := &providers[providerIndex]
		targets := make([]blockexport.Target, 0, len(paths))
		for pathIndex, target := range paths {
			id := fmt.Sprintf("%s.%d", p.Name, pathIndex+1)
			body := fmt.Sprintf("%s-%d.tmpl", p.Name, pathIndex+1)
			p.Bodies[body] = []byte(fmt.Sprintf("// %s %d\n", p.Name, pathIndex+1))
			targets = append(targets, blockexport.Target{Path: target, Blocks: []blockexport.Block{{ID: id, Provider: p.Name, Layout: layout, Body: body, Order: (providerIndex + 1) * 10}}})
		}
		exports = append(exports, blockexport.BlockExport{APIVersion: blockexport.APIVersion, Kind: blockexport.Kind, Metadata: blockexport.Metadata{ID: p.Name, Version: "1.0.0"}, Compatibility: blockexport.Compatibility{Tplater: ">=0.3.0", MarkerSchema: blockexport.MarkerSchema}, MergeStrategy: blockexport.MergeStrategy, Formatter: blockexport.Formatter{Adapter: "none", OptionsDigest: digest('a')}, Targets: targets})
	}
	return Input{Exports: exports, Providers: providers, Skeletons: skeletons}
}

func TestThreeProvidersNineBlocksThreePathsGoAndRustBothLayouts(t *testing.T) {
	for _, language := range []string{"go", "rust"} {
		for _, layout := range []string{"layer_files", "per_entity"} {
			t.Run(language+"/"+layout, func(t *testing.T) {
				in := threeProviderInput(language, layout)
				one, err := Compose(in)
				if err != nil {
					t.Fatal(err)
				}
				two, err := Compose(in)
				if err != nil || len(one.Targets) != 3 || len(two.Targets) != 3 {
					t.Fatalf("composition=%+v err=%v", one, err)
				}
				ids := make([]string, 0, 9)
				for i, target := range one.Targets {
					if len(target.Blocks) != 3 || !bytes.Equal(target.Content, two.Targets[i].Content) {
						t.Fatalf("target %s is incomplete or unstable", target.Path)
					}
					doc, err := managedblocks.Parse(target.Path, target.Content)
					if err != nil || len(doc.Regions) != 3 {
						t.Fatalf("markers %s: %v", target.Path, err)
					}
					for _, b := range target.Blocks {
						ids = append(ids, b.ID)
					}
				}
				sort.Strings(ids)
				if len(ids) != 9 || strings.Join(ids, ",") != "root.1,root.2,root.3,security.1,security.2,security.3,telemetry.1,telemetry.2,telemetry.3" {
					t.Fatalf("block identities=%v", ids)
				}
			})
		}
	}
}
