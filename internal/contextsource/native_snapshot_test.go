package contextsource

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func TestRecordedNativeSnapshotRetainsRetiredAndInactiveAnswers(t *testing.T) {
	f := newContextFixture(t, func(alias string, files map[string][]byte) {
		if alias == "root" {
			contract, err := DecodeNativeContextContractV2(files["template.contract.json"], files["template.manifest.yaml"])
			if err != nil {
				t.Fatal(err)
			}
			files["template.manifest.yaml"] = []byte(strings.Replace(string(files["template.manifest.yaml"]), "settings: []", `settings:
  - group: retired
    title: Retired
    type: multiselect
    deprecated: true
    options:
      - id: old
        title: Old
  - group: parent
    title: Parent
    type: select
    default: off
    options:
      - id: off
        title: Off
      - id: on
        title: On
        settings:
          - group: child
            title: Child
            type: toggle
            default: false`, 1))
			contract.ManifestSHA256 = evidencecas.Digest(files["template.manifest.yaml"])
			files["template.contract.json"] = contextJSON(t, contract)
		}
	})
	ctx := context.Background()
	sources, err := PrepareContextSources(ctx, f.runtime, contextJSON(t, f.input))
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	values := settings.Values{"retired": []any{"old"}, "parent": "off", "child": true}
	p, err := PrepareRecordedNativeSnapshot(ctx, f.runtime, sources, RecordedNativeSnapshotInput{Render: renderref.Input{Values: values}, RecordedValues: values, RendererVersion: "1.0.0"})
	if err != nil {
		t.Fatal("recorded retained values", err)
	}
	defer p.Close()
	got, err := p.Rendered(ctx, f.runtime)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Resolved.Values["retired"], []string{"old"}) || got.Resolved.Values["child"] != true {
		t.Fatalf("recorded snapshot changed: %+v", got.Resolved)
	}
	got.Files["hello.txt"][0] = 'X'
	got.Template.Metadata.Name = "tampered"
	got.Baseline.Files["hello.txt"] = "tampered"
	again, err := p.Rendered(ctx, f.runtime)
	if err != nil || string(again.Files["hello.txt"]) != "Hello public project.\n" || again.Template.Metadata.Name == "tampered" || again.Baseline.Files["hello.txt"] == "tampered" {
		t.Fatal("mutable calculation escaped", err)
	}
	if p.RecheckFor(ctx, &trustload.Runtime{}) == nil {
		t.Fatal("foreign runtime accepted")
	}
	changed := settings.Values{"retired": []string{"old"}, "parent": "off", "child": true}
	if _, err := PrepareRecordedNativeSnapshot(ctx, f.runtime, sources, RecordedNativeSnapshotInput{Render: renderref.Input{Values: changed}, RecordedValues: settings.Values{"retired": []string{}, "parent": "off", "child": true}, RendererVersion: "1.0.0"}); err == nil {
		t.Fatal("new retired answer accepted as recorded")
	}
	sources.Close()
	if p.RecheckFor(ctx, f.runtime) == nil {
		t.Fatal("closed source accepted")
	}
}

func TestRecordedNativeSnapshotCannotBeFabricated(t *testing.T) {
	p := &PreparedNativeSnapshot{}
	if _, err := p.RootLock(context.Background(), &trustload.Runtime{}); err == nil {
		t.Fatal("fabricated snapshot")
	}
	if _, err := PrepareRecordedNativeSnapshot(context.Background(), &trustload.Runtime{}, &PreparedContextSources{}, RecordedNativeSnapshotInput{RendererVersion: "1.0.0"}); err == nil {
		t.Fatal("missing recorded context accepted")
	}
}
