package templatequery

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
)

func TestDiscoveryAdmittedReferenceJoinDoesNotPromoteRecipe(t *testing.T) {
	body := []byte("Read AGENTS instructions; this is documentation only.\n")
	p := exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: "guide", Files: []exports.PayloadFile{{SourcePath: "guide.md", TargetPath: "context/guide.md", Mode: "100644", ContentSHA256: d.Digest(body)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}}
	raw, _ := json.Marshal(p)
	entry := exports.ExportEntry{ID: "guide", Domain: "block", Name: "guide", Version: "1.0.0", ContentDigest: d.Digest(raw), ToolDigest: d.Digest([]byte("tool")), Parameters: []exports.ScalarParameter{}, Requires: []exports.ExportRequirement{}}
	// A validated payload is insufficient to declare installability. Real
	// normal-owner admission is additionally exercised by the installed CLI test.
	c := exports.SourceCatalog{Catalog: exports.Catalog{APIVersion: exports.CatalogAPIVersion, Provider: "provider", Source: "sha256:" + strings.Repeat("a", 64), ContractDigest: "sha256:" + strings.Repeat("b", 64), Exports: []exports.ExportEntry{entry}}, Payloads: []exports.SourcePayload{{ExportID: "guide", Raw: raw}}, Blobs: []exports.MaterialBlob{{Path: "guide.md", Mode: "100644", Content: body}}}
	if catalogKind(c, entry) != d.KindContext {
		t.Fatal("prose-only payload became installable block")
	}
	ref := d.Reference{ID: "not-present", SourcePin: exportPin(entry), CandidateKind: d.KindSkill, Readiness: d.Ready, DeclarationStatus: "metadata-declared", Availability: "metadata-declared"}
	joined, selector, resolvedDigest := joinReference(ref, c, "base", &deps.SourceGraph{}, []exports.Catalog{c.Catalog})
	if joined.Availability != "unavailable" || resolvedDigest != "" || joined.Provenance != nil || selector != "" {
		t.Fatal("missing record manufactured")
	}
	entry.Domain = "approach"
	if catalogKind(c, entry) != d.KindRecipe {
		t.Fatal("recipe inferred as executable skill")
	}
}

func TestDiscoveryJoinedUseCaseFallbackKeepsExactReadonlyCallAtSmallBudget(t *testing.T) {
	// Public typed material tests the actual resolver and body/domain/digest join.
	// This calculation fixture supplies no signed runtime admission authority.
	contract := d.Digest([]byte("neutral contract"))
	pins := []deps.PinnedSource{{APIVersion: "tplaiter.dev/pinned-source/v1", Alias: "base", ProviderID: "neutral", Origin: "https://example.test/neutral", TemplatePath: ".", RequestedRef: "main", CommitAlgorithm: "sha1", Commit: strings.Repeat("a", 40), TreeDigest: d.Digest([]byte("tree")), ContentDigest: d.Digest([]byte("source")), ContractDigest: contract, EvidenceDigest: d.Digest([]byte("evidence")), Parameters: []deps.Parameter{}, Dependencies: []string{}}}
	graph, err := deps.BuildSourceGraph(pins)
	if err != nil {
		t.Fatal(err)
	}
	catalog := exports.SourceCatalog{Catalog: exports.Catalog{APIVersion: exports.CatalogAPIVersion, Provider: "neutral", Source: graph.Nodes[0].Key, ContractDigest: contract, Exports: []exports.ExportEntry{}}, Payloads: []exports.SourcePayload{}, Blobs: []exports.MaterialBlob{}}
	for _, spec := range []struct{ id, domain string }{{"account-controller", "block"}, {"account-model", "block"}, {"code-audit", "skill"}, {"code-check", "skill"}} {
		body := []byte("Declared public descriptive material.\n")
		path := "resources/" + spec.id + ".md"
		payload := exports.ExportPayload{APIVersion: exports.ExportPayloadAPIVersion, ExportID: spec.id, Files: []exports.PayloadFile{{SourcePath: path, TargetPath: "context/" + spec.id + ".md", Mode: "100644", ContentSHA256: d.Digest(body)}}, Slots: []exports.PayloadSlot{}, Blocks: []exports.PayloadBlock{}}
		raw, _ := json.Marshal(payload)
		entry := exports.ExportEntry{ID: spec.id, Domain: spec.domain, Name: spec.id, Version: "1.0.0", ContentDigest: d.Digest(raw), ToolDigest: d.Digest([]byte("readonly tool")), Parameters: []exports.ScalarParameter{}, Requires: []exports.ExportRequirement{}}
		catalog.Catalog.Exports = append(catalog.Catalog.Exports, entry)
		catalog.Payloads = append(catalog.Payloads, exports.SourcePayload{ExportID: spec.id, Raw: raw})
		catalog.Blobs = append(catalog.Blobs, exports.MaterialBlob{Path: path, Mode: "100644", Content: body})
	}
	candidate := d.Candidate{SourcePin: d.SourcePin{Qualification: "owner-supplied", SourceID: graph.Nodes[0].Key, Revision: pins[0].Commit, ContentSHA256: pins[0].ContentDigest}, MetadataSHA256: d.Digest([]byte("actual declared use-case metadata")), Name: "neutral-components", Version: "1.0.0", Description: "Declared component use cases", Labels: map[string][]string{"tags": {"entity", "сущность"}, "lang": {"go"}, "use-cases": {"Add entity", "Добавить сущность"}}, CandidateKind: d.KindTemplate, Readiness: d.Experimental, Blocks: []d.Reference{}, Skills: []d.Reference{}}
	selectors := map[string]string{}
	digests := map[string]string{}
	for _, entry := range catalog.Catalog.Exports {
		kind := d.KindContext
		if entry.Domain == "skill" {
			kind = d.KindSkill
		}
		ref := d.Reference{ID: entry.ID, SourcePin: exportPin(entry), CandidateKind: kind, Readiness: d.Unknown, DeclarationStatus: "metadata-declared", Availability: "metadata-declared"}
		joined, selector, resolvedDigest := joinReference(ref, catalog, "base", graph, []exports.Catalog{catalog.Catalog})
		if joined.Availability != "admitted-record" || selector == "" || joined.Provenance == nil || joined.Provenance.ContentSHA256 != entry.ContentDigest {
			t.Fatal("real typed record not joined", joined)
		}
		selectors[joined.ID] = selector
		digests[joined.ID] = resolvedDigest
		if entry.Domain == "block" {
			candidate.Blocks = append(candidate.Blocks, joined)
		} else {
			candidate.Skills = append(candidate.Skills, joined)
		}
	}
	candidate, err = d.Identify(candidate)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]d.ReadOnlyCall{}
	for id, selector := range selectors {
		calls[candidate.ID+"\x00"+id] = []d.ReadOnlyCall{admittedReadCall("/project", "root", "/input.json", selector, digests[id])}
	}
	for _, task := range []string{"Add entity", "Добавить сущность"} {
		result, e := d.Rank(d.Query{Task: task, Language: "go", MaxBytes: 2048}, []d.Candidate{candidate})
		if e != nil {
			t.Fatal(e)
		}
		result, e = fitAdmittedReadCalls(result, calls, 2048)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(result)
		if len(raw) > 2048 || len(result.Suggestions) != 1 || len(result.Suggestions[0].Blocks) != 1 || len(result.Suggestions[0].NextToolCalls) != 1 || !result.Budget.Truncated {
			t.Fatalf("representative lost despite fitting floor %s", raw)
		}
		s := result.Suggestions[0]
		ref := s.Blocks[0]
		call := s.NextToolCalls[0]
		if ref.CandidateKind != d.KindContext || ref.Readiness != d.Unknown || ref.Availability != "admitted-record" || call.Tool != "graph_exports" {
			t.Fatal("kind/readiness/availability changed", s)
		}
		selection := call.Arguments["selectors"].([]any)[0].(string)
		if selection != selectors[ref.ID] {
			t.Fatal("read call no longer refers to retained record", ref.ID, selection)
		}
		resolved, e := exports.ResolveSelections([]exports.Selection{{APIVersion: exports.SelectionAPIVersion, Selector: selection, Bindings: []exports.ScalarParameter{}}}, graph, []exports.Catalog{catalog.Catalog})
		if e != nil {
			t.Fatal("constructed real readonly selector not consumed", e)
		}
		if call.Arguments["expectedDigest"] != resolved.Digest || resolved.Digest != digests[ref.ID] {
			t.Fatal("followup digest not derived from original singleton owner graph", call)
		}
		longCalls := map[string][]d.ReadOnlyCall{}
		for key, list := range calls {
			item := admittedReadCall("/project", "root", strings.Repeat("p", 4096), list[0].Arguments["selectors"].([]string)[0], list[0].Arguments["expectedDigest"].(string))
			longCalls[key] = []d.ReadOnlyCall{item}
		}
		if _, longErr := fitAdmittedReadCalls(result, longCalls, 2048); !errors.Is(longErr, ErrOutputBudget) {
			t.Fatal("long read call must refuse finite output budget", longErr)
		}
		// Escaped presentation maps cannot mutate the owner's retained call map.
		call.Arguments["selectors"].([]any)[0] = "invented.block.other"
		again, e := fitAdmittedReadCalls(result, calls, 2048)
		if e != nil || again.Suggestions[0].NextToolCalls[0].Arguments["selectors"].([]any)[0] != selectors[ref.ID] {
			t.Fatal("caller data aliased retained owner call map", e)
		}
	}
}
