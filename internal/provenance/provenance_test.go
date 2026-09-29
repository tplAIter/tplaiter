package provenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	js "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func fixtureProfile() bootstrap.ProfileBinding {
	return bootstrap.ProfileBinding{APIVersion: bootstrap.ProfileBindingAPIVersion, ID: bootstrap.ProfileOSS, DefinitionVersion: 1, ConfigSHA256: d('a'), PolicySHA256: d('b'), AuthoritySHA256: d('c'), Assurance: bootstrap.PublisherVerified, EvidenceClass: bootstrap.EvidenceProduction}
}
func d(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }
func fixtureRoot() RootTemplateLock {
	v := RootTemplateLock{APIVersion: RootTemplateLockAPIVersion, Kind: RootTemplateLockKind, TrustProfile: fixtureProfile(), Policy: PolicyBinding{PolicySHA256: d('b')}, Root: RootSubject{Origin: "https://example.test/templates", TemplatePath: "base", RequestedRef: "refs/tags/v1", Commit: strings.Repeat("a", 40), TreeSHA256: d('1'), ContractSHA256: d('2'), StatementCAS: d('3'), SignatureCAS: d('4'), KeyFingerprint: d('5'), CheckpointCAS: d('6'), InclusionProofCAS: d('7')}, Renderer: RendererIdentity{Name: "go-text-template", Version: "v2"}}
	v.RootLockSHA256, _ = ComputeRootLockSHA256(v)
	if v.RootLockSHA256 != "sha256:0fdf1f81a9dd8a7ae8474a1ec5a63d47e395c6e1217e3cf8af0da9f5ca2efab1" {
		panic(v.RootLockSHA256)
	}
	return v
}

func TestRootAndEmptyTemplateLockRoundTrip(t *testing.T) {
	r := fixtureRoot()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRootTemplateLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootLockSHA256 != r.RootLockSHA256 {
		t.Fatalf("root digest changed: %s", got.RootLockSHA256)
	}
	tpl := TemplateLock{APIVersion: TemplateLockAPIVersion, Kind: DependencyExportLockKind, TrustProfile: r.TrustProfile, RootLockSHA256: r.RootLockSHA256, Dependencies: []DependencySubject{}, LockSHA256: ""}
	tpl.LockSHA256, err = ComputeTemplateLockSHA256(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if tpl.LockSHA256 != "sha256:67971d9157204868cb3b641c0e06034eb64dd9b7fc888ec343c61149f5e6e033" {
		panic(tpl.LockSHA256)
	}
	if _, err = DecodeTemplateLock(mustJSON(t, tpl)); err != nil {
		t.Fatal(err)
	}
}

func TestClosedModelsRejectUnknownMissingNullDuplicateAndWrongDigest(t *testing.T) {
	raw := mustJSON(t, fixtureRoot())
	for name, mutate := range map[string]func(string) string{
		"unknown": func(s string) string { return strings.Replace(s, "}", ",\"extra\":1}", 1) },
		"missing": func(s string) string { return strings.Replace(s, "\"kind\":\"RootTemplateLock\",", "", 1) },
		"null": func(s string) string {
			return strings.Replace(s, "\"renderer\":{", "\"renderer\":null,\"unused\":{", 1)
		},
		"wrong-digest": func(s string) string { return strings.Replace(s, "sha256:", "sha257:", 1) },
	} {
		if _, err := DecodeRootTemplateLock([]byte(mutate(string(raw)))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dup := strings.Replace(string(raw), "{\"apiVersion\":", "{\"apiVersion\":\"x\",\"apiVersion\":", 1)
	if _, err := DecodeRootTemplateLock([]byte(dup)); err == nil {
		t.Error("duplicate field accepted")
	}
}

func TestStableV2ConsumersClassifyProfilelessV1(t *testing.T) {
	cases := []struct {
		name    string
		fixture func() map[string]any
		decode  func([]byte) error
	}{
		{"root", legacyRootV1Fixture, func(raw []byte) error { _, err := DecodeRootTemplateLock(raw); return err }},
		{"template", legacyTemplateV1Fixture, func(raw []byte) error { _, err := DecodeTemplateLock(raw); return err }},
		{"dependency alias", legacyTemplateV1Fixture, func(raw []byte) error { _, err := DecodeDependencyExportLock(raw); return err }},
		{"plan", legacyUpdatePlanV1Fixture, func(raw []byte) error { _, err := DecodeUpdatePlan(raw); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustJSON(t, tc.fixture())
			before := append([]byte(nil), raw...)
			err := tc.decode(raw)
			if !errors.Is(err, ErrLegacyUnbound) || err.Error() != string(trustverify.TrustLegacyUnbound) {
				t.Fatalf("error = %v, want exact %s", err, trustverify.TrustLegacyUnbound)
			}
			if !bytes.Equal(raw, before) {
				t.Fatal("legacy input bytes were modified")
			}
			for name, malformed := range map[string][]byte{
				"missing required member": []byte(`{"apiVersion":"` + tc.fixture()["apiVersion"].(string) + `"}`),
				"duplicate member":        []byte(strings.Replace(string(raw), `{"apiVersion":`, `{"apiVersion":"`+tc.fixture()["apiVersion"].(string)+`","apiVersion":`, 1)),
				"v2 missing profile":      []byte(strings.Replace(string(raw), tc.fixture()["apiVersion"].(string), v2VersionForLegacy(tc.name), 1)),
			} {
				t.Run(name, func(t *testing.T) {
					err := tc.decode(malformed)
					if errors.Is(err, ErrLegacyUnbound) {
						t.Fatalf("%s was falsely classified as legacy", name)
					}
				})
			}
		})
	}
}

func v2VersionForLegacy(name string) string {
	switch name {
	case "root":
		return RootTemplateLockAPIVersion
	case "template", "dependency alias":
		return TemplateLockAPIVersion
	default:
		return UpdatePlanAPIVersion
	}
}

func legacyDigestEvidence() map[string]any { return map[string]any{"schema": 1, "sha256": d('a')} }

func legacyVerificationFixture() map[string]any {
	return map[string]any{
		"policyDigest": d('a'),
		"subject":      map[string]any{"commit": strings.Repeat("a", 40), "treeSHA256": d('a')},
		"evidence": []any{map[string]any{
			"type": "git-tag-signature", "signedObjectOID": strings.Repeat("a", 40), "signatureDigest": d('a'), "evidenceCAS": d('a'), "keyFingerprint": "neutral-key", "issuer": "neutral-issuer", "transparencyURI": "https://example.invalid/proof", "inclusionProofCAS": d('a'), "checkpointDigest": d('a'), "verifiedAt": "2026-01-01T00:00:00Z",
		}},
	}
}

func legacyRootV1Fixture() map[string]any {
	return map[string]any{
		"apiVersion": "tplater.dev/root-template-lock/v1", "kind": "RootTemplateLock", "rootLockSHA256": d('a'),
		"policy":   map[string]any{"source": "https://example.invalid/policy", "requestedRef": "v1", "resolvedCommit": strings.Repeat("a", 40), "digest": d('a')},
		"root":     map[string]any{"source": "https://example.invalid/template", "template": "neutral", "requestedRef": "v1", "resolvedCommit": strings.Repeat("a", 40), "treeSHA256": d('a'), "contractSHA256": d('a'), "verification": legacyVerificationFixture()},
		"renderer": map[string]any{"name": "neutral-renderer", "version": "v1"},
	}
}

func legacyTemplateV1Fixture() map[string]any {
	return map[string]any{
		"apiVersion": "tplater.dev/template-lock/v1", "kind": "DependencyExportLock", "rootLockSHA256": d('a'), "lockSHA256": d('a'),
		"dependencies": []any{map[string]any{"alias": "neutral", "source": "https://example.invalid/template", "requestedRef": "v1", "resolvedCommit": strings.Repeat("a", 40), "treeSHA256": d('a'), "exports": []any{"default"}, "verification": legacyVerificationFixture()}},
	}
}

func legacyUpdatePlanV1Fixture() map[string]any {
	ref := func(name string) map[string]any {
		return map[string]any{"schema": 1, "ref": name + "/v1", "sha256": d('a')}
	}
	document := map[string]any{
		"project": map[string]any{"schema": 1, "id": "neutral-project", "sha256": d('a')}, "git": map[string]any{"schema": 1, "head": strings.Repeat("a", 40), "sha256": d('a')},
		"index": legacyDigestEvidence(), "tracked": legacyDigestEvidence(), "untracked": legacyDigestEvidence(), "ledgers": legacyDigestEvidence(),
		"policy": ref("policy"), "inventory": ref("inventory"), "orchestrator": ref("orchestrator"), "bootstrap": map[string]any{"schema": 1, "id": "neutral-bootstrap", "sha256": d('a')},
		"rootLock": map[string]any{"schema": 1, "ref": "v1", "commit": strings.Repeat("a", 40), "sha256": d('a')}, "dependencyLock": legacyDigestEvidence(), "formatter": legacyDigestEvidence(), "migrations": legacyDigestEvidence(), "hooks": legacyDigestEvidence(),
	}
	return map[string]any{"apiVersion": "tplater.dev/update-plan/v1", "kind": "UpdatePlan", "schema": 1, "createdAt": "2026-01-01T00:00:00Z", "document": document, "lifecycle": map[string]any{"migrations": []any{}, "hooks": []any{}}, "mutations": []any{}, "planSHA256": d('a')}
}

func TestSealDomainsDiffer(t *testing.T) {
	r := fixtureRoot()
	a, err := ComputeRootLockSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.APIVersion = TemplateLockAPIVersion
	b, err := ComputeRootLockSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("domain replay produced same digest")
	}
}

func TestLockPairRejectsBindingMismatches(t *testing.T) {
	root := fixtureRoot()
	dep := TemplateLock{APIVersion: TemplateLockAPIVersion, Kind: DependencyExportLockKind, TrustProfile: root.TrustProfile, RootLockSHA256: root.RootLockSHA256, Dependencies: []DependencySubject{}}
	dep.LockSHA256, _ = ComputeTemplateLockSHA256(dep)
	if err := ValidateLockPair(root, dep); err != nil {
		t.Fatal(err)
	}
	checks := []func(*bootstrap.ProfileBinding){func(p *bootstrap.ProfileBinding) {
		p.ID = bootstrap.ProfileDevelopment
		p.Assurance = bootstrap.DevelopmentUnverified
	}, func(p *bootstrap.ProfileBinding) { p.ConfigSHA256 = d('8') }, func(p *bootstrap.ProfileBinding) { p.PolicySHA256 = d('8') }, func(p *bootstrap.ProfileBinding) { p.AuthoritySHA256 = d('8') }, func(p *bootstrap.ProfileBinding) { p.Assurance = bootstrap.OrganizationProtected }, func(p *bootstrap.ProfileBinding) { p.EvidenceClass = bootstrap.EvidenceSimulated }}
	for i, mutate := range checks {
		bad := dep
		bad.TrustProfile = root.TrustProfile
		mutate(&bad.TrustProfile)
		bad.LockSHA256, _ = ComputeTemplateLockSHA256(bad)
		if err := ValidateLockPair(root, bad); err == nil {
			t.Fatalf("profile mismatch %d accepted", i)
		}
	}
	bad := dep
	bad.RootLockSHA256 = d('f')
	bad.LockSHA256, _ = ComputeTemplateLockSHA256(bad)
	if err := ValidateLockPair(root, bad); err == nil {
		t.Fatal("root digest mismatch accepted")
	}
}

func TestV2SchemaParityOracle(t *testing.T) {
	c := js.NewCompiler()
	loader := schemaMapLoader{docs: map[string]any{}}
	for name, id := range map[string]string{"../../schema/trust-profile-binding.v1.schema.json": "https://schemas.invalid/trust-profile-binding.v1.schema.json", "../../schema/root-template-lock.v2.schema.json": "https://schemas.invalid/root-template-lock.v2.schema.json", "../../schema/template-lock.v2.schema.json": "https://schemas.invalid/template-lock.v2.schema.json"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		delete(obj, "$id")
		delete(obj, "$schema")
		rewriteSchemaRefs(obj)
		normalized, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := js.UnmarshalJSON(strings.NewReader(string(normalized)))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatal(err)
		}
		var normalizedDoc any
		if err := json.Unmarshal(normalized, &normalizedDoc); err != nil {
			t.Fatal(err)
		}
		loader.docs[id] = normalizedDoc
	}
	rootSchema, err := c.Compile("../../schema/root-template-lock.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	tplSchema, err := c.Compile("../../schema/template-lock.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	root := fixtureRoot()
	check := func(s *js.Schema, v any) {
		b := mustJSON(t, v)
		var x any
		if err := json.Unmarshal(b, &x); err != nil {
			t.Fatal(err)
		}
		if err := s.Validate(x); err != nil {
			t.Fatal(err)
		}
	}
	check(rootSchema, root)
	tpl := TemplateLock{APIVersion: TemplateLockAPIVersion, Kind: DependencyExportLockKind, TrustProfile: root.TrustProfile, RootLockSHA256: root.RootLockSHA256, Dependencies: []DependencySubject{}}
	tpl.LockSHA256, err = ComputeTemplateLockSHA256(tpl)
	if err != nil {
		t.Fatal(err)
	}
	check(tplSchema, tpl)
	rootMap := func() map[string]any { var x map[string]any; _ = json.Unmarshal(mustJSON(t, root), &x); return x }
	badRoot := rootMap()
	badRoot["root"].(map[string]any)["templatePath"] = "nested/../escape"
	if schemaAccepts(rootSchema, badRoot) {
		t.Fatal("root traversal accepted by schema")
	}
	badRoot = rootMap()
	badRoot["trustProfile"].(map[string]any)["assurance"] = "development-unverified"
	if schemaAccepts(rootSchema, badRoot) {
		t.Fatal("root profile mismatch accepted by schema")
	}
	badRoot = rootMap()
	badRoot["root"].(map[string]any)["templatePath"] = "base\x00escape"
	if schemaAccepts(rootSchema, badRoot) {
		t.Fatal("root control path accepted by schema")
	}
	controlled := root
	controlled.Root.TemplatePath = "base\x00escape"
	controlled.RootLockSHA256, _ = ComputeRootLockSHA256(controlled)
	if controlled.Validate() == nil {
		t.Fatal("root control path accepted by Go validation")
	}
	// Draft 2020 receives parsed JSON values and therefore cannot distinguish
	// lexical 1 from 1.0. The strict Go decoder remains the raw-wire layer.
	numericRoot := strings.Replace(string(mustJSON(t, root)), `"definitionVersion":1`, `"definitionVersion":1.0`, 1)
	var parsedNumericRoot any
	if err := json.Unmarshal([]byte(numericRoot), &parsedNumericRoot); err != nil {
		t.Fatal(err)
	}
	if !schemaAccepts(rootSchema, parsedNumericRoot) {
		t.Fatal("schema unexpectedly rejected parsed 1.0")
	}
	if _, err := DecodeRootTemplateLock([]byte(numericRoot)); err == nil {
		t.Fatal("strict Go decoder accepted lexical 1.0")
	}
	withDependency := tpl
	withDependency.Dependencies = []DependencySubject{root.Root.dependency()}
	withDependency.LockSHA256, err = ComputeTemplateLockSHA256(withDependency)
	if err != nil {
		t.Fatal(err)
	}
	var templateMap map[string]any
	if err := json.Unmarshal(mustJSON(t, withDependency), &templateMap); err != nil {
		t.Fatal(err)
	}
	templateMap["dependencies"].([]any)[0].(map[string]any)["templatePath"] = "base\x00escape"
	if schemaAccepts(tplSchema, templateMap) {
		t.Fatal("dependency control path accepted by schema")
	}
	controlledDependency := withDependency
	controlledDependency.Dependencies = append([]DependencySubject(nil), withDependency.Dependencies...)
	controlledDependency.Dependencies[0].TemplatePath = "base\x00escape"
	controlledDependency.LockSHA256, _ = ComputeTemplateLockSHA256(controlledDependency)
	if controlledDependency.Validate() == nil {
		t.Fatal("dependency control path accepted by Go validation")
	}
	badTpl := map[string]any{}
	_ = json.Unmarshal(mustJSON(t, tpl), &badTpl)
	badTpl["dependencies"] = []any{map[string]any{"origin": "bad origin!"}}
	if schemaAccepts(tplSchema, badTpl) {
		t.Fatal("dependency token violation accepted by schema")
	}
	badTpl = map[string]any{}
	_ = json.Unmarshal(mustJSON(t, tpl), &badTpl)
	badTpl["dependencies"] = make([]any, 4097)
	if schemaAccepts(tplSchema, badTpl) {
		t.Fatal("dependency cardinality violation accepted by schema")
	}
}

func schemaAccepts(s *js.Schema, v any) bool { return s.Validate(v) == nil }

func TestRootSubjectValidateUsesSealedRootBoundary(t *testing.T) {
	subject := fixtureRoot().Root
	if err := subject.Validate(); err != nil {
		t.Fatalf("valid root subject rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RootSubject){
		"non-hex commit":        func(s *RootSubject) { s.Commit = strings.Repeat("g", 40) },
		"invalid origin":        func(s *RootSubject) { s.Origin = "bad origin" },
		"invalid requested ref": func(s *RootSubject) { s.RequestedRef = "bad ref" },
		"backslash path":        func(s *RootSubject) { s.TemplatePath = `a\\b` },
		"control path":          func(s *RootSubject) { s.TemplatePath = "a\x00b" },
	} {
		t.Run(name, func(t *testing.T) {
			got := subject
			mutate(&got)
			if got.Validate() == nil {
				t.Fatal("hostile root subject accepted")
			}
		})
	}
}

type schemaMapLoader struct{ docs map[string]any }

func (l schemaMapLoader) Load(url string) (any, error) {
	if v, ok := l.docs[url]; ok {
		return v, nil
	}
	for key, v := range l.docs {
		if strings.Contains(url, "root-template-lock-v2") && strings.Contains(key, "root-template-lock-v2") {
			return v, nil
		}
		if strings.Contains(url, "template-lock-v2") && !strings.Contains(url, "root-template-lock-v2") && strings.Contains(key, "template-lock-v2") {
			return v, nil
		}
		if strings.Contains(url, "trust-profile-binding") && strings.Contains(key, "trust-profile-binding") {
			return v, nil
		}
	}
	for key, v := range l.docs {
		if strings.HasSuffix(url, "/"+strings.TrimPrefix(key, "https://schemas.invalid/")) || strings.HasSuffix(url, strings.TrimPrefix(key, "https://schemas.invalid/")) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("schema oracle: unknown %s", url)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rewriteSchemaRefs(v any) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			switch ref {
			case "trust-profile-binding.v1.schema.json":
				x["$ref"] = "https://schemas.invalid/trust-profile-binding.v1.schema.json"
			case "root-template-lock.v2.schema.json#/$defs/subject":
				x["$ref"] = "https://schemas.invalid/root-template-lock.v2.schema.json#/$defs/subject"
			}
		}
		for _, child := range x {
			rewriteSchemaRefs(child)
		}
	case []any:
		for _, child := range x {
			rewriteSchemaRefs(child)
		}
	}
}
