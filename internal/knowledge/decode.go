package knowledge

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
)

const (
	Invalid            = "KNOWLEDGE_INVALID"
	UnsupportedVersion = "KNOWLEDGE_VERSION_UNSUPPORTED"
	PinMismatch        = "KNOWLEDGE_PIN_MISMATCH"
	IncompletePin      = "KNOWLEDGE_PIN_INCOMPLETE"
	AmbiguousID        = "KNOWLEDGE_ID_AMBIGUOUS"
	Unresolved         = "KNOWLEDGE_UNRESOLVED"
	SourceMissing      = "KNOWLEDGE_SOURCE_MISSING"
	SourceStale        = "KNOWLEDGE_SOURCE_STALE"
	SourceMismatch     = "KNOWLEDGE_SOURCE_MISMATCH"
)

// Error is a typed protocol diagnostic. It never includes descriptor contents.
type Error struct{ Code, Path string }

func (e *Error) Error() string     { return e.Code + ": " + e.Path }
func fail(code, path string) error { return &Error{Code: code, Path: path} }

var (
	idRE     = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}:(block|skill|resource|source|catalog|owner|executor|quality):[a-z][a-z0-9._-]{0,63}$`)
	tokenRE  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	pathRE   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Decode rejects duplicate keys, unknown fields, disallowed nulls, missing fields, and
// unsupported versions before a descriptor can enter the knowledge graph.
func Decode(raw []byte) (Catalog, error) {
	var d Catalog
	if len(raw) > MaxBytes {
		return d, fail(Invalid, "byte limit")
	}
	// Parse the version envelope without interpreting a future major's fields.
	// The shared parser still rejects ambiguous keys/nulls/trailing input.
	var envelope map[string]json.RawMessage
	if err := versionEnvelope(raw, &envelope); err != nil {
		return Catalog{}, fail(Invalid, "wire shape")
	}
	var api string
	value, ok := envelope["apiVersion"]
	if !ok || json.Unmarshal(value, &api) != nil || api == "" {
		return Catalog{}, fail(Invalid, "apiVersion")
	}
	if api != APIVersion {
		return Catalog{}, fail(UnsupportedVersion, "apiVersion")
	}
	if err := decodeDescriptor(raw, &d); err != nil {
		return Catalog{}, fail(Invalid, "wire shape")
	}
	if err := required(raw, reflect.TypeFor[Catalog](), "document"); err != nil {
		return Catalog{}, err
	}
	if err := Validate(d); err != nil {
		return Catalog{}, err
	}
	return d, nil
}

func required(raw json.RawMessage, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Pointer {
		return required(raw, typ.Elem(), path)
	}
	switch typ.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return fail(Invalid, path)
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "" || name == "-" {
				continue
			}
			v, ok := obj[name]
			if !ok && len(tag) > 1 && tag[1] == "omitempty" {
				continue
			}
			if !ok {
				code := Invalid
				if strings.Contains(path, ".pin") || strings.Contains(path, ".anchor") {
					code = IncompletePin
				}
				return fail(code, path+"."+name)
			}
			if err := required(v, f.Type, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if typ == reflect.TypeFor[json.RawMessage]() {
			return nil
		}
		var xs []json.RawMessage
		if err := json.Unmarshal(raw, &xs); err != nil {
			return fail(Invalid, path)
		}
		for i, x := range xs {
			if err := required(x, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func version(s string) bool { _, err := semver.StrictNewVersion(s); return len(s) <= 128 && err == nil }

func idKind(id, kind string) bool { return idRE.MatchString(id) && strings.Split(id, ":")[1] == kind }
func state(s string) bool         { return s == "declared" || s == "static" || s == "unresolved" }
func safePath(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	if !pathRE.MatchString(s) || len(s) > 256 || strings.ContainsAny(s, "\\\x00\r\n\t") || strings.HasPrefix(s, "/") {
		return false
	}
	for _, c := range strings.Split(s, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}
func boundedJSON(v any) bool { raw, err := json.Marshal(v); return err == nil && len(raw) <= 4096 }

// Validate checks structural pins and references, not signatures or execution
// quality. Programmatically constructed descriptors face the same checks.
func Validate(d Catalog) error {
	if d.APIVersion != APIVersion {
		return fail(UnsupportedVersion, "apiVersion")
	}
	if d.Kind != "KnowledgeCatalog" || !idKind(d.ID, "catalog") || !version(d.Version) || len(d.Sources) == 0 || len(d.Sources) > 128 || len(d.Items) == 0 || len(d.Items) > 512 || d.Edges == nil || len(d.Edges) > 1024 {
		return fail(Invalid, "catalog")
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > MaxBytes {
		return fail(Invalid, "byte limit")
	}
	known := map[string]bool{}
	sources := map[string]Source{}
	aliases := map[string]bool{}
	add := func(id string) error {
		if known[id] {
			return fail(AmbiguousID, id)
		}
		known[id] = true
		return nil
	}
	for _, s := range d.Sources {
		if !idKind(s.ID, "source") || len(s.Pin.TemplatePath) > 256 || !boundedJSON(s) {
			return fail(Invalid, "source")
		}
		if err := add(s.ID); err != nil {
			return err
		}
		raw, err := json.Marshal(s.Pin)
		if err != nil {
			return fail(IncompletePin, s.ID)
		}
		if _, err := deps.DecodePinnedSource(raw); err != nil || s.Anchor.Validate() != nil {
			return fail(IncompletePin, s.ID)
		}
		p, a := s.Pin, s.Anchor
		if p.Origin != a.Origin || p.TemplatePath != a.TemplatePath || p.RequestedRef != a.RequestedRef || p.Commit != a.Commit || p.TreeDigest != a.TreeSHA256 || p.ContractDigest != a.ContractSHA256 {
			return fail(PinMismatch, s.ID)
		}
		if aliases[p.Alias] {
			return fail(AmbiguousID, s.ID)
		}
		aliases[p.Alias] = true
		sources[s.ID] = s
	}
	// A complete declared source closure reuses the existing source dependency
	// validator; these edges are never reclassified as workflow/package edges.
	pins := make([]deps.PinnedSource, 0, len(d.Sources))
	for _, s := range d.Sources {
		pins = append(pins, s.Pin)
	}
	if _, err := deps.BuildSourceGraph(pins); err != nil {
		return fail(IncompletePin, "source closure")
	}
	for _, it := range d.Items {
		if (it.Kind != "block" && it.Kind != "skill" && it.Kind != "resource") || !idKind(it.ID, it.Kind) || !version(it.Version) || sources[it.SourceID].ID == "" || !safePath(it.SourcePath) || !digestRE.MatchString(it.ContentSHA256) || (it.Mode != "100644" && it.Mode != "100755") || !boundedJSON(it) {
			return fail(Invalid, "item")
		}
		if err := add(it.ID); err != nil {
			return err
		}
		if !idKind(it.Ownership.OwnerID, "owner") || !version(it.Ownership.Version) || !digestRE.MatchString(it.Ownership.PolicySHA256) {
			return fail(Invalid, it.ID+".ownership")
		}
		if !idKind(it.Executor.ID, "executor") || !version(it.Executor.Version) || !digestRE.MatchString(it.Executor.InputContractSHA256) || !digestRE.MatchString(it.Executor.OutputContractSHA256) {
			return fail(Invalid, it.ID+".executor")
		}
		if it.Requires == nil || it.Produces == nil || len(it.Requires) > 16 || len(it.Produces) > 16 || it.UpdateTriggers == nil || len(it.UpdateTriggers) == 0 || len(it.UpdateTriggers) > 8 || it.Quality == nil || len(it.Quality) > 16 {
			return fail(Invalid, it.ID+".metadata")
		}
		triggers := map[string]bool{}
		for _, t := range it.UpdateTriggers {
			if !oneOf(t, "source", "contract", "content", "dependencies", "ownership", "version", "quality") || triggers[t] {
				return fail(Invalid, it.ID+".updateTriggers")
			}
			triggers[t] = true
		}
		quality := map[string]bool{}
		for _, q := range it.Quality {
			if !idKind(q.ID, "quality") || !version(q.Version) || !digestRE.MatchString(q.ContractSHA256) || !state(q.State) || quality[q.ID] {
				return fail(Invalid, it.ID+".quality")
			}
			quality[q.ID] = true
		}
		if it.Export != nil {
			s := sources[it.SourceID]
			g, err := deps.BuildSourceGraph([]deps.PinnedSource{withoutDependencies(s.Pin)})
			if err != nil {
				return fail(Invalid, it.ID+".export")
			}
			c := exports.Catalog{APIVersion: exports.CatalogAPIVersion, Provider: s.Pin.ProviderID, Source: g.Nodes[0].Key, ContractDigest: s.Pin.ContractDigest, Exports: []exports.ExportEntry{*it.Export}}
			if c.Validate() != nil || it.Version != it.Export.Version || it.Export.Parameters == nil || it.Export.Requires == nil {
				return fail(Invalid, it.ID+".export")
			}
			for _, requirement := range it.Export.Requires {
				if len(requirement.Selector) > 1024 {
					return fail(Invalid, it.ID+".export.requires")
				}
			}
		}
	}
	for _, it := range d.Items {
		if err := validateInputs(it.Inputs, it.ID); err != nil {
			return err
		}
		for _, refs := range [][]string{it.Requires, it.Produces, it.Inputs.ContextFloor} {
			seen := map[string]bool{}
			for _, ref := range refs {
				if !known[ref] || seen[ref] {
					return fail(AmbiguousID, it.ID+".reference")
				}
				seen[ref] = true
			}
		}
	}
	seenEdges := map[string]bool{}
	for _, e := range append(declaredEdges(d), d.Edges...) {
		key := e.From + "\x00" + e.To + "\x00" + e.Layer + ":" + e.Relation
		if !idRE.MatchString(e.From) || !idRE.MatchString(e.To) || !oneOf(e.Layer, "source", "export", "semantic", "workflow", "package") || !tokenRE.MatchString(e.Relation) || !state(e.State) || ((!known[e.From] || !known[e.To]) && e.State != "unresolved") {
			return fail(Invalid, "edge")
		}
		if seenEdges[key] {
			return fail(AmbiguousID, "edge")
		}
		seenEdges[key] = true
	}
	return nil
}

func oneOf(s string, xs ...string) bool {
	for _, x := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func withoutDependencies(p deps.PinnedSource) deps.PinnedSource {
	p.Dependencies = []string{}
	return p
}
