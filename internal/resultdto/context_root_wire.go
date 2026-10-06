package resultdto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
)

const ContextRootV2 = "tplaiter.dev/context-root-selection/v2"
const ContextRootV3 = "tplaiter.dev/context-root-selection/v3"
const RootReceiptV3 = "tplaiter.dev/context-root-delivery-receipt/v3"

const RootReceiptV2 = "tplaiter.dev/context-root-delivery-receipt/v2"

// RootDeliveryReceiptV2 records complete local consumption, not source authority.
type RootDeliveryReceiptV2 struct {
	APIVersion   string `json:"apiVersion"`
	BodySHA256   string `json:"bodySHA256"`
	PacketSHA256 string `json:"packetSHA256"`
	GuardSHA256  string `json:"guardSHA256"`
	ImagesSHA256 string `json:"imagesSHA256"`
	FileCount    int    `json:"fileCount"`
}

// The public type remains a complete logical body. Only explicitly versioned
// ROOT version branches factor the packet. Ordinary v1 serialization is unchanged.
func (b RootContextBody) MarshalJSON() ([]byte, error) {
	type plain RootContextBody
	if b.APIVersion == ContextRootV3 {
		return marshalRootV3(b)
	}
	if b.APIVersion != ContextRootV2 {
		return json.Marshal(plain(b))
	}
	facts, e := contextindex.EncodeRootFactsV2(b.Packet)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(plain(b))
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	fields["packet"], e = json.Marshal(facts)
	if e != nil {
		return nil, e
	}
	return json.Marshal(fields)
}
func (b *RootContextBody) UnmarshalJSON(raw []byte) error {
	type plain RootContextBody
	var tag struct {
		APIVersion string `json:"apiVersion"`
	}
	if e := json.Unmarshal(raw, &tag); e != nil {
		return e
	}
	if tag.APIVersion == ContextRootV3 {
		return unmarshalRootV3(b, raw)
	}
	if tag.APIVersion != ContextRootV2 {
		var out plain
		if e := json.Unmarshal(raw, &out); e != nil {
			return e
		}
		*b = RootContextBody(out)
		return nil
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	p, e := contextindex.DecodeRootFactsV2(fields["packet"])
	if e != nil {
		return e
	}
	fields["packet"], e = json.Marshal(p)
	if e != nil {
		return e
	}
	filesRaw, ok := fields["files"]
	if !ok {
		return fmt.Errorf("ROOT files missing")
	}
	delete(fields, "files")
	rebuilt, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	var out plain
	if e = canonicaljson.DecodeStrict(rebuilt, &out); e != nil {
		return e
	}
	var files []rootWireFile
	if e = canonicaljson.DecodeStrict(filesRaw, &files); e != nil {
		return e
	}
	if len(files) < 1 || len(files) > 256 {
		return fmt.Errorf("ROOT file count")
	}
	var rawFiles []map[string]json.RawMessage
	if e = json.Unmarshal(filesRaw, &rawFiles); e != nil {
		return e
	}
	for i, file := range files {
		if len(rawFiles[i]) != 7 {
			return fmt.Errorf("ROOT file fields")
		}
		if file.SelectedIdentity == "" || file.ExportID == "" || (file.Mode != "100644" && file.Mode != "100755") || exports.ValidatePortablePath(file.SourcePath) != nil || exports.ValidatePortablePath(file.TargetPath) != nil {
			return fmt.Errorf("ROOT file identity")
		}
		content, e := base64.StdEncoding.Strict().DecodeString(file.Content)
		if e != nil || base64.StdEncoding.EncodeToString(content) != file.Content || evidencecas.Digest(content) != file.ContentSHA256 {
			return fmt.Errorf("ROOT file content")
		}
		out.Files = append(out.Files, RootContextFile{file.SelectedIdentity, file.ExportID, file.SourcePath, file.TargetPath, file.Mode, file.ContentSHA256, content})
	}
	fields["files"] = filesRaw
	// Require every ROOT body key, including zero-valued observations.
	var required map[string]json.RawMessage
	all, _ := json.Marshal(plain(out))
	_ = json.Unmarshal(all, &required)
	if len(required) != len(fields) {
		return fmt.Errorf("ROOT v2 body fields")
	}
	for k := range required {
		if _, ok := fields[k]; !ok {
			return fmt.Errorf("ROOT v2 body missing %s", k)
		}
	}
	*b = RootContextBody(out)
	return nil
}

// RootGuardV2 carries full images and metadata, with the packet supplied once by
// the owned C04 selection. It is not a valid standalone public ROOT result.
func RootGuardV2(b RootContextBody) ([]byte, error) {
	type plain RootContextBody
	b.Packet = contextindex.Packet{}
	return json.Marshal(plain(b))
}
func DecodeRootGuardV2(raw []byte) (RootContextBody, error) {
	type plain RootContextBody
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return RootContextBody{}, e
	}
	var b plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&b); e != nil {
		return RootContextBody{}, e
	}
	if b.APIVersion != ContextRootV2 {
		return RootContextBody{}, fmt.Errorf("ROOT guard version")
	}
	p, _ := json.Marshal(b.Packet)
	zero, _ := json.Marshal(contextindex.Packet{})
	if string(p) != string(zero) {
		return RootContextBody{}, fmt.Errorf("ROOT guard packet")
	}
	return RootContextBody(b), nil
}

// ContextRootV2Schema is the standalone closed schema consumed by the on-demand
// registered context schema. Its file is generated and checked against this API.
func ContextRootV2Schema() ([]byte, error) {
	body, e := jsonschema.For[RootContextBody](nil)
	if e != nil {
		return nil, e
	}
	facts, e := jsonschema.For[contextindex.RootFactsV2](nil)
	if e != nil {
		return nil, e
	}
	receipt, e := jsonschema.For[RootDeliveryReceiptV2](nil)
	if e != nil {
		return nil, e
	}
	var b, f, r map[string]any
	for _, v := range []struct {
		schema *jsonschema.Schema
		dst    *map[string]any
	}{{body, &b}, {facts, &f}, {receipt, &r}} {
		raw, e := json.Marshal(v.schema)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, v.dst); e != nil {
			return nil, e
		}
	}
	props := b["properties"].(map[string]any)
	props["apiVersion"] = map[string]any{"const": ContextRootV2}
	props["packet"] = f
	f["properties"].(map[string]any)["apiVersion"] = map[string]any{"const": contextindex.RootFactsAPIVersion}
	props["files"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["content"] = map[string]any{"type": "string", "contentEncoding": "base64"}
	r["properties"].(map[string]any)["apiVersion"] = map[string]any{"const": RootReceiptV2}
	b["$id"] = "https://tplaiter.dev/schema/context-root-selection.v2.schema.json"
	b["$defs"] = map[string]any{"deliveryReceipt": r}
	return json.MarshalIndent(b, "", "  ")
}

type rootWireFile struct {
	SelectedIdentity string `json:"selectedIdentity"`
	ExportID         string `json:"exportID"`
	SourcePath       string `json:"sourcePath"`
	TargetPath       string `json:"targetPath"`
	Mode             string `json:"mode"`
	ContentSHA256    string `json:"contentSHA256"`
	Content          string `json:"content"`
}

// RootDeliveryReceiptV3 has measured consumption fields and grants no authority.
type RootDeliveryReceiptV3 RootDeliveryReceiptV2

func marshalRootV3(b RootContextBody) ([]byte, error) {
	type plain RootContextBody
	if b.APIVersion != ContextRootV3 {
		return json.Marshal(plain(b))
	}
	if b.Selections == nil || b.Graph.Selected == nil || b.Graph.Edges == nil {
		return nil, fmt.Errorf("ROOT v3 collections")
	}
	if e := sourceImagesV3(b.Files); e != nil {
		return nil, e
	}
	facts, e := contextindex.EncodeSourceFactsV3(b.Packet)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(plain(b))
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	fields["packet"], e = json.Marshal(facts)
	if e != nil {
		return nil, e
	}
	raw, e = json.Marshal(fields)
	if e == nil && len(raw) > 32768 {
		return nil, fmt.Errorf("ROOT v3 body budget")
	}
	return raw, e
}
func unmarshalRootV3(b *RootContextBody, raw []byte) error {
	if len(raw) == 0 || len(raw) > 32768 {
		return fmt.Errorf("ROOT v3 body budget")
	}
	type plain RootContextBody
	var tag struct {
		APIVersion string `json:"apiVersion"`
	}
	if e := json.Unmarshal(raw, &tag); e != nil {
		return e
	}
	if tag.APIVersion != ContextRootV3 {
		var out plain
		if e := json.Unmarshal(raw, &out); e != nil {
			return e
		}
		*b = RootContextBody(out)
		return nil
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	p, e := contextindex.DecodeSourceFactsV3(fields["packet"])
	if e != nil {
		return e
	}
	fields["packet"], e = json.Marshal(p)
	if e != nil {
		return e
	}
	filesRaw, ok := fields["files"]
	if !ok {
		return fmt.Errorf("ROOT files missing")
	}
	delete(fields, "files")
	rebuilt, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	var out plain
	if e = canonicaljson.DecodeStrict(rebuilt, &out); e != nil {
		return e
	}
	var files []rootWireFile
	if e = canonicaljson.DecodeStrict(filesRaw, &files); e != nil {
		return e
	}
	if len(files) < 1 || len(files) > 256 {
		return fmt.Errorf("ROOT file count")
	}
	var rawFiles []map[string]json.RawMessage
	if e = json.Unmarshal(filesRaw, &rawFiles); e != nil {
		return e
	}
	for i, file := range files {
		if len(rawFiles[i]) != 7 {
			return fmt.Errorf("ROOT file fields")
		}
		if file.SelectedIdentity == "" || file.ExportID == "" || (file.Mode != "100644" && file.Mode != "100755") || exports.ValidatePortablePath(file.SourcePath) != nil || exports.ValidatePortablePath(file.TargetPath) != nil {
			return fmt.Errorf("ROOT file identity")
		}
		content, e := base64.StdEncoding.Strict().DecodeString(file.Content)
		if e != nil || base64.StdEncoding.EncodeToString(content) != file.Content || evidencecas.Digest(content) != file.ContentSHA256 {
			return fmt.Errorf("ROOT file content")
		}
		out.Files = append(out.Files, RootContextFile{file.SelectedIdentity, file.ExportID, file.SourcePath, file.TargetPath, file.Mode, file.ContentSHA256, content})
	}
	fields["files"] = filesRaw
	closedRaw, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	if e = sourceBodyKeysV3(closedRaw, reflect.TypeFor[plain]()); e != nil {
		return e
	}
	// Require every ROOT body key, including zero-valued observations.
	var required map[string]json.RawMessage
	all, _ := json.Marshal(plain(out))
	_ = json.Unmarshal(all, &required)
	if len(required) != len(fields) {
		return fmt.Errorf("ROOT v3 body fields")
	}
	for k := range required {
		if _, ok := fields[k]; !ok {
			return fmt.Errorf("ROOT v3 body missing %s", k)
		}
	}
	if out.Selections == nil || out.Graph.Selected == nil || out.Graph.Edges == nil {
		return fmt.Errorf("ROOT v3 collections")
	}
	if e = sourceImagesV3(out.Files); e != nil {
		return e
	}
	*b = RootContextBody(out)
	return nil
}

func RootGuardV3(b RootContextBody) ([]byte, error) {
	if b.APIVersion != ContextRootV3 {
		return nil, fmt.Errorf("ROOT guard version")
	}
	if e := sourceImagesV3(b.Files); e != nil {
		return nil, e
	}
	type plain RootContextBody
	b.Packet = contextindex.Packet{}
	raw, e := json.Marshal(plain(b))
	if e == nil && len(raw) > 32768 {
		return nil, fmt.Errorf("ROOT guard budget")
	}
	return raw, e
}
func DecodeRootGuardV3(raw []byte) (RootContextBody, error) {
	if len(raw) == 0 || len(raw) > 32768 {
		return RootContextBody{}, fmt.Errorf("ROOT guard budget")
	}
	type plain RootContextBody
	if e := sourceBodyKeysV3(raw, reflect.TypeFor[plain]()); e != nil {
		return RootContextBody{}, e
	}
	if _, e := canonicaljson.Canonicalize(raw); e != nil {
		return RootContextBody{}, e
	}
	var b plain
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(&b); e != nil {
		return RootContextBody{}, e
	}
	if b.APIVersion != ContextRootV3 {
		return RootContextBody{}, fmt.Errorf("ROOT guard version")
	}
	p, _ := json.Marshal(b.Packet)
	zero, _ := json.Marshal(contextindex.Packet{})
	if string(p) != string(zero) {
		return RootContextBody{}, fmt.Errorf("ROOT guard packet")
	}
	if e := sourceImagesV3(b.Files); e != nil {
		return RootContextBody{}, e
	}
	return RootContextBody(b), nil
}

func ContextRootV3Schema() ([]byte, error) {
	body, e := jsonschema.For[RootContextBody](nil)
	if e != nil {
		return nil, e
	}
	facts, e := jsonschema.For[contextindex.SourceFactsV3](nil)
	if e != nil {
		return nil, e
	}
	receipt, e := jsonschema.For[RootDeliveryReceiptV3](nil)
	if e != nil {
		return nil, e
	}
	var b, f, r map[string]any
	for _, v := range []struct {
		schema *jsonschema.Schema
		dst    *map[string]any
	}{{body, &b}, {facts, &f}, {receipt, &r}} {
		raw, e := json.Marshal(v.schema)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, v.dst); e != nil {
			return nil, e
		}
	}
	props := b["properties"].(map[string]any)
	props["apiVersion"] = map[string]any{"const": ContextRootV3}
	props["packet"] = f
	f["properties"].(map[string]any)["apiVersion"] = map[string]any{"const": contextindex.SourceFactsAPIVersion}
	props["files"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["content"] = map[string]any{"type": "string", "contentEncoding": "base64"}
	r["properties"].(map[string]any)["apiVersion"] = map[string]any{"const": RootReceiptV3}
	b["$id"] = "https://tplaiter.dev/schema/context-root-selection.v3.schema.json"
	b["$defs"] = map[string]any{"deliveryReceipt": r}
	fp := f["properties"].(map[string]any)
	boundArray := func(p map[string]any, key string, lo, hi int) {
		a := p[key].(map[string]any)
		a["type"] = "array"
		a["minItems"] = lo
		a["maxItems"] = hi
	}
	boundArray(fp, "descriptorDefaults", 2, 32)
	boundArray(fp, "records", 2, 32)
	boundArray(fp, "exports", 0, 32)
	boundArray(fp, "relations", 0, 256)
	boundArray(fp, "relationFacts", 0, 256)
	fp["logicalSHA256"] = map[string]any{"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
	rp := fp["records"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	rp["defaultsRef"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 31}
	rp["line"] = map[string]any{"const": 1}
	rp["state"] = map[string]any{"const": "declared"}
	dp := rp["descriptor"].(map[string]any)["properties"].(map[string]any)
	dp["exportRef"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 31}
	dp["mode"] = map[string]any{"enum": []string{"100644", "100755"}}
	fp["relations"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["factRef"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 255}
	pp := fp["packet"].(map[string]any)["properties"].(map[string]any)
	boundArray(pp, "sources", 2, 32)
	boundArray(pp, "sourceEvidence", 2, 32)
	boundArray(pp, "excerpts", 2, 32)
	boundArray(pp, "requiredFloor", 4, 64)
	// The input request's required-ID ceiling remains 32. Its resulting floor
	// also includes up to 32 source anchors, as in unchanged C03 retrieval.
	pp["bytes"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 32768}
	boundArray(props, "files", 1, 256)
	return json.MarshalIndent(b, "", "  ")
}

func sourceImagesV3(files []RootContextFile) error {
	if len(files) < 1 || len(files) > 256 {
		return fmt.Errorf("ROOT v3 image count")
	}
	seen := map[string]bool{}
	for i, f := range files {
		identity, e := hex.DecodeString(strings.TrimPrefix(f.SelectedIdentity, "sha256:"))
		if e != nil || len(identity) != 32 || f.SelectedIdentity != "sha256:"+hex.EncodeToString(identity) || f.ExportID == "" || (f.Mode != "100644" && f.Mode != "100755") || exports.ValidatePortablePath(f.SourcePath) != nil || exports.ValidatePortablePath(f.TargetPath) != nil || evidencecas.Digest(f.Content) != f.ContentSHA256 {
			return fmt.Errorf("ROOT v3 image identity/content")
		}
		key := f.SelectedIdentity + "\x00" + f.TargetPath
		if seen[key] {
			return fmt.Errorf("ROOT v3 duplicate selected image")
		}
		seen[key] = true
		segments := strings.Split(f.TargetPath, "/")
		for _, prior := range files[:i] {
			parts := strings.Split(prior.TargetPath, "/")
			n := min(len(parts), len(segments))
			prefix := true
			for j := range n {
				if !strings.EqualFold(parts[j], segments[j]) {
					prefix = false
					break
				}
			}
			if prefix && (len(parts) != len(segments) || prior.TargetPath != f.TargetPath || prior.Mode != f.Mode || prior.ContentSHA256 != f.ContentSHA256) {
				return fmt.Errorf("ROOT v3 image topology")
			}
		}
	}
	return nil
}

// Required zero-valued observations cannot be supplied by decoder defaults.
func sourceBodyKeysV3(raw json.RawMessage, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if e := json.Unmarshal(raw, &values); e != nil {
			return e
		}
		for _, v := range values {
			if e := sourceBodyKeysV3(v, typ.Elem()); e != nil {
				return e
			}
		}
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if e := json.Unmarshal(raw, &fields); e != nil {
			return e
		}
		allowed := map[string]bool{}
		for i := range typ.NumField() {
			tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")
			if tag[0] != "" && tag[0] != "-" {
				allowed[tag[0]] = true
			}
		}
		for key := range fields {
			if !allowed[key] {
				return fmt.Errorf("ROOT v3 unknown %s", key)
			}
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "" || tag[0] == "-" {
				continue
			}
			v, ok := fields[tag[0]]
			if !ok {
				if strings.Contains(field.Tag.Get("json"), "omitempty") {
					continue
				}
				return fmt.Errorf("ROOT v3 missing %s", tag[0])
			}
			if e := sourceBodyKeysV3(v, field.Type); e != nil {
				return e
			}
		}
	}
	return nil
}
