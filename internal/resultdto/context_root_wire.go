package resultdto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/exports"
)

const ContextRootV2 = "tplaiter.dev/context-root-selection/v2"
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
// ROOT v2 JSON factors the packet. Ordinary v1 serialization is unchanged.
func (b RootContextBody) MarshalJSON() ([]byte, error) {
	type plain RootContextBody
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
