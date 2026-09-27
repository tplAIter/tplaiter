// Package blockformatter holds fixed adapter descriptors. Execution belongs to T6.
package blockformatter

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

//go:embed adapters/typescript.cjs
var typeScriptHelper []byte

const TypeScriptProviderAPIVersion = "tplaiter.dev/typescript-provider/v1"
const TypeScriptAdapterID = "prettier-typescript-standalone-v1"

type TypeScriptProviderFile struct {
	Path          string `json:"path"`
	Mode          string `json:"mode"`
	ContentSHA256 string `json:"contentSHA256"`
}
type TypeScriptFormatOptions struct {
	Parser                     string `json:"parser"`
	PrintWidth                 int    `json:"printWidth"`
	TabWidth                   int    `json:"tabWidth"`
	UseTabs                    bool   `json:"useTabs"`
	Semi                       bool   `json:"semi"`
	SingleQuote                bool   `json:"singleQuote"`
	QuoteProps                 string `json:"quoteProps"`
	JSXSingleQuote             bool   `json:"jsxSingleQuote"`
	TrailingComma              string `json:"trailingComma"`
	BracketSpacing             bool   `json:"bracketSpacing"`
	BracketSameLine            bool   `json:"bracketSameLine"`
	ArrowParens                string `json:"arrowParens"`
	EndOfLine                  string `json:"endOfLine"`
	EmbeddedLanguageFormatting string `json:"embeddedLanguageFormatting"`
	ProseWrap                  string `json:"proseWrap"`
	RequirePragma              bool   `json:"requirePragma"`
	InsertPragma               bool   `json:"insertPragma"`
}
type TypeScriptProvider struct {
	APIVersion          string                   `json:"apiVersion"`
	Adapter             string                   `json:"adapter"`
	PrettierVersion     string                   `json:"prettierVersion"`
	CompilerVersion     string                   `json:"compilerVersion"`
	EstreeVersion       string                   `json:"estreeVersion"`
	CommentUtilsVersion string                   `json:"commentUtilsVersion"`
	NodeVersion         string                   `json:"nodeVersion"`
	NodeBinarySHA256    string                   `json:"nodeBinarySHA256"`
	Files               []TypeScriptProviderFile `json:"files"`
	FormatOptions       TypeScriptFormatOptions  `json:"formatOptions"`
}

var tsDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var tsPath = regexp.MustCompile(`^(adapter/typescript\.cjs|tool/standalone\.cjs|tool/plugins/(estree|typescript)\.cjs)$`)
var tsNodeVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

func (p TypeScriptProvider) Validate() error {
	if p.APIVersion != TypeScriptProviderAPIVersion || p.Adapter != TypeScriptAdapterID || p.PrettierVersion != "3.9.6" || p.CompilerVersion != "6.0.3" || p.EstreeVersion != "8.65.0" || p.CommentUtilsVersion != "2.5.0" || !tsNodeVersion.MatchString(p.NodeVersion) || !tsDigest.MatchString(p.NodeBinarySHA256) || len(p.Files) != 4 {
		return fmt.Errorf("typescript provider: invalid descriptor")
	}
	want := []string{"adapter/typescript.cjs", "tool/plugins/estree.cjs", "tool/plugins/typescript.cjs", "tool/standalone.cjs"}
	for i, f := range p.Files {
		if f.Path != want[i] || !tsPath.MatchString(f.Path) || f.Mode != "100644" || !tsDigest.MatchString(f.ContentSHA256) {
			return fmt.Errorf("typescript provider: invalid files")
		}
	}
	o := p.FormatOptions
	if o.Parser != "typescript" || o.PrintWidth != 80 || o.TabWidth != 2 || o.UseTabs || !o.Semi || o.SingleQuote || o.JSXSingleQuote || o.BracketSameLine || o.RequirePragma || o.InsertPragma || o.QuoteProps != "as-needed" || o.TrailingComma != "all" || !o.BracketSpacing || o.ArrowParens != "always" || o.EndOfLine != "lf" || o.EmbeddedLanguageFormatting != "off" || o.ProseWrap != "preserve" {
		return fmt.Errorf("typescript provider: invalid fixed options")
	}
	return nil
}
func TypeScriptHelperSHA256() string {
	h := sha256.Sum256(typeScriptHelper)
	return "sha256:" + hex.EncodeToString(h[:])
}

// TypeScriptHelperBytes returns a defensive copy of the fixed embedded helper.
func TypeScriptHelperBytes() []byte { return append([]byte(nil), typeScriptHelper...) }

// DecodeTypeScriptProvider is the strict descriptor wire boundary. It rejects
// duplicate/unknown/missing fields, non-canonical bytes, trailing values and
// scalar type substitutions before projecting into the typed descriptor.
func DecodeTypeScriptProvider(raw []byte) (TypeScriptProvider, error) {
	if !utf8.Valid(raw) {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: invalid UTF-8")
	}
	if err := scanJSON(bytes.NewReader(raw)); err != nil {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: invalid JSON: %w", err)
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: invalid JSON: %w", err)
	}
	if err := requireEOF(dec); err != nil {
		return TypeScriptProvider{}, err
	}
	canonical, err := canonicalJSON(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: descriptor is not canonical")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: descriptor must be object")
	}
	if err := exactKeys(top, []string{"apiVersion", "adapter", "prettierVersion", "compilerVersion", "estreeVersion", "commentUtilsVersion", "nodeVersion", "nodeBinarySHA256", "files", "formatOptions"}); err != nil {
		return TypeScriptProvider{}, err
	}
	var p TypeScriptProvider
	if err := decodeField(top, "apiVersion", &p.APIVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "adapter", &p.Adapter); err != nil {
		return p, err
	}
	if err := decodeField(top, "prettierVersion", &p.PrettierVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "compilerVersion", &p.CompilerVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "estreeVersion", &p.EstreeVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "commentUtilsVersion", &p.CommentUtilsVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "nodeVersion", &p.NodeVersion); err != nil {
		return p, err
	}
	if err := decodeField(top, "nodeBinarySHA256", &p.NodeBinarySHA256); err != nil {
		return p, err
	}
	if err := decodeField(top, "files", &p.Files); err != nil {
		return p, err
	}
	if err := decodeField(top, "formatOptions", &p.FormatOptions); err != nil {
		return p, err
	}
	var fileWire []map[string]json.RawMessage
	if err := json.Unmarshal(rawField(top, "files"), &fileWire); err != nil || len(fileWire) != len(p.Files) {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: invalid files")
	}
	for _, m := range fileWire {
		if err := exactKeys(m, []string{"path", "mode", "contentSHA256"}); err != nil {
			return TypeScriptProvider{}, err
		}
	}
	var optionsWire map[string]json.RawMessage
	if err := json.Unmarshal(rawField(top, "formatOptions"), &optionsWire); err != nil {
		return TypeScriptProvider{}, fmt.Errorf("typescript provider: invalid formatOptions")
	}
	if err := exactKeys(optionsWire, []string{"parser", "printWidth", "tabWidth", "useTabs", "semi", "singleQuote", "quoteProps", "jsxSingleQuote", "trailingComma", "bracketSpacing", "bracketSameLine", "arrowParens", "endOfLine", "embeddedLanguageFormatting", "proseWrap", "requirePragma", "insertPragma"}); err != nil {
		return TypeScriptProvider{}, err
	}
	if err := p.Validate(); err != nil {
		return TypeScriptProvider{}, err
	}
	return p, nil
}

func rawField(m map[string]json.RawMessage, key string) []byte { return m[key] }
func decodeField(m map[string]json.RawMessage, key string, dst any) error {
	raw, ok := m[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("typescript provider: missing/null %s", key)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("typescript provider: invalid %s: %w", key, err)
	}
	return nil
}
func exactKeys(m map[string]json.RawMessage, want []string) error {
	set := make(map[string]bool, len(want))
	for _, k := range want {
		set[k] = true
	}
	if len(m) != len(want) {
		return fmt.Errorf("typescript provider: unknown or missing fields")
	}
	for k := range m {
		if !set[k] {
			return fmt.Errorf("typescript provider: unknown field %s", k)
		}
	}
	return nil
}
func requireEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("typescript provider: trailing JSON")
	}
	return nil
}
func scanJSON(r io.Reader) error {
	d := json.NewDecoder(r)
	d.UseNumber()
	if err := scanValue(d); err != nil {
		return err
	}
	return requireEOF(d)
}
func scanValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch v := t.(type) {
	case json.Delim:
		if v == '{' {
			seen := map[string]bool{}
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate/non-string object key")
				}
				seen[key] = true
				if err := scanValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		if v == '[' {
			for d.More() {
				if err := scanValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	}
	return nil
}
func canonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// ValidateTypeScriptRequest applies the helper's closed language/path contract.
func ValidateTypeScriptRequest(language, logicalPath string) error {
	if language != "typescript" && language != "tsx" {
		return fmt.Errorf("typescript provider: unsupported language")
	}
	if !utf8.ValidString(logicalPath) || len([]byte(logicalPath)) > 4096 || utf8.RuneCountInString(logicalPath) > 1024 {
		return fmt.Errorf("typescript provider: logical path exceeds bounds")
	}
	if logicalPath == "" || strings.HasPrefix(logicalPath, "/") || strings.ContainsAny(logicalPath, "\\\\:\x00\r\n\t") {
		return fmt.Errorf("typescript provider: invalid logical path")
	}
	parts := strings.Split(logicalPath, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(part) {
			return fmt.Errorf("typescript provider: invalid logical path")
		}
	}
	exts := ".ts"
	if language == "tsx" {
		exts = ".tsx"
	} else if strings.HasSuffix(logicalPath, ".mts") || strings.HasSuffix(logicalPath, ".cts") {
		exts = logicalPath[len(logicalPath)-4:]
	}
	if !strings.HasSuffix(logicalPath, exts) {
		return fmt.Errorf("typescript provider: language/path mismatch")
	}
	return nil
}
func SortedProviderFiles(files []TypeScriptProviderFile) []TypeScriptProviderFile {
	out := append([]TypeScriptProviderFile(nil), files...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
