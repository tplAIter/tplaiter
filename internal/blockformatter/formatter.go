package blockformatter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const (
	PlanAPIVersion = "tplaiter.dev/formatter-plan/v1"
	maxPlanBytes   = 1 << 20
	maxOutputBytes = 16 << 20
)

type (
	Marker   = blockmarkers.Marker
	PlanTool = trustverify.Tool
	Plan     struct {
		APIVersion       string   `json:"apiVersion"`
		Path             string   `json:"path"`
		Language         string   `json:"language"`
		Adapter          string   `json:"adapter"`
		Tool             PlanTool `json:"tool"`
		Options          []string `json:"options"`
		InputSHA256      string   `json:"inputSHA256"`
		InputMode        string   `json:"inputMode"`
		Markers          []Marker `json:"markers"`
		TimeoutMillis    int64    `json:"timeoutMillis"`
		OutputLimitBytes int64    `json:"outputLimitBytes"`
		PlanSHA256       string   `json:"planSHA256"`
	}
)

type PlanInput struct {
	Path, Language, Adapter         string
	Tool                            PlanTool
	Options                         []string
	InputMode                       string
	Markers                         []Marker
	TimeoutMillis, OutputLimitBytes int64
	Input                           []byte
}

type wireMarker struct {
	Kind     blockmarkers.Kind `json:"kind"`
	ID       string            `json:"id"`
	Provider string            `json:"provider"`
}
type wirePlan struct {
	APIVersion       string       `json:"apiVersion"`
	Path             string       `json:"path"`
	Language         string       `json:"language"`
	Adapter          string       `json:"adapter"`
	Tool             PlanTool     `json:"tool"`
	Options          []string     `json:"options"`
	InputSHA256      string       `json:"inputSHA256"`
	InputMode        string       `json:"inputMode"`
	Markers          []wireMarker `json:"markers"`
	TimeoutMillis    int64        `json:"timeoutMillis"`
	OutputLimitBytes int64        `json:"outputLimitBytes"`
	PlanSHA256       string       `json:"planSHA256"`
}

func (p Plan) MarshalJSON() ([]byte, error) {
	markers := make([]wireMarker, len(p.Markers))
	for i, m := range p.Markers {
		markers[i] = wireMarker{Kind: m.Kind, ID: m.ID, Provider: m.Provider}
	}
	return json.Marshal(wirePlan{p.APIVersion, p.Path, p.Language, p.Adapter, p.Tool, p.Options, p.InputSHA256, p.InputMode, markers, p.TimeoutMillis, p.OutputLimitBytes, p.PlanSHA256})
}

type Check struct {
	PlanSHA256, InputSHA256, FirstOutputSHA256, SecondOutputSHA256 string
	Formatted                                                      []byte
}
type MarkerValidator interface {
	Validate(language, path string, content []byte) ([]Marker, error)
}
type Error struct{ Code, Path string }

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}
func ferr(code, path string) error { return &Error{Code: code, Path: path} }

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
)

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func domainDigest(v any) (string, error) {
	b, err := canonicaljson.Canonical(v)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(PlanAPIVersion))
	h.Write([]byte{0})
	h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func BuildPlan(in PlanInput) (Plan, error) {
	p := Plan{APIVersion: PlanAPIVersion, Path: in.Path, Language: in.Language, Adapter: in.Adapter, Tool: in.Tool, Options: append([]string{}, in.Options...), InputMode: in.InputMode, Markers: append([]Marker{}, in.Markers...), TimeoutMillis: in.TimeoutMillis, OutputLimitBytes: in.OutputLimitBytes}
	if err := validatePlanFields(&p, in.Input); err != nil {
		return Plan{}, err
	}
	p.InputSHA256 = digest(in.Input)
	p.PlanSHA256 = ""
	d, err := planDigest(p)
	if err != nil {
		return Plan{}, ferr("FORMAT_PLAN", in.Path)
	}
	p.PlanSHA256 = d
	return clonePlan(p), nil
}

func ParsePlan(raw []byte) (Plan, error) {
	var p Plan
	if len(raw) == 0 || len(raw) > maxPlanBytes || !utf8.Valid(raw) {
		return p, ferr("FORMAT_PLAN", "")
	}
	if _, err := canonicaljson.Canonicalize(raw); err != nil {
		return p, ferr("FORMAT_PLAN", "")
	}
	var w wirePlan
	if err := canonicaljson.DecodeStrict(raw, &w); err != nil {
		return Plan{}, ferr("FORMAT_PLAN", "")
	}
	p = Plan{APIVersion: w.APIVersion, Path: w.Path, Language: w.Language, Adapter: w.Adapter, Tool: w.Tool, Options: w.Options, InputSHA256: w.InputSHA256, InputMode: w.InputMode, TimeoutMillis: w.TimeoutMillis, OutputLimitBytes: w.OutputLimitBytes, PlanSHA256: w.PlanSHA256}
	p.Markers = make([]Marker, len(w.Markers))
	for i, m := range w.Markers {
		p.Markers[i] = Marker{Kind: m.Kind, ID: m.ID, Provider: m.Provider}
	}
	if err := validatePlanFields(&p, nil); err != nil {
		return Plan{}, err
	}
	if p.InputSHA256 == "" || !digestRE.MatchString(p.InputSHA256) || !digestRE.MatchString(p.PlanSHA256) {
		return Plan{}, ferr("FORMAT_PLAN", p.Path)
	}
	d, err := planDigest(p)
	if err != nil || d != p.PlanSHA256 {
		return Plan{}, ferr("FORMAT_PLAN", p.Path)
	}
	return clonePlan(p), nil
}

type planPreimage struct {
	APIVersion       string       `json:"apiVersion"`
	Path             string       `json:"path"`
	Language         string       `json:"language"`
	Adapter          string       `json:"adapter"`
	Tool             PlanTool     `json:"tool"`
	Options          []string     `json:"options"`
	InputSHA256      string       `json:"inputSHA256"`
	InputMode        string       `json:"inputMode"`
	Markers          []wireMarker `json:"markers"`
	TimeoutMillis    int64        `json:"timeoutMillis"`
	OutputLimitBytes int64        `json:"outputLimitBytes"`
}

func planDigest(p Plan) (string, error) {
	markers := make([]wireMarker, len(p.Markers))
	for i, m := range p.Markers {
		markers[i] = wireMarker{Kind: m.Kind, ID: m.ID, Provider: m.Provider}
	}
	return domainDigest(planPreimage{p.APIVersion, p.Path, p.Language, p.Adapter, p.Tool, p.Options, p.InputSHA256, p.InputMode, markers, p.TimeoutMillis, p.OutputLimitBytes})
}

func validatePlanFields(p *Plan, input []byte) error {
	if p.APIVersion != PlanAPIVersion || !safePath(p.Path) || p.Tool.Validate() != nil || !exports.VersionMatches(p.Tool.Version, "*") || !adapterToolID(p.Adapter, p.Tool.ID) || (p.InputMode != "100644" && p.InputMode != "100755") || p.TimeoutMillis <= 0 || p.TimeoutMillis > 120000 || p.OutputLimitBytes <= 0 || p.OutputLimitBytes > maxOutputBytes || p.Options == nil || p.Markers == nil || !digestRE.MatchString(p.InputSHA256) && input == nil {
		return ferr("FORMAT_PLAN", p.Path)
	}
	if len(p.Options) > 256 || len(p.Markers) > 4096 {
		return ferr("FORMAT_PLAN", p.Path)
	}
	for _, o := range p.Options {
		if !utf8.ValidString(o) || len(o) > 4096 || strings.ContainsRune(o, 0) {
			return ferr("FORMAT_PLAN", p.Path)
		}
	}
	opt, err := trustverify.ComputeToolOptionsSHA256(p.Options)
	if err != nil || opt != p.Tool.OptionsSHA256 {
		return ferr("FORMAT_PLAN", p.Path)
	}
	if !adapterAllowed(p.Language, p.Adapter, p.Options) {
		return ferr("FORMAT_PLAN", p.Path)
	}
	for _, m := range p.Markers {
		if (m.Kind != blockmarkers.KindBegin && m.Kind != blockmarkers.KindEnd) || !tokenRE.MatchString(m.ID) || (m.Kind == blockmarkers.KindBegin && !providerRE(m.Provider)) || (m.Kind == blockmarkers.KindEnd && m.Provider != "") {
			return ferr("FORMAT_MARKER", p.Path)
		}
	}
	if input != nil && len(input) > maxOutputBytes {
		return ferr("FORMAT_OUTPUT_LIMIT", p.Path)
	}
	return nil
}

func providerRE(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._/-", r)) {
			return false
		}
	}
	return true
}

func adapterAllowed(language, adapter string, options []string) bool {
	switch {
	case language == "go" && adapter == "gofmt-stdin-v1":
		return len(options) == 0
	case language == "rust" && adapter == "rustfmt-stdin-v1":
		return same(options, []string{"--emit", "stdout", "--edition", "2021", "--config-path", "formatter/rustfmt.toml"})
	case (language == "typescript" || language == "tsx") && adapter == TypeScriptAdapterID:
		return len(options) == 0
	}
	return false
}

func adapterToolID(adapter, toolID string) bool {
	switch adapter {
	case "gofmt-stdin-v1":
		return toolID == "gofmt"
	case "rustfmt-stdin-v1":
		return toolID == "rustfmt"
	case TypeScriptAdapterID:
		return toolID == "prettier-typescript"
	default:
		return false
	}
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func safePath(s string) bool {
	return exports.ValidatePortablePath(s) == nil
}

func CheckOutputs(plan Plan, input, first, second []byte, validator MarkerValidator) (Check, error) {
	if _, err := ParsePlan(mustCanonical(plan)); err != nil {
		return Check{}, ferr("FORMAT_PLAN", plan.Path)
	}
	if len(input) > maxOutputBytes || int64(len(first)) > plan.OutputLimitBytes || int64(len(second)) > plan.OutputLimitBytes {
		return Check{}, ferr("FORMAT_OUTPUT_LIMIT", plan.Path)
	}
	if digest(input) != plan.InputSHA256 {
		return Check{}, ferr("FORMAT_PLAN", plan.Path)
	}
	if !bytes.Equal(first, second) {
		return Check{}, ferr("FORMAT_NONDETERMINISTIC", plan.Path)
	}
	if validator == nil {
		return Check{}, ferr("FORMAT_UNAVAILABLE", plan.Path)
	}
	for _, content := range [][]byte{input, first, second} {
		got, err := validator.Validate(plan.Language, plan.Path, content)
		if err != nil {
			return Check{}, ferr("FORMAT_SYNTAX", plan.Path)
		}
		if !markersEqual(got, plan.Markers) {
			return Check{}, ferr("FORMAT_MARKER", plan.Path)
		}
	}
	return Check{PlanSHA256: plan.PlanSHA256, InputSHA256: plan.InputSHA256, FirstOutputSHA256: digest(first), SecondOutputSHA256: digest(second), Formatted: append([]byte(nil), first...)}, nil
}

func markersEqual(a, b []Marker) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].ID != b[i].ID || a[i].Provider != b[i].Provider {
			return false
		}
	}
	return true
}
func mustCanonical(p Plan) []byte { b, _ := canonicaljson.Canonical(p); return b }
func clonePlan(p Plan) Plan {
	p.Options = append([]string{}, p.Options...)
	p.Markers = append([]Marker{}, p.Markers...)
	return p
}

func ValidateMaterialTools(constraints []exports.ToolConstraint, actual []trustverify.Tool) error {
	if len(constraints) > 256 || len(actual) > 256 {
		return ferr("FORMAT_TOOL_REQUIREMENT", "")
	}
	byID := map[string]trustverify.Tool{}
	for _, t := range actual {
		if t.Validate() != nil || !exports.VersionMatches(t.Version, "*") {
			return ferr("FORMAT_TOOL_REQUIREMENT", "")
		}
		if old, ok := byID[t.ID]; ok && old != t {
			return ferr("FORMAT_TOOL_REQUIREMENT", "")
		}
		byID[t.ID] = t
	}
	for _, c := range constraints {
		if c.ID == "" || !digestRE.MatchString(c.OptionsDigest) {
			return ferr("FORMAT_TOOL_REQUIREMENT", "")
		}
		t, ok := byID[c.ID]
		if !ok || t.OptionsSHA256 != c.OptionsDigest || !exports.VersionMatches(t.Version, c.CompatibleRange) {
			return ferr("FORMAT_TOOL_REQUIREMENT", c.ID)
		}
	}
	return nil
}
