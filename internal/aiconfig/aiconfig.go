// Package aiconfig loads the centralized source of AI rules (the ai-config/
// directory) and renders per-tool artifacts (CLAUDE.md, .cursor/**,
// AGENTS.md, GEMINI.md) into the project root.
//
// The source (the go-template WP-19 migration, now part of the tplater
// contract) consists of:
//   - config.json           — language, target tools, line length;
//   - modules/NN-*.json     — rule module declarations (activation, globs, when);
//   - rules/NN-*.md         — "quick reference" (compact examples);
//   - docs/*.md             — "full" documentation with canonical code;
//   - targets/*.tmpl        — text/template compositions for each tool.
//
// The main difference from go-template is that module gating uses the `when`
// field in the §3.2 condition mini-language (settings.Eval), rather than the
// boolean `feature` from the binary feature registry. As with [gen], the source
// (the ai-config directory) is not embedded in the binary, but copied into the
// project: [AIConfigRelPath] is the contract with related / components,
// symmetric to gen.GeneratorsRelPath.
package aiconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ConfigFileName — name of the source root configuration file.
const ConfigFileName = "config.json"

// AIConfigRelPath — path to the copied ai-config directory in the generated
// project, relative to its root. `tplater new` copies here the directory
// referenced by the template manifest's aiConfig.path (the contract with /).
const AIConfigRelPath = ".tplaiter/ai-config"

// Activation types for modules (corresponding to ways of attaching rules in Cursor).
const (
	ActivationAlways   = "always"
	ActivationGlobs    = "globs"
	ActivationSemantic = "semantic"
)

// Config — model of config.json.
type Config struct {
	Language     string   `json:"language"`
	CodeLanguage string   `json:"code_language"`
	Targets      []string `json:"targets"`
	LineLength   int      `json:"line_length"`
}

// Module — declaration of one rule module (modules/NN-*.json). When is the
// activation condition in §3.2 terms (empty means an unconditional module),
// replacing go-template's Feature *string.
type Module struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Activation  string   `json:"activation"`
	Globs       []string `json:"globs"`
	Description string   `json:"description"`
	When        string   `json:"when"`
	RuleFile    string   `json:"rule_file"`
	DocFile     string   `json:"doc_file"`
}

// LoadedModule — module with the loaded rule/doc contents and derived names.
type LoadedModule struct {
	Module

	// Rule — contents of rule_file (quick reference).
	Rule string
	// Doc — contents of doc_file (full documentation).
	Doc string
	// DocBase — base name of the doc file with its extension (e.g. "base.md").
	DocBase string
	// DocName — base name of the doc file without its extension (e.g. "base").
	DocName string
	// RuleName — base name of the rule file without its extension (e.g. "00-base").
	RuleName string
}

// Source — loaded ai-config source (configuration plus all modules).
type Source struct {
	// Dir — source root directory (ai-config/).
	Dir string
	// Config — parsed config.json.
	Config Config
	// Modules — all modules, sorted by ID.
	Modules []LoadedModule
}

// Load reads config.json and all modules from dir, including their rule/doc files.
// Schema validation is performed separately by [Source.Validate].
func Load(dir string) (*Source, error) {
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	modules, err := loadModules(dir)
	if err != nil {
		return nil, err
	}
	return &Source{Dir: dir, Config: cfg, Modules: modules}, nil
}

// loadConfig reads and parses config.json.
func loadConfig(dir string) (Config, error) {
	path := filepath.Join(dir, ConfigFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("aiconfig: reading %s: %w", path, err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("aiconfig: parsing %s: %w", path, err)
	}
	return cfg, nil
}

// loadModules reads modules/*.json, loads the rule/doc contents, and sorts by ID.
func loadModules(dir string) ([]LoadedModule, error) {
	modulesDir := filepath.Join(dir, "modules")
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return nil, fmt.Errorf("aiconfig: reading modules directory %s: %w", modulesDir, err)
	}

	modules := make([]LoadedModule, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		m, err := loadModule(dir, filepath.Join(modulesDir, e.Name()))
		if err != nil {
			return nil, err
		}
		modules = append(modules, m)
	}

	sort.Slice(modules, func(i, j int) bool { return modules[i].ID < modules[j].ID })
	return modules, nil
}

// loadModule parses one module JSON file and reads its related rule/doc files.
func loadModule(root, path string) (LoadedModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LoadedModule{}, fmt.Errorf("aiconfig: reading module %s: %w", path, err)
	}
	var m Module
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return LoadedModule{}, fmt.Errorf("aiconfig: parsing module %s: %w", path, err)
	}

	loaded := LoadedModule{Module: m}
	if m.RuleFile != "" {
		content, err := os.ReadFile(filepath.Join(root, m.RuleFile))
		if err != nil {
			return LoadedModule{}, fmt.Errorf("aiconfig: reading rule %s (module %s): %w", m.RuleFile, m.ID, err)
		}
		loaded.Rule = string(content)
		loaded.RuleName = baseName(m.RuleFile)
	}
	if m.DocFile != "" {
		content, err := os.ReadFile(filepath.Join(root, m.DocFile))
		if err != nil {
			return LoadedModule{}, fmt.Errorf("aiconfig: reading doc %s (module %s): %w", m.DocFile, m.ID, err)
		}
		loaded.Doc = string(content)
		loaded.DocBase = filepath.Base(m.DocFile)
		loaded.DocName = baseName(m.DocFile)
	}
	return loaded, nil
}

// baseName returns the file name without its directory and extension.
func baseName(p string) string {
	b := filepath.Base(p)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// Filter returns modules applicable to the given settings values:
// unconditional modules (When == "") plus those whose when condition is true
// (settings.Eval, §3.2). An unparsable condition or reference to an unknown
// group is an error (abort): such a module.when is an ai-config bug that
// [Source.Validate] must catch in advance, rather than silently excluding the
// module from output (symmetric with engine.compileFileRules for file rules).
func (s *Source) Filter(values settings.Values) ([]LoadedModule, error) {
	out := make([]LoadedModule, 0, len(s.Modules))
	for _, m := range s.Modules {
		if m.When == "" {
			out = append(out, m)
			continue
		}
		ok, err := evalWhen(m.When, values)
		if err != nil {
			return nil, fmt.Errorf("aiconfig: module %s: when %q: %w", m.ID, m.When, err)
		}
		if ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// evalWhen parses and evaluates a module's when condition (§3.2, conjunction via &&).
func evalWhen(when string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(when)
	if err != nil {
		return false, err
	}
	return settings.Eval(cond, values)
}
