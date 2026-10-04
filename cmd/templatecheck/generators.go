package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

type generatorRecord struct {
	Kind   string   `json:"kind"`
	Names  []string `json:"names,omitempty"`
	Status string   `json:"status"`
}

// Preparation reaches the core's execution-unavailable gate after its actual
// target/snippet/anchor checks. This is not generation or a language build check.
// Available generators must have valid defaults for their parameters.
func preflightGenerators(source, fixture string, tpl *manifest.Template, values settings.Values) ([]generatorRecord, error) {
	before, err := fixtureSnapshot(fixture)
	if err != nil {
		return nil, err
	}
	var records []generatorRecord
	for _, status := range gen.List(tpl, values) {
		if !status.Available {
			records = append(records, generatorRecord{Kind: status.Kind, Status: "skipped: " + status.Reason})
			continue
		}
		g, err := gen.Lookup(tpl, status.Kind)
		if err != nil {
			return nil, err
		}
		params, fields, err := gen.ResolveParams(g, nil)
		if err != nil {
			return nil, fmt.Errorf("%s default parameters: %w", g.Kind, err)
		}
		opts := gen.Options{
			ProjectRoot: fixture, GeneratorsDir: source, Values: values,
			Project: manifest.ProjectInfo{Name: "CI Fixture", Slug: "ci_fixture", Module: "example.com/ci_fixture", System: "ci", Domain: "ci"},
			Params:  params, Fields: fields, NoBuild: true, Runner: noExecution{},
		}
		names := []string{"CheckFirst", "check-second"}
		var operations []gen.Operation
		for _, name := range names {
			if err := confinedGeneratorPaths(g, name, opts); err != nil {
				return nil, err
			}
			if err := validateGeneratorAnchors(g, name, opts); err != nil {
				return nil, err
			}
			_, err = gen.Generate(context.Background(), tpl, g.Kind, name, opts)
			if !errors.Is(err, gen.ErrExecutionUnavailable) {
				return nil, fmt.Errorf("%s %s preparation: expected execution-unavailable gate, got %v", g.Kind, name, err)
			}
			operations = append(operations, gen.Operation{Kind: g.Kind, Name: name, Params: params, Fields: fields})
		}
		// The real batch preparation checks both names against shared targets and
		// accumulated anchor state, catching collisions that single calls miss.
		_, err = gen.GenerateBatch(context.Background(), tpl, operations, opts)
		if !errors.Is(err, gen.ErrExecutionUnavailable) {
			return nil, fmt.Errorf("%s two-name preparation: %w", g.Kind, err)
		}
		// A repeated name and its normalized spelling must fail before execution.
		for _, repeat := range []string{names[0], engine.Snake(names[0])} {
			repeated := []gen.Operation{operations[0], {Kind: g.Kind, Name: repeat, Params: params, Fields: fields}}
			_, err = gen.GenerateBatch(context.Background(), tpl, repeated, opts)
			if err == nil || errors.Is(err, gen.ErrExecutionUnavailable) ||
				(!strings.Contains(err.Error(), "already planned") && !strings.Contains(err.Error(), "already present")) {
				return nil, fmt.Errorf("%s repeated-name preparation did not reject a collision: %v", g.Kind, err)
			}
		}
		records = append(records, generatorRecord{Kind: g.Kind, Names: names, Status: "prepared; execution unavailable; duplicate rejected"})
	}
	after, err := fixtureSnapshot(fixture)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before, after) {
		return nil, errors.New("generator preparation modified the rendered fixture")
	}
	return records, nil
}

// Boundary checks confine untrusted manifest paths before calling gen.Generate,
// whose current preparation API does not expose a confined file-system handle.
func confinedGeneratorPaths(g *manifest.Generator, raw string, opts gen.Options) error {
	check := func(rel string) error {
		if !fs.ValidPath(rel) || strings.Contains(rel, "\\") {
			return fmt.Errorf("generator %s path must stay within its root: %q", g.Kind, rel)
		}
		return nil
	}
	data := generatorContext(raw, opts)
	targets := g.Targets
	if g.Snippet != "" {
		targets = []manifest.Target{{Snippet: g.Snippet, Target: g.Target}}
	}
	for _, target := range targets {
		if err := check(target.Snippet); err != nil {
			return err
		}
		t, err := template.New("target boundary").Funcs(engine.FuncMap(data.Settings)).Parse(target.Target)
		if err != nil {
			return err
		}
		var out bytes.Buffer
		if err := t.Execute(&out, data); err != nil {
			return err
		}
		if err := check(out.String()); err != nil {
			return err
		}
	}
	for _, anchor := range g.Anchors {
		if err := check(anchor.File); err != nil {
			return err
		}
		if err := check(anchor.Insert); err != nil {
			return err
		}
	}
	return nil
}

func generatorContext(raw string, opts gen.Options) gen.Context {
	return gen.Context{
		Name:    gen.Name{Raw: raw, Snake: engine.Snake(raw), Pascal: engine.Pascal(raw), Camel: engine.Camel(raw), Kebab: engine.Kebab(raw)},
		Project: opts.Project, Settings: settings.View(opts.Values), Params: opts.Params, Fields: opts.Fields, MigrationSeq: "00001",
	}
}

// The generator API selects the first matching anchor and does not enforce its
// documented insertion-marker contract. Enforce both here before Generate, so a
// target collision cannot masquerade as proof of wiring idempotency.
func validateGeneratorAnchors(g *manifest.Generator, raw string, opts gen.Options) error {
	data := generatorContext(raw, opts)
	data.Marker = fmt.Sprintf("// gen:%s:%s", g.Kind, data.Name.Snake)
	owned := make(map[string]bool)
	for _, anchor := range g.Anchors {
		original, err := os.ReadFile(filepath.Join(opts.ProjectRoot, filepath.FromSlash(anchor.File)))
		if err != nil {
			return err
		}
		if anchor.Anchor == "" || strings.Count(string(original), anchor.Anchor) != 1 {
			return fmt.Errorf("generator %s anchor %q in %s must occur exactly once", g.Kind, anchor.Anchor, anchor.File)
		}
		if owned[anchor.File] {
			return fmt.Errorf("generator %s marker %q already present in planned anchor file %s", g.Kind, data.Marker, anchor.File)
		}
		owned[anchor.File] = true
		source, err := os.ReadFile(filepath.Join(opts.GeneratorsDir, filepath.FromSlash(anchor.Insert)))
		if err != nil {
			return err
		}
		t, err := template.New(anchor.Insert).Funcs(engine.FuncMap(data.Settings)).Parse(string(source))
		if err != nil {
			return err
		}
		var block bytes.Buffer
		if err := t.Execute(&block, data); err != nil {
			return err
		}
		if strings.Count(block.String(), data.Marker) != 1 {
			return fmt.Errorf("generator %s insertion %s must preserve exactly one unchanged Marker", g.Kind, anchor.Insert)
		}
		// Substitution also proves the insertion consumes the supplied Marker,
		// rather than hard-coding a coincidentally matching idempotency string.
		probe := data
		probe.Marker = "// marker-probe:UNCHANGED"
		var probed bytes.Buffer
		if err := t.Execute(&probed, probe); err != nil {
			return err
		}
		if strings.Count(probed.String(), probe.Marker) != 1 ||
			strings.Replace(block.String(), data.Marker, probe.Marker, 1) != probed.String() {
			return fmt.Errorf("generator %s insertion %s must consume the unchanged Marker interface", g.Kind, anchor.Insert)
		}
		if strings.Contains(block.String(), anchor.Anchor) {
			return fmt.Errorf("generator %s insertion %s duplicates owned anchor %q", g.Kind, anchor.Insert, anchor.Anchor)
		}
	}
	return nil
}

func fixtureSnapshot(root string) (map[string][32]byte, error) {
	files := make(map[string][32]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[rel] = sha256.Sum256(data)
		return nil
	})
	return files, err
}

// No formatter, build gate, or executable lookup is allowed by this checker.
type noExecution struct{}

func (noExecution) Run(context.Context, string, []string, execx.Options) (execx.Result, error) {
	return execx.Result{}, errors.New("generator preflight cannot execute commands")
}

func (noExecution) LookPath(string) (string, error) {
	return "", errors.New("generator preflight cannot look up executables")
}
