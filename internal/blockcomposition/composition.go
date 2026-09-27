// Package blockcomposition builds deterministic managed-block candidate images.
// It has no filesystem, formatter, network, or trust-verification adapter.
package blockcomposition

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/tplAIter/tplaiter/internal/blockexport"
	"github.com/tplAIter/tplaiter/internal/managedblocks"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

type Provider struct {
	Name   string
	Source managedblocks.ProviderSource
	Bodies map[string][]byte
}

type Input struct {
	Exports   []blockexport.BlockExport
	Providers []Provider
	Skeletons map[string][]byte
}

type Block struct {
	ID       string
	Provider string
	BodyPath string
	Source   provenance.RootSubject
}

type Target struct {
	Path    string
	Content []byte
	Blocks  []Block
}

type Result struct{ Targets []Target }

// Error is a stable, pure diagnostic. It contains safe logical identities
// only; no host path or body contents are reported.
type Error struct {
	Code string
	Path string
	ID   string
}

func (e *Error) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("block composition: %s: %s#%s", e.Code, e.Path, e.ID)
	}
	if e.Path != "" {
		return fmt.Sprintf("block composition: %s: %s", e.Code, e.Path)
	}
	return "block composition: " + e.Code
}

func fail(code, path, id string) error { return &Error{Code: code, Path: path, ID: id} }

// Compose validates immutable provider bindings and materializes a copied,
// deterministic candidate for every resolved block target.
func Compose(input Input) (Result, error) {
	resolved, err := blockexport.Resolve(input.Exports)
	if err != nil {
		return Result{}, err
	}
	providers := make(map[string]Provider, len(input.Providers))
	for _, p := range input.Providers {
		if p.Name == "" || p.Source.Provider != p.Name || p.Source.Source.Validate() != nil {
			return Result{}, fail("PROVIDER_BINDING", p.Name, "")
		}
		if _, found := providers[p.Name]; found {
			return Result{}, fail("PROVIDER_DUPLICATE", p.Name, "")
		}
		for body := range p.Bodies {
			if !safePath(body) {
				return Result{}, fail("BODY_PATH", p.Name, body)
			}
		}
		providers[p.Name] = p
	}
	result := Result{Targets: make([]Target, 0, len(resolved))}
	for _, target := range resolved {
		if !safePath(target.Path) {
			return Result{}, fail("TARGET_PATH", target.Path, "")
		}
		skeleton, found := input.Skeletons[target.Path]
		if !found {
			return Result{}, fail("SKELETON_MISSING", target.Path, "")
		}
		content := append([]byte(nil), skeleton...)
		crlf := bytes.Contains(content, []byte("\r\n"))
		blocks := make([]Block, 0, len(target.Blocks))
		for _, spec := range target.Blocks {
			if !safePath(spec.Body) {
				return Result{}, fail("BODY_PATH", target.Path, spec.ID)
			}
			provider, found := providers[spec.Provider]
			if !found {
				return Result{}, fail("PROVIDER_MISSING", target.Path, spec.ID)
			}
			body, found := provider.Bodies[spec.Body]
			if !found {
				return Result{}, fail("BODY_MISSING", target.Path, spec.ID)
			}
			if len(content) > 0 && content[len(content)-1] != '\n' {
				content = append(content, lineEnd(crlf)...)
			}
			content = append(content, marker("begin", spec.ID, spec.Provider, crlf)...)
			body = normalizeEOL(body, crlf)
			content = append(content, body...)
			if len(body) == 0 || body[len(body)-1] != '\n' {
				content = append(content, lineEnd(crlf)...)
			}
			content = append(content, marker("end", spec.ID, "", crlf)...)
			blocks = append(blocks, Block{ID: spec.ID, Provider: spec.Provider, BodyPath: spec.Body, Source: provider.Source.Source})
		}
		result.Targets = append(result.Targets, Target{Path: target.Path, Content: content, Blocks: blocks})
	}
	return cloneResult(result), nil
}

func (r Result) Clone() Result { return cloneResult(r) }

func cloneResult(in Result) Result {
	out := Result{Targets: make([]Target, len(in.Targets))}
	for i, target := range in.Targets {
		out.Targets[i] = Target{Path: target.Path, Content: append([]byte(nil), target.Content...), Blocks: append([]Block(nil), target.Blocks...)}
	}
	return out
}

func (t Target) IDs() []string {
	ids := make([]string, len(t.Blocks))
	for i := range t.Blocks {
		ids[i] = t.Blocks[i].ID
	}
	sort.Strings(ids)
	return ids
}

func safePath(value string) bool {
	if value == "" || path.IsAbs(value) || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\:") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if strings.EqualFold(component, ".git") || strings.EqualFold(component, ".tplater") {
			return false
		}
	}
	return true
}

func marker(kind, id, provider string, crlf bool) []byte {
	line := "// tplater:managed-" + kind + " id=" + id
	if provider != "" {
		line += " provider=" + provider
	}
	return append([]byte(line), lineEnd(crlf)...)
}

func lineEnd(crlf bool) []byte {
	if crlf {
		return []byte("\r\n")
	}
	return []byte("\n")
}

func normalizeEOL(body []byte, crlf bool) []byte {
	out := bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	if crlf {
		out = bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n"))
	}
	return out
}
