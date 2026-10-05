// Package knowledge validates data-only knowledge descriptors and projects them
// into graphdoc. Descriptors never grant execution or publication authority.
package knowledge

import (
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/provenance"
)

const (
	APIVersion = "tplaiter.dev/knowledge/v1"
	MaxBytes   = 1 << 20
)

// Catalog is a portable, closed descriptor. Source proof locators are claims
// until ObserveSource verifies them using an actual runtime-bound resolution.
type Catalog struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	ID         string   `json:"id"`
	Version    string   `json:"version"`
	Sources    []Source `json:"sources"`
	Items      []Item   `json:"items"`
	Edges      []Edge   `json:"edges"`
}

type Source struct {
	ID     string                 `json:"id"`
	Pin    deps.PinnedSource      `json:"pin"`
	Anchor provenance.RootSubject `json:"anchor"`
}

type Item struct {
	ID             string               `json:"id"`
	Kind           string               `json:"kind"`
	Version        string               `json:"version"`
	SourceID       string               `json:"sourceId"`
	SourcePath     string               `json:"sourcePath"`
	ContentSHA256  string               `json:"contentSHA256"`
	Mode           string               `json:"mode"`
	Ownership      Ownership            `json:"ownership"`
	UpdateTriggers []string             `json:"updateTriggers"`
	Requires       []string             `json:"requires"`
	Produces       []string             `json:"produces"`
	Executor       Executor             `json:"executor"`
	Inputs         InputContract        `json:"inputs"`
	Quality        []Quality            `json:"quality"`
	Export         *exports.ExportEntry `json:"export,omitempty"`
}

type Ownership struct {
	OwnerID      string `json:"ownerId"`
	Version      string `json:"version"`
	PolicySHA256 string `json:"policySHA256"`
}

// Executor describes an interface, not a command or an ExecutionPermit.
type Executor struct {
	ID                   string `json:"id"`
	Version              string `json:"version"`
	InputContractSHA256  string `json:"inputContractSHA256"`
	OutputContractSHA256 string `json:"outputContractSHA256"`
}

type Quality struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ContractSHA256 string `json:"contractSHA256"`
	State          string `json:"state"`
}

// Edge.Layer separates dependency semantics; unresolved endpoints are retained
// explicitly as placeholders rather than promoted to established knowledge.
type Edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Layer    string `json:"layer"`
	Relation string `json:"relation"`
	State    string `json:"state"`
}
