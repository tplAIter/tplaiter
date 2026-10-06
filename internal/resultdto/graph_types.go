package resultdto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
	"strings"
)

const (
	OperationGraphSource  Operation = "graph.source"
	OperationGraphExports Operation = "graph.exports"
	OperationGraphAST     Operation = "graph.ast"
	OperationGraphStats   Operation = "graph.stats"
)

func init() {
	for op, kind := range map[Operation]string{OperationGraphSource: "SourceGraph", OperationGraphExports: "ExportGraph", OperationGraphAST: "ASTGraph", OperationGraphStats: "GraphStats"} {
		operationRegistry[op] = operationSpec{kind, ScopeOptional}
	}
}

// GraphRecord is a whole native fact. An edge's original endpoints are retained
// even when a page does not contain its nodes. Pages are not complete graphs.
type GraphRecord struct {
	Kind       string                  `json:"kind"`
	Identity   string                  `json:"identity,omitempty"`
	Source     *deps.SourceNode        `json:"source,omitempty"`
	Pins       []deps.PinnedSource     `json:"pins,omitempty"`
	SourceEdge *deps.SourceEdge        `json:"sourceEdge,omitempty"`
	Export     *exports.SelectedExport `json:"export,omitempty"`
	ExportEdge *exports.ExportEdge     `json:"exportEdge,omitempty"`
	Node       *graphdoc.Node          `json:"node,omitempty"`
	Edge       *graphdoc.Edge          `json:"edge,omitempty"`
	Diagnostic *graphdoc.Diagnostic    `json:"diagnostic,omitempty"`
}
type GraphPage struct {
	Representation string `json:"representation"`
	Digest         string `json:"pageDigest"`
	Returned       int    `json:"returnedRecords"`
	Total          int    `json:"totalRecords"`
	Omitted        int    `json:"omittedRecords"`
	NextCursor     string `json:"nextCursor,omitempty"`
}
type GraphLayerStats struct {
	State       string `json:"state"`
	Digest      string `json:"digest,omitempty"`
	Nodes       int    `json:"nodes"`
	Edges       int    `json:"edges"`
	Diagnostics int    `json:"diagnostics"`
}
type GraphData struct {
	APIVersion        string                     `json:"apiVersion"`
	Layer             string                     `json:"layer"`
	QueryDigest       string                     `json:"queryDigest"`
	ObservationBasis  string                     `json:"observationBasis"`
	InputDigests      []string                   `json:"inputDigests"`
	FullGraphDigest   string                     `json:"fullGraphDigest"`
	VerificationLevel string                     `json:"verificationLevel"`
	CacheState        string                     `json:"cacheState"`
	GraphStatus       string                     `json:"graphStatus"`
	Records           []GraphRecord              `json:"records"`
	Page              GraphPage                  `json:"page"`
	Stats             map[string]GraphLayerStats `json:"stats,omitempty"`
}

// DecodeGraphData is a closed decoder, not an authority constructor.
func DecodeGraphData(raw []byte) (GraphData, error) {
	var d GraphData
	if len(raw) > 32768 {
		return d, fmt.Errorf("graph: data limit")
	}
	if e := canonicaljson.DecodeStrict(raw, &d); e != nil {
		return d, e
	}
	if d.APIVersion != "tplaiter.dev/graph-query-result/v1" || d.Page.Returned != len(d.Records) || d.Page.Total < d.Page.Returned || d.Page.Omitted != d.Page.Total-d.Page.Returned || d.Records == nil || d.InputDigests == nil {
		return d, fmt.Errorf("graph: invalid page")
	}
	if !graphChoice(d.Layer, "source", "exports", "ast", "stats") || !graphChoice(d.GraphStatus, "ok", "partial", "error") || !graphChoice(d.CacheState, "missing", "stale", "hit", "corrupt", "disabled", "recomputed", "unverified") || !graphChoice(d.Page.Representation, "whole", "page") || !graphChoice(d.ObservationBasis, "enrolled-source-selection", "installed-project-syntax") || !graphChoice(d.VerificationLevel, "authenticated-source-pins", "syntax-go-and-approximate-rust-outline") {
		return d, fmt.Errorf("graph: invalid domain metadata")
	}
	for _, digest := range append(append([]string{}, d.InputDigests...), d.QueryDigest, d.FullGraphDigest, d.Page.Digest) {
		if !graphDigest(digest) {
			return d, fmt.Errorf("graph: malformed digest")
		}
	}
	b, e := canonicaljson.Canonical(d.Records)
	if e != nil {
		return d, e
	}
	h := sha256.Sum256(b)
	if d.Page.Digest != "sha256:"+hex.EncodeToString(h[:]) {
		return d, fmt.Errorf("graph: page digest mismatch")
	}
	if d.Page.Representation == "whole" && (d.Page.Omitted != 0 || d.Page.NextCursor != "") {
		return d, fmt.Errorf("graph: incomplete whole graph")
	}
	for _, r := range d.Records {
		n := 0
		for _, present := range []bool{r.Source != nil, r.SourceEdge != nil, r.Export != nil, r.ExportEdge != nil, r.Node != nil, r.Edge != nil, r.Diagnostic != nil} {
			if present {
				n++
			}
		}
		if n != 1 {
			return d, fmt.Errorf("graph: invalid fact union")
		}
		switch r.Kind {
		case "source":
			if r.Source == nil || r.Identity != r.Source.Key || len(r.Pins) == 0 {
				return d, fmt.Errorf("graph: incomplete source fact")
			}
		case "source-edge":
			if r.SourceEdge == nil {
				return d, fmt.Errorf("graph: invalid source edge")
			}
		case "export":
			if r.Export == nil {
				return d, fmt.Errorf("graph: invalid export fact")
			}
			identity, e := exports.SelectedExportIdentity(*r.Export)
			if e != nil || identity != r.Identity {
				return d, fmt.Errorf("graph: incomplete export identity")
			}
		case "export-edge":
			if r.ExportEdge == nil {
				return d, fmt.Errorf("graph: invalid export edge")
			}
		case "ast-node":
			if r.Node == nil || r.Identity != r.Node.ID {
				return d, fmt.Errorf("graph: invalid syntax node")
			}
		case "ast-edge":
			if r.Edge == nil {
				return d, fmt.Errorf("graph: invalid syntax edge")
			}
		case "ast-diagnostic":
			if r.Diagnostic == nil {
				return d, fmt.Errorf("graph: invalid syntax diagnostic")
			}
		default:
			return d, fmt.Errorf("graph: unknown fact")
		}
		if r.Kind != "source" && len(r.Pins) > 0 {
			return d, fmt.Errorf("graph: pins outside source fact")
		}
	}
	for _, v := range d.Stats {
		if v.Nodes < 0 || v.Edges < 0 || v.Diagnostics < 0 {
			return d, fmt.Errorf("graph: invalid stats")
		}
	}

	return d, nil
}

func graphChoice(value string, allowed ...string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}
func graphDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	b, e := hex.DecodeString(value[7:])
	return e == nil && len(b) == 32 && value == "sha256:"+hex.EncodeToString(b)
}
