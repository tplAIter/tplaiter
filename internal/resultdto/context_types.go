package resultdto

import (
	"encoding/json"

	"github.com/tplAIter/tplaiter/internal/contextindex"
	"github.com/tplAIter/tplaiter/internal/contextwindow"
)

const OperationContextQuery Operation = "context.query"

// The context domain registers independently of other owners' registry edits.
func init() { operationRegistry[OperationContextQuery] = operationSpec{"ContextQuery", ScopeOptional} }

type ContextEntry struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	SourceID    string `json:"sourceId"`
	Path        string `json:"path"`
	ResourceURI string `json:"resourceUri"`
}

// ContextData reports serialized bytes. Window admission is a separate host
// contract; these observations cannot manufacture a token/window allowance.
type ContextData struct {
	// BytePlan and Spending describe this invocation's local retrieval transport.
	// They never represent the caller model's complete context or remaining tokens.
	BytePlan       *contextwindow.Plan     `json:"bytePlan,omitempty"`
	ByteProfile    *contextwindow.Profile  `json:"byteProfile,omitempty"`
	Spending       *contextwindow.Spending `json:"spending,omitempty"`
	RetrievalState string                  `json:"retrievalState,omitempty"`

	Action        string               `json:"action"`
	Snapshot      string               `json:"snapshot"`
	CatalogOrigin string               `json:"catalogOrigin"`
	Entries       []ContextEntry       `json:"entries"`
	Total         int                  `json:"total"`
	NextCursor    string               `json:"nextCursor,omitempty"`
	Packet        *contextindex.Packet `json:"packet,omitempty"`
	WindowState   string               `json:"windowState"`
	WindowReason  string               `json:"windowReason,omitempty"`
	Schema        json.RawMessage      `json:"schema,omitempty"`
	Bytes         int                  `json:"bytes"`
}
