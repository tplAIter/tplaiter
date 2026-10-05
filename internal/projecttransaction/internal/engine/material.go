package engine

import (
	"encoding/json"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

// Material is transport restricted by Go's nested internal import boundary.
// It is never exposed by the public projecttransaction admission facade.
type File struct {
	Data      Bytes  `json:"data"`
	Mode      uint32 `json:"mode"`
	Directory bool   `json:"directory"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
}
type RegistryPair struct {
	Before File `json:"before"`
	After  File `json:"after"`
}

type Material struct {
	Registry      *RegistryPair            `json:"registry,omitempty"`
	Root          string                   `json:"root"`
	Home          string                   `json:"home"`
	ProjectID     string                   `json:"projectID"`
	Binding       bootstrap.ProfileBinding `json:"binding"`
	Before        map[string]File          `json:"before"`
	After         map[string]File          `json:"after"`
	Fingerprint   string                   `json:"fingerprint"`
	ReadOnlyPaths []string                 `json:"readOnlyPaths"`
	Intent        json.RawMessage          `json:"intent"`
}

// Bytes uses an explicit integer array: strict wire decoding rejects nulls
// and byte slices encoded as ambient base64 strings. Empty directories carry [].
type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	values := make([]uint16, len(b))
	for i, v := range b {
		values[i] = uint16(v)
	}
	return json.Marshal(values)
}

func (b *Bytes) UnmarshalJSON(raw []byte) error {
	var values []uint16
	if err := json.Unmarshal(raw, &values); err != nil {
		return err
	}
	if values == nil {
		return ErrAuthentication
	}
	out := make(Bytes, len(values))
	for i, v := range values {
		if v > 255 {
			return ErrAuthentication
		}
		out[i] = byte(v)
	}
	*b = out
	return nil
}
