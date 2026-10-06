package resultwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

const DiscoveryFrameVersion = "tplaiter.dev/template-discovery-mcp-frame/v1"

// DiscoveryFrameLayout is presentation data only. It preserves an original
// string/int64 JSON-RPC ID without the SDK's float64 numeric projection.
// Existing GraphFrameLayout and other tool transports keep their contract.
type DiscoveryFrameLayout struct {
	APIVersion string          `json:"apiVersion"`
	ID         json.RawMessage `json:"originalID"`
	Ceiling    int             `json:"ceiling"`
}

// NormalizeDiscoveryID closes the scalar domain without a float64 conversion.
// int64 values retain all53+bits; strings retain their exact logical value.
func NormalizeDiscoveryID(raw []byte) (json.RawMessage, error) {
	invalid := errors.New("DISCOVERY_FRAME_INVALID")
	if len(raw) == 0 || len(raw) > 32768 || !utf8.Valid(raw) {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, invalid
	}
	switch v := value.(type) {
	case string:
		encoded, err := json.Marshal(v)
		return encoded, err
	case json.Number:
		number, err := v.Int64()
		if err != nil {
			return nil, invalid
		}
		return json.RawMessage(strconv.FormatInt(number, 10)), nil
	default:
		return nil, invalid
	}
}
func (l DiscoveryFrameLayout) Validate() error {
	if l.APIVersion != DiscoveryFrameVersion || l.Ceiling < 2048 || l.Ceiling > 32768 {
		return errors.New("DISCOVERY_FRAME_INVALID")
	}
	normalized, err := NormalizeDiscoveryID(l.ID)
	if err != nil || !bytes.Equal(normalized, l.ID) {
		return errors.New("DISCOVERY_FRAME_INVALID")
	}
	return nil
}
func (l DiscoveryFrameLayout) RequestID() mcp.RequestId {
	return mcp.NewRequestId(append(json.RawMessage{}, l.ID...))
}
func EncodeDiscoveryFrame(l DiscoveryFrameLayout) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(l)
	return base64.RawURLEncoding.EncodeToString(raw), err
}
func DecodeDiscoveryFrame(encoded string) (DiscoveryFrameLayout, error) {
	var l DiscoveryFrameLayout
	if len(encoded) > 65536 {
		return l, errors.New("DISCOVERY_FRAME_INVALID")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return l, err
	}
	if err = canonicaljson.DecodeStrict(raw, &l); err != nil {
		return l, err
	}
	return l, l.Validate()
}
