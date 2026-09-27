package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

// ComputeRootLockSHA256 seals the root lock after removing only its top-level
// self field and the two explicitly permitted evidence timestamps (the latter
// are nested in future evidence extensions and therefore absent from v2 DTOs).
func ComputeRootLockSHA256(v RootTemplateLock) (string, error) {
	return seal(RootTemplateLockAPIVersion, v, "rootLockSHA256")
}

func ComputeTemplateLockSHA256(v TemplateLock) (string, error) {
	return seal(TemplateLockAPIVersion, v, "lockSHA256")
}

func seal(domain string, value any, self string) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("provenance: marshal: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	delete(obj, self)
	b, err := canonicaljson.Canonical(obj)
	if err != nil {
		return "", fmt.Errorf("provenance: canonicalize: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
