package adoption

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
)

func TestReceiptReaderAuthenticatesKindLocationAndBytes(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, 32) // public synthetic unit key
	payload := json.RawMessage(`{"version":1}`)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(receiptVersion + "\x00" + receiptKind + "\x00" + dir + "\x00plan.json\x00"))
	mac.Write(payload)
	raw, e := canonicaljson.Canonical(struct {
		Payload json.RawMessage `json:"payload"`
		MAC     string          `json:"mac"`
	}{payload, hex.EncodeToString(mac.Sum(nil))})
	if e != nil {
		t.Fatal(e)
	}
	name := filepath.Join(dir, "plan.json")
	if e = os.WriteFile(name, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	var out struct {
		Version int `json:"version"`
	}
	if _, _, e = receiptSigned(key, dir, "plan.json", &out); e != nil || out.Version != 1 {
		t.Fatal(e)
	}
	// A valid MAC for one operation/location/name cannot authenticate another.
	if e = os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receiptSigned(key, dir, "state.json", &out); e == nil {
		t.Fatal("record name substitution accepted")
	}
	if e = os.WriteFile(name, bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receiptSigned(key, dir, "plan.json", &out); e == nil {
		t.Fatal("content tamper accepted")
	}
	if e = os.WriteFile(name, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(name, append(bytes.Clone(raw), byte('\n')), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receiptSigned(key, dir, "plan.json", &out); e == nil {
		t.Fatal("valid inner MAC with changed envelope bytes accepted")
	}
	if e = os.WriteFile(name, raw, 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(name, 0o600|os.ModeSetuid); e != nil {
		t.Fatal(e)
	}
	if _, _, e = receiptSigned(key, dir, "plan.json", &out); e == nil {
		t.Fatal("special-mode receipt accepted")
	}
}
func TestReceiptWireRefusesNullAndOutOfRangeByteArrays(t *testing.T) {
	for _, raw := range []string{"null", "[256]", "[-1]", "\"AQ==\""} {
		var b receiptBytes
		if json.Unmarshal([]byte(raw), &b) == nil {
			t.Fatal("invalid byte wire accepted", raw)
		}
	}
}
