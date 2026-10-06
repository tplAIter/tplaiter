package adoption

import (
	"encoding/json"
	"testing"
)

func TestReceiptWireRefusesNullAndOutOfRangeByteArrays(t *testing.T) {
	for _, raw := range []string{"null", "[256]", "[-1]", "\"AQ==\""} {
		var b receiptBytes
		if json.Unmarshal([]byte(raw), &b) == nil {
			t.Fatal("invalid byte wire accepted", raw)
		}
	}
}
