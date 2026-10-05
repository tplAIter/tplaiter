package ledgerpath

import "testing"

func TestHomeProjectTransactionSlotExactNamespace(t *testing.T) {
	for _, test := range []struct {
		path  string
		valid bool
	}{
		{"transactions/project/tx-00112233445566778899aabbccddeeff/000001", true},
		{"transactions/project/tx-00112233445566778899aabbccddeeff/../credentials", false},
		{"transactions/project/tx-00112233445566778899aabbccddeeff/000001/extra", false},
		{"transactions/project/tx-00112233445566778899aabbccddeeff/secret", false},
		{"transactions/project/foreign/000001", false},
		{"transactions/new/tx-00112233445566778899aabbccddeeff/000001", false},
	} {
		_, valid := HomeProjectTransactionSlot(test.path)
		if valid != test.valid {
			t.Fatal(test.path)
		}
	}
}
