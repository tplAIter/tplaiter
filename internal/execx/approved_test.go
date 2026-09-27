package execx

import "testing"

func TestApprovedRunnerNilFails(t *testing.T) {
	if r, e := NewApprovedRunner(nil); e == nil || r != nil {
		t.Fatal("nil runtime accepted")
	}
}
