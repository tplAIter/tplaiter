package trustverify

import (
	"strings"
	"testing"
)

func validToolForValidation() Tool {
	return Tool{
		ID:            "gofmt",
		Version:       "1.26.0",
		BinarySHA256:  "sha256:" + strings.Repeat("1", 64),
		OptionsSHA256: "sha256:" + strings.Repeat("2", 64),
	}
}

func TestToolValidateDelegatesPureWireChecks(t *testing.T) {
	if err := validToolForValidation().Validate(); err != nil {
		t.Fatalf("valid tool rejected: %v", err)
	}
	cases := []Tool{
		func() Tool { v := validToolForValidation(); v.ID = ""; return v }(),
		func() Tool { v := validToolForValidation(); v.Version = "1 2 3"; return v }(),
		func() Tool {
			v := validToolForValidation()
			v.BinarySHA256 = "sha256:" + strings.Repeat("x", 64)
			return v
		}(),
		func() Tool { v := validToolForValidation(); v.OptionsSHA256 = ""; return v }(),
	}
	for i, tc := range cases {
		if err := tc.Validate(); err == nil {
			t.Fatalf("case %d accepted invalid tool", i)
		}
	}
}
