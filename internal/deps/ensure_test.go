package deps

import (
	"bytes"
	"context"
	"errors"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
	"strings"
	"testing"
)

func TestEnsureRequiredFailsBeforeEffects(t *testing.T) {
	for _, autoYes := range []bool{false, true} {
		t.Run("auto_yes="+map[bool]string{false: "false", true: "true"}[autoYes], func(t *testing.T) {
			r := &closedSpy{}
			var output bytes.Buffer
			e := EnsureTools(context.Background(), r, NewUI(&output, ui.Palette{}), []manifest.Tool{
				{Name: "../host", Required: true},
				{Name: "canary-SECRET", Required: false},
			}, EnsureOptions{AutoYes: autoYes})
			if !errors.Is(e, ErrMissingRequiredTools) || r.look != 0 || r.run != 0 {
				t.Fatalf("%v look=%d run=%d", e, r.look, r.run)
			}
			public := e.Error() + output.String()
			for _, forbidden := range []string{"../host", "/host/path", "SECRET", "canary"} {
				if strings.Contains(public, forbidden) {
					t.Fatalf("public text leaks %q: %q", forbidden, public)
				}
			}
		})
	}
}
