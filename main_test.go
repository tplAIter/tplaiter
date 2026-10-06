package main

import (
	"testing"

	"github.com/tplAIter/tplaiter/internal/cmd"
)

func TestActionBootstrapClosedIngress(t *testing.T) {
	for _, args := range [][]string{nil, {"run", "check"}, {"--help"}} {
		if handled, _ := cmd.TryActionBootstrap(args); handled {
			t.Fatal("ordinary command consumed")
		}
	}
	for _, args := range [][]string{{"--tplaiter-action-bootstrap=v2"}, {"--tplaiter-action-bootstrap=v1", "extra"}, {"--tplaiter-action-bootstrap-other"}, {"--tplaiter-action-bootstrap"}} {
		if handled, code := cmd.TryActionBootstrap(args); !handled || code != 126 {
			t.Fatal("unknown/extra bootstrap accepted")
		}
	}
}
