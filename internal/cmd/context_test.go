package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func TestContextReadonlyRegistrationAndCancellation(t *testing.T) {
	in, root := installedNativeGenCLI(t)
	for _, action := range []string{"discover", "search", "get", "plan", "continue", "schema"} {
		c := newTrustRootCommand(in)
		leaf, _, err := c.Find([]string{"context", action})
		if err != nil {
			t.Fatal(err)
		}
		if classifyPrerun(leaf, nil) != prerunReadonly {
			t.Fatalf("hidden root hooks for %s", action)
		}
	}
	before := nativeGenTree(t, root)
	c := newTrustRootCommand(in)
	ctx, cancel := context.WithCancel(c.Context())
	cancel()
	c.SetContext(ctx)
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetArgs([]string{"context", "discover", "--json"})
	err := c.Execute()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if !equalStringMap(before, nativeGenTree(t, root)) {
		t.Fatal("cancelled context request wrote project")
	}
	// No numeric window or catalog JSON flag is admitted.
	for _, args := range [][]string{{"context", "plan", "--trusted-window=256000"}, {"context", "get", "--catalog-json={} "}} {
		c = newTrustRootCommand(in)
		c.SetArgs(args)
		if c.Execute() == nil {
			t.Fatal("authority flag accepted")
		}
	}
	raw, err := executeNativeGenCLI(in, "context", "plan", "--limit=1", "--max-bytes=32768", "--json")
	var exit resultdto.ExitCoder
	if !errors.As(err, &exit) || exit.ExitCode() != resultdto.ExitUnavailable {
		t.Fatalf("plan window was guessed: %v %s", err, raw)
	}
	env := decodeOne(t, raw)
	if len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != contextcmd.WindowUnknown {
		t.Fatalf("unknown window outcome: %s", raw)
	}
}
