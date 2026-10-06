package cmd

import (
	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
	"os/signal"
	"syscall"
)

func init() {
	registerCommand(newGraphCmd)
	registerDepsSubcommand(func() *cobra.Command { return newGraphLeaf("source", "graph") })
}
func newGraphCmd() *cobra.Command {
	c := &cobra.Command{Use: "graph", Short: "Inspect separate source, export and bounded syntax graphs", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly)}
	for _, layer := range []string{"source", "exports", "ast", "stats"} {
		c.AddCommand(newGraphLeaf(layer, layer))
	}
	return c
}
func graphError(err error) error {
	code := graphcmd.Code(err)
	exit := resultdto.ExitOperational
	if code == "GRAPH_ARGUMENT_INVALID" || code == "GRAPH_SELECTOR_INVALID" || code == "GRAPH_CURSOR_STALE" {
		exit = resultdto.ExitUsage
	}
	if code == "GRAPH_SOURCE_ADMISSION" {
		exit = resultdto.ExitTrust
	}
	return resultdto.NewError(code, exit, err)
}
func newGraphLeaf(layer, name string) *cobra.Command {
	var key, dir, source, mcpFrame string
	var selectors []string
	q := graphcmd.Query{Layer: layer}
	c := &cobra.Command{Use: name, Short: "Observe " + layer + " graph; source selection is not project dependency enrollment", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunTrustOwned)}
	f := c.Flags()
	f.StringVar(&key, "project-context", "", "exact installed project-context key")
	f.StringVar(&dir, "dir", "", "locator matching installed project root")
	f.StringVar(&source, "source-input", "", "bounded operator-enrolled source selection locator")
	f.StringArrayVar(&selectors, "select", nil, "export selector; repeat for a closed batch with empty bindings")
	f.StringVar(&q.ExpectedDigest, "expected-digest", "", "expected complete graph digest")
	f.StringVar(&q.Cursor, "cursor", "", "digest-bound page locator")
	f.IntVar(&q.Limit, "limit", 64, "maximum whole records per page")
	f.IntVar(&q.MaxBytes, "max-bytes", 16384, "complete CLI result/v1 bytes including newline, 1024..32768")
	f.StringVar(&q.Representation, "representation", "page", "page or whole; whole refuses over-budget output")
	f.StringVar(&q.Cache, "cache", "read", "read or off; AST refresh explicitly publishes derived cache")
	f.StringVar(&mcpFrame, "graph-mcp-frame", "", "closed internal SDK serialization layout; no authority")
	_ = f.MarkHidden("graph-mcp-frame")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		var layout *resultwire.GraphFrameLayout
		if mcpFrame != "" {
			l, e := resultwire.DecodeGraphFrame(mcpFrame)
			if e != nil {
				return resultdto.NewError("GRAPH_ARGUMENT_INVALID", resultdto.ExitUsage, e)
			}
			layout = &l
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		cmd.SetContext(ctx)
		request := q
		request.Selections = []exports.Selection{}
		for _, s := range selectors {
			request.Selections = append(request.Selections, exports.Selection{APIVersion: exports.SelectionAPIVersion, Selector: s, Bindings: []exports.ScalarParameter{}})
		}
		if source != "" {
			b, e := graphcmd.ReadSourceInput(source)
			if e != nil {
				return graphError(e)
			}
			request.SourceInput = b
		}
		if e := request.Normalize(); e != nil {
			return graphError(e)
		}
		r, e := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
		if e != nil {
			return e
		}
		defer r.Close()
		opts := runtimeassembly.Options{}
		// Root-scoped admission uses the same real reader as ROOT context. Home
		// credential classification and global journal inspection are not claimed.

		observed, e := graphcmd.Prepare(ctx, r, request, opts)
		if e != nil {
			return graphError(e)
		}
		defer observed.Close()
		var frame []byte
		if layout == nil {
			frame, e = observed.Frame(ctx, resolveVersion())
		} else {
			frame, e = observed.FrameForMCP(ctx, resolveVersion(), *layout)
		}
		if e != nil {
			return graphError(e)
		}
		if e = observed.Recheck(ctx); e != nil {
			return graphError(e)
		}
		// The ordinary CLI owns its observation through this complete serialized write.
		// MCP uses the existing captured-child route, not a final-output live grant.
		emittedResult = true
		return writeRootFrameContext(ctx, cmd.OutOrStdout(), frame)
	}
	return withResult(c, graphcmd.Operation(layer))
}
