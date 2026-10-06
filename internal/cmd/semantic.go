package cmd

import (
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/semanticpreview"
	"github.com/tplAIter/tplaiter/internal/stateledger/runtimeassembly"
)

func init() { registerCommand(newSemanticCmd) }
func newSemanticCmd() *cobra.Command {
	c := &cobra.Command{Use: "semantic", Short: "Inspect bounded Go syntax edits without writing or executing", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly)}
	c.AddCommand(newSemanticPreviewCmd())
	return c
}
func newSemanticPreviewCmd() *cobra.Command {
	var key, dir, input, mcpFrame string
	var maxBytes int
	c := &cobra.Command{Use: "preview", Short: "Calculate original-token Go edits; Apply is unavailable", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunTrustOwned)}
	f := c.Flags()
	f.StringVar(&key, "project-context", "", "exact installed project-context key")
	f.StringVar(&dir, "dir", "", "locator matching installed project root")
	f.StringVar(&input, "input", "", "closed semantic-preview/v1 request file")
	f.IntVar(&maxBytes, "max-bytes", 32768, "complete result bytes including newline, 1024..32768")
	f.StringVar(&mcpFrame, "graph-mcp-frame", "", "internal whole-SDK layout; presentation only")
	_ = f.MarkHidden("graph-mcp-frame")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if input == "" || maxBytes < 1024 || maxBytes > 32768 {
			return semanticError(semanticpreview.ErrRequest)
		}
		raw, e := graphcmd.ReadSourceInput(input)
		if e != nil {
			return semanticError(e)
		}
		q, e := semanticpreview.DecodeRequest(raw)
		if e != nil {
			return semanticError(e)
		}
		var layout *resultwire.GraphFrameLayout
		if mcpFrame != "" {
			l, e := resultwire.DecodeGraphFrame(mcpFrame)
			if e != nil || l.Ceiling != maxBytes {
				return semanticError(semanticpreview.ErrRequest)
			}
			layout = &l
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		cmd.SetContext(ctx)
		r, e := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
		if e != nil {
			return e
		}
		defer r.Close()
		p, e := semanticpreview.Prepare(ctx, r, q, runtimeassembly.Options{})
		if e != nil {
			return semanticError(e)
		}
		defer p.Close()
		var frame []byte
		if layout == nil {
			frame, e = p.Frame(ctx, resolveVersion(), maxBytes)
		} else {
			frame, e = p.FrameForMCP(ctx, resolveVersion(), *layout)
		}
		if e != nil {
			return semanticError(e)
		}
		if e = p.Recheck(ctx); e != nil {
			return semanticError(e)
		}
		emittedResult = true
		// Direct CLI retains the real read session until the complete write returns.
		// A captured MCP child reports observations, never final-write effect authority.
		return writeRootFrameContext(ctx, cmd.OutOrStdout(), frame)
	}
	return withResult(c, resultdto.OperationSemanticPreview)
}
func semanticError(e error) error {
	code := "SEMANTIC_PROJECT_NOT_READY"
	exit := resultdto.ExitOperational
	switch e {
	case semanticpreview.ErrRequest:
		code = "SEMANTIC_REQUEST_INVALID"
		exit = resultdto.ExitUsage
	case semanticpreview.ErrAnchor:
		code = "SEMANTIC_ANCHOR_STALE"
	case semanticpreview.ErrSyntax:
		code = "SEMANTIC_SYNTAX_INVALID"
	case semanticpreview.ErrOverlap:
		code = "SEMANTIC_EDIT_OVERLAP"
		exit = resultdto.ExitUsage
	case semanticpreview.ErrBudget:
		code = "SEMANTIC_OUTPUT_BUDGET"
	}
	return resultdto.NewError(code, exit, e)
}
