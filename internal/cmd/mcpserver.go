package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() {
	registerCommand(newMCPServerCmd)
}

// newMCPServerCmd creates `tplaiter mcp-server`: exposes tplaiter commands as
// MCP tools for AI agents over stdio JSON-RPC.
//
// Architecture uses a subprocess pattern: each tool runs the same tplaiter
// binary in a separate process (rather than calling cobra in-process, which
// would leak global flag state between calls). See internal/mcpsrv.
func newMCPServerCmd() *cobra.Command {
	var printConfig string
	var direct bool

	c := &cobra.Command{
		Use:   "mcp-server",
		Short: "MCP server: tplaiter commands as tools for AI agents (stdio JSON-RPC)",
		Long: "Runs an MCP server on top of the tplaiter CLI (pattern borrowed from goca, " +
			"docs/research/clean-codegen.md §1): ~20 tools (repo/template/project/gen/...) " +
			"are available to AI agents via the MCP protocol over stdio. Each tool executes tplaiter " +
			"as a separate process with separate arguments (no shell interpolation).\n\n" +
			"Server logs go to stderr (stdout is occupied by the protocol). " +
			"`--print-config claude|cursor|vscode` prints a ready configuration snippet for the client.",
		Args: cobra.NoArgs,
		// PersistentPreRunE overrides rootPreRun (first-run greeting, suggest check,
		// and registry sync): all write to stdout and/or use the network, which is
		// forbidden while stdout carries the MCP protocol. Child tplaiter processes
		// executing tools run rootPreRun normally, as separate processes whose
		// stdout is captured by the server.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			exe, err := os.Executable()
			if err != nil {
				return errors.New("MCP_UNAVAILABLE")
			}
			// The held stage opens every path component without following
			// symlinks, so resolve the launch path first: installs reached
			// through a symlinked directory (macOS /var, /tmp, package-manager
			// shims) would otherwise report MCP_UNAVAILABLE. The stage still
			// copies and digests the resolved file itself.
			if resolved, resolveErr := filepath.EvalSymlinks(exe); resolveErr == nil {
				exe = resolved
			}

			if printConfig != "" {
				snippet, err := mcpsrv.PrintConfig(printConfig, exe)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), snippet)
				return nil
			}

			in, err := installedInvocation(cmd.Context())
			if err != nil {
				return err
			}
			if err := storeProvisioned(cmd.Context(), in); err != nil {
				return err
			}
			runtime, err := trustload.OpenRuntime(cmd.Context(), trustload.RuntimeOptions{Selection: in.Selection, ProjectKey: in.ProjectKey, Clock: in.Clock})
			if err != nil {
				return err
			}
			scratchRoot := runtime.ScratchRoot()
			if err := runtime.Close(); err != nil {
				return errors.New("MCP_UNAVAILABLE")
			}
			_ = direct // Retained for CLI compatibility; the child environment is always fixed.
			srv := mcpsrv.NewInstalled(exe, resolveVersion(), scratchRoot)
			if srv == nil {
				return errors.New("MCP_UNAVAILABLE")
			}
			return srv.ServeStdio()
		},
	}

	c.Flags().StringVar(&printConfig, "print-config", "",
		"print JSON configuration snippet for MCP client ("+strings.Join(mcpsrv.SupportedPrintConfigClients(), "|")+") and exit")
	c.Flags().BoolVar(&direct, "direct", false,
		"do not inherit HTTP(S)_PROXY/ALL_PROXY/NO_PROXY in MCP tools and their child processes")
	return c
}
