package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() {
	rootCmd.AddCommand(newMCPServerCmd())
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
		Short: "MCP-сервер: команды tplaiter как инструменты для AI-агентов (stdio JSON-RPC)",
		Long: "Запускает MCP-сервер поверх CLI tplaiter (заимствование из goca, " +
			"docs/research/clean-codegen.md §1): ~20 tools (repo/template/project/gen/...) " +
			"доступны AI-агентам по протоколу MCP через stdio. Каждый tool исполняет tplaiter " +
			"отдельным процессом с раздельными аргументами (без shell-интерполяции).\n\n" +
			"Логи сервера идут в stderr (stdout занят протоколом). " +
			"`--print-config claude|cursor|vscode` печатает готовый сниппет конфигурации клиента.",
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
		"напечатать JSON-сниппет конфигурации MCP-клиента ("+strings.Join(mcpsrv.SupportedPrintConfigClients(), "|")+") и выйти")
	c.Flags().BoolVar(&direct, "direct", false,
		"не наследовать HTTP(S)_PROXY/ALL_PROXY/NO_PROXY в MCP tools и их дочерние процессы")
	return c
}
