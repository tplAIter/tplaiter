package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
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
				return fmt.Errorf("cmd: mcp-server: определение пути к бинарнику: %w", err)
			}

			if printConfig != "" {
				snippet, err := mcpsrv.PrintConfig(printConfig, exe)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), snippet)
				return nil
			}

			if direct {
				for _, key := range []string{
					"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
					"http_proxy", "https_proxy", "all_proxy", "no_proxy",
				} {
					if err := os.Unsetenv(key); err != nil {
						return fmt.Errorf("cmd: mcp-server: очистка %s: %w", key, err)
					}
				}
			}

			fmt.Fprintf(os.Stderr, "tplaiter mcp-server: старт (bin=%s)\n", exe)
			srv := mcpsrv.New(exe, resolveVersion(), execx.Exec{})
			return srv.ServeStdio()
		},
	}

	c.Flags().StringVar(&printConfig, "print-config", "",
		"напечатать JSON-сниппет конфигурации MCP-клиента ("+strings.Join(mcpsrv.SupportedPrintConfigClients(), "|")+") и выйти")
	c.Flags().BoolVar(&direct, "direct", false,
		"не наследовать HTTP(S)_PROXY/ALL_PROXY/NO_PROXY в MCP tools и их дочерние процессы")
	return c
}
