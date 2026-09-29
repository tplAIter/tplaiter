package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stats"
	"github.com/tplAIter/tplaiter/internal/ui"
)

func init() {
	registerCommand(newStatsCmd)
}

// newStatsCmd creates `tplater stats`: a drift report comparing the generated
// project with a clean render of the pinned template version — file statuses,
// percentage of changed lines (LCS), updateability classification
// (auto/conflict-prone/manual-only), total drift score, and broken anchors.
func newStatsCmd() *cobra.Command {
	var asJSON bool

	c := &cobra.Command{
		Use:   "stats",
		Short: "Показать дрейф проекта от шаблона (drift-score)",
		Long: "Сравнивает чистый рендер зафиксированной версии+ответов шаблона (эталон) с рабочим " +
			"деревом проекта (): по каждому файлу — статус (identical/modified/deleted/extra), " +
			"процент изменённых строк (LCS) и класс обновляемости — auto (update приведёт 3-way чисто), " +
			"conflict-prone (шаблон исторически менял этот файл) или manual-only (удалённый эталонный файл, " +
			"сломанный якорь CODEGEN, правка в copyWithoutRender-артефакте).\n\n" +
			"Выводит суммарный drift-score 0..100, топ-10 файлов по дрейфу, число extra-файлов и сломанных " +
			"якорей. --json даёт стабильную машиночитаемую схему для дашбордов эксплуатации шаблонов.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			home, _, err := state.EnsureHome()
			if err != nil {
				return err
			}

			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("cmd: stats: определение рабочего каталога: %w", err)
			}

			return stats.Run(cmd.Context(), stats.Deps{
				Manager: mgr,
				Home:    home,
				Out:     cmd.OutOrStdout(),
				Err:     cmd.ErrOrStderr(),
				Palette: ui.Default(),
			}, stats.Options{
				StartDir: cwd,
				JSON:     asJSON,
			})
		},
	}

	c.Flags().BoolVar(&asJSON, "json", false, "машиночитаемый JSON-отчёт")
	return c
}
