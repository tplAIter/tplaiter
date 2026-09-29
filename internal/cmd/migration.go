package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/naming"
)

// newMigrationCmd exposes the explicit two-step compatibility migration. It
// never runs from discovery/help and has no credential-migration capability.
func newMigrationCmd() *cobra.Command {
	var roots, relocations []string
	var apply bool
	var planPath, expectedDigest string
	c := &cobra.Command{
		Use:         "migrate-state --root kind=source:destination [--root ...] | --apply --plan file --expected-digest sha256",
		Annotations: prerunAnnotations(prerunTrustOwned),
		Short:       "Построить или применить явную миграцию состояния",
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if apply {
				if planPath == "" || expectedDigest == "" || len(roots) != 0 || len(relocations) != 0 {
					return errors.New("migrate-state: --apply requires only --plan and --expected-digest")
				}
				b, err := os.ReadFile(planPath)
				if err != nil {
					return err
				}
				var plan naming.Plan
				if err := json.Unmarshal(b, &plan); err != nil {
					return err
				}
				if plan.Digest != expectedDigest {
					return errors.New("migrate-state: expected digest does not match sealed plan")
				}
				receipt, err := naming.Apply(plan)
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(receipt)
			}
			if len(roots) == 0 {
				return errors.New("migrate-state: --root is required when planning")
			}
			planRoots := make([]naming.Root, 0, len(roots))
			for _, raw := range roots {
				kindAndPaths := strings.SplitN(raw, "=", 2)
				if len(kindAndPaths) != 2 {
					return fmt.Errorf("migrate-state: invalid --root %q (want kind=source:destination)", raw)
				}
				paths := strings.SplitN(kindAndPaths[1], ":", 2)
				if len(paths) != 2 || paths[0] == "" || paths[1] == "" {
					return fmt.Errorf("migrate-state: invalid root paths %q", raw)
				}
				planRoots = append(planRoots, naming.Root{Kind: kindAndPaths[0], SourceRoot: paths[0], DestinationRoot: paths[1]})
			}
			if len(relocations) != 0 {
				foundHome := false
				for i := range planRoots {
					if planRoots[i].Kind != "home" {
						continue
					}
					foundHome = true
					for _, raw := range relocations {
						parts := strings.SplitN(raw, "=", 2)
						paths := []string(nil)
						if len(parts) == 2 {
							paths = strings.SplitN(parts[1], ":", 2)
						}
						if len(parts) != 2 || parts[0] == "" || len(paths) != 2 || paths[0] == "" || paths[1] == "" {
							return fmt.Errorf("migrate-state: invalid --relocate %q (want id=old-path:new-path)", raw)
						}
						planRoots[i].Relocations = append(planRoots[i].Relocations, naming.Relocation{ID: parts[0], OldPath: paths[0], NewPath: paths[1]})
					}
					break
				}
				if !foundHome {
					return errors.New("migrate-state: --relocate requires a home root")
				}
			}
			plan, err := naming.PlanRoots(planRoots)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(plan)
		},
	}
	c.Flags().StringSliceVar(&roots, "root", nil, "ledger: home|project=source:destination")
	c.Flags().StringSliceVar(&relocations, "relocate", nil, "declared registry move: id=old-project-root:new-project-root")
	c.Flags().BoolVar(&apply, "apply", false, "apply the sealed migration plan")
	c.Flags().StringVar(&planPath, "plan", "", "path to a reviewed sealed plan")
	c.Flags().StringVar(&expectedDigest, "expected-digest", "", "expected sealed plan digest")
	return c
}
