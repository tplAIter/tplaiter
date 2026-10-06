package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/graphcmd"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/resultwire"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/templatequery"
	d "github.com/tplAIter/tplaiter/pkg/templatediscovery"
)

func newTemplateDiscoverCmd() *cobra.Command {
	var q d.Query
	var dir, sourceInput, projectKey, mcpFrame string
	c := &cobra.Command{Use: "discover", Short: "Rank bounded immutable template context for a task without mutation", Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly), RunE: func(cmd *cobra.Command, _ []string) error {
		normalized, err := d.Normalize(q)
		if err != nil {
			return err
		}
		var layout *resultwire.DiscoveryFrameLayout
		if mcpFrame != "" {
			v, e := resultwire.DecodeDiscoveryFrame(mcpFrame)
			if e != nil || v.Ceiling != normalized.MaxBytes {
				return d.ErrInput
			}
			layout = &v
		}
		home, err := state.Home()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()
		if sourceInput != "" {
			r, err := composeRuntimeForProject(ctx, projectKey)
			if err != nil {
				return err
			}
			defer r.Close()
			if dir != "" && dir != r.ProjectContext().RootPath {
				return templatequery.ErrSource
			}
			if dir != "" {
				normalized.Facts = templatequery.ObserveProject(dir)
			}
			raw, err := graphcmd.ReadSourceInput(sourceInput)
			if err != nil {
				return err
			}
			key := r.ProjectContext().Key
			observed, err := templatequery.Admit(ctx, r, raw, sourceInput, key, normalized)
			if err != nil {
				if errors.Is(err, templatequery.ErrOutputBudget) {
					return resultdto.NewError("DISCOVERY_OUTPUT_BUDGET", resultdto.ExitOperational, err)
				}
				return err
			}
			defer observed.Close()
			return emitDiscoveryOwned(ctx, cmd, observed.Result(), normalized.MaxBytes, observed, layout)
		}
		if projectKey != "" {
			return d.ErrInput
		}
		data, err := templatequery.Discover(ctx, home, dir, normalized)
		if err != nil {
			return err
		}
		return emitDiscoveryOwned(ctx, cmd, data, normalized.MaxBytes, nil, layout)
	}}
	f := c.Flags()
	f.StringVar(&mcpFrame, "discovery-mcp-frame", "", "Fixed discovery-only SDK frame presentation; never authority")
	_ = f.MarkHidden("discovery-mcp-frame")
	f.StringVar(&q.Task, "task", "", "Natural task; matched against declared descriptive metadata")
	f.StringVar(&sourceInput, "source-input", "", "Optional original pinned source selection through installed source admission")
	f.StringVar(&projectKey, "project-context", "", "Exact installed context key for admitted catalog discovery")
	f.StringVar(&dir, "dir", "", "Optional observed project directory; reads only fixed bounded files")
	f.StringVar(&q.Language, "language", "", "Exact declared language constraint")
	f.StringVar(&q.Framework, "framework", "", "Exact declared framework constraint")
	f.StringArrayVar(&q.Labels, "label", nil, "Declared group=value constraint (AND)")
	f.IntVar(&q.MaxCandidates, "max-candidates", 64, "Ranked candidate shortlist (1..256), score/ID order before cutoff; input work bounded4096")
	f.IntVar(&q.MaxResults, "limit", 5, "Result budget (1..20)")
	f.IntVar(&q.MaxBytes, "max-bytes", 16384, "Total emitted envelope budget (2048..65536 bytes)")
	return withResult(c, resultdto.OperationTemplateDiscover)
}
func emitDiscovery(cmd *cobra.Command, data d.Result, maxBytes int) error {
	return emitDiscoveryOwned(cmd.Context(), cmd, data, maxBytes, nil, nil)
}
func emitDiscoveryOwned(ctx context.Context, cmd *cobra.Command, data d.Result, maxBytes int, owner *templatequery.AdmittedObservation, layout *resultwire.DiscoveryFrameLayout) error {
	for i := 0; i < 10; i++ {
		env := newResult(resultdto.OperationTemplateDiscover)
		if err := env.SetData(data); err != nil {
			return err
		}
		raw, err := resultdto.MarshalCanonical(env)
		if err != nil {
			return err
		}
		wireBytes := len(raw) + 1
		if layout != nil {
			frame, e := resultwire.Frame(layout.RequestID(), resultwire.Structured(env, false))
			if e != nil {
				return e
			}
			wireBytes = len(frame)
		}
		if wireBytes <= maxBytes {
			if owner != nil {
				if err := owner.Recheck(ctx); err != nil {
					return err
				}
			}
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		// Reserve exact envelope overhead plus a small fixed-point margin. Never
		// print a partial JSON record or omit the mandatory budget/refusal floor.
		remaining := maxBytes - (wireBytes - data.Budget.Bytes) - 64
		// Escaping and SDK wrappers can expand optional records. Shrink whole
		// optional records progressively before deciding the mandatory floor fails.
		if remaining < 512 {
			remaining = data.Budget.Bytes / 2
			if remaining < 512 {
				remaining = 512
			}
		}
		if owner != nil {
			data, err = owner.Fit(ctx, remaining)
		} else {
			data, err = d.Fit(data, remaining)
		}
		if err != nil {
			return resultdto.NewError("DISCOVERY_OUTPUT_BUDGET", resultdto.ExitOperational, err)
		}
	}
	return resultdto.NewError("DISCOVERY_OUTPUT_BUDGET", resultdto.ExitOperational, nil)
}
func runPinnedTemplateShow(cmd *cobra.Command, ref, commit, manifestSHA string) error {
	if commit == "" || manifestSHA == "" {
		return templatequery.ErrSource
	}
	home, err := state.Home()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
	defer cancel()
	tpl, alias, err := templatequery.Show(ctx, home, ref, commit, manifestSHA)
	if err != nil {
		return err
	}
	data := templateShowData(alias, tpl.Metadata.Version, []string{}, tpl)
	if jsonMode(cmd) {
		return emitData(cmd, resultdto.OperationTemplateShow, nil, data)
	}
	// This pinned route returns metadata only; it never follows authored docs.
	fmt.Fprintf(cmd.OutOrStdout(), "%s/%s %s\n%s\n", alias, tpl.Metadata.Name, tpl.Metadata.Version, tpl.Metadata.Description)
	return nil
}
