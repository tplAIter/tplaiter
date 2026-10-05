package cmd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tplAIter/tplaiter/internal/linkcmd"
	linktx "github.com/tplAIter/tplaiter/internal/projecttransaction/link"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func init() {
	registerCommand(func() *cobra.Command { return newLinkCmd("link") })
	registerCommand(func() *cobra.Command { return newLinkCmd("adopt") })
}
func linkOperation(action string) resultdto.Operation {
	if action == "adopt" {
		return resultdto.OperationProjectAdopt
	}
	return resultdto.OperationProjectLink
}
func linkError(err error) error {
	if errors.Is(err, linkcmd.ErrInput) {
		return resultdto.NewError("TPL-E-LINK-INPUT", resultdto.ExitUsage, err)
	}
	if errors.Is(err, linkcmd.ErrConflict) || errors.Is(err, linkcmd.ErrState) {
		return resultdto.NewError("TPL-E-LINK-CONFLICT", resultdto.ExitOperational, err)
	}
	if errors.Is(err, linkcmd.ErrExclusion) {
		return resultdto.NewError("TPL-E-LINK-EXCLUSION", resultdto.ExitUnavailable, err)
	}
	return err
}
func newLinkCmd(action string) *cobra.Command {
	var key, dir, source, module string
	var sets, choices []string
	var port int
	var dry bool
	op := linkOperation(action)
	c := &cobra.Command{Use: action + " <commit> <project-name>", Short: "Attach signed native state to an existing project without writing user files", Args: cobra.ExactArgs(2), Annotations: prerunAnnotations(prerunTrustOwned)}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		r, err := composeRuntimeForProject(cmd.Context(), key)
		if err != nil {
			return err
		}
		defer r.Close()
		if dir != "" {
			abs, e := filepath.Abs(dir)
			if e != nil || abs != r.ProjectContext().RootPath {
				return linkError(linkcmd.ErrInput)
			}
		}
		if source == "" {
			return linkError(linkcmd.ErrInput)
		}
		raw, err := readUntrustedDocument(cmd.Context(), source)
		if err != nil {
			return err
		}
		home, err := readonlyHome()
		if err != nil {
			return err
		}
		selected := map[string]string{}
		for _, v := range choices {
			p, choice, ok := strings.Cut(v, "=")
			if !ok || p == "" || selected[p] != "" {
				return linkError(linkcmd.ErrInput)
			}
			selected[p] = choice
		}
		p, err := linkcmd.Prepare(cmd.Context(), r, home, linkcmd.Input{Action: action, Ref: args[0], Name: args[1], Module: module, Sets: sets, Port: port, Source: raw, Choices: selected}, resolveVersion())
		if err != nil {
			return linkError(err)
		}
		id := ""
		if !dry {
			tx, e := linktx.Begin(cmd.Context(), p, p.Fingerprint(), resolveVersion())
			if tx != nil {
				defer tx.Release()
				id = tx.ID()
			}
			if e != nil {
				return resultdto.NewError("TPL-E-LINK-TRANSACTION", resultdto.ExitTransaction, fmt.Errorf("transaction %s: %w", id, e))
			}
			if e = tx.Commit(cmd.Context()); e != nil {
				return resultdto.NewError("TPL-E-LINK-TRANSACTION", resultdto.ExitTransaction, fmt.Errorf("transaction %s: %w", id, e))
			}
		}
		env := newResult(op)
		env.Project = trustProject(r.ProjectContext())
		env.PlanSHA256 = p.Fingerprint()
		env.CurrentRef = args[0]
		env.Status = resultdto.StatusChanges
		if id != "" {
			env.TransactionID = &id
		}
		report := p.Report()
		for _, path := range report.Paths {
			env.Changes = append(env.Changes, resultdto.Change{Path: path, Action: "write"})
		}
		env.Summary.FilesChanged = len(report.Paths)
		data := linkData(action, dry, args[0], report)
		if err = env.SetData(data); err != nil {
			return err
		}
		if jsonMode(cmd) {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s signed state (%s) transaction %s\n", action, map[bool]string{true: "dry-run", false: "committed"}[dry], id)
		return err
	}
	f := c.Flags()
	f.StringVar(&key, "project-context", "", "authenticated installed project context")
	f.StringVar(&dir, "dir", "", "exact installed existing project root")
	f.StringVar(&source, "source-input", "", "pinned signed source selection")
	f.StringVar(&module, "module", "", "project module used to reconstruct signed baseline")
	f.StringArrayVar(&sets, "set", nil, "setting group=value")
	f.StringArrayVar(&choices, "ownership", nil, "explicit conflict choice path=track or path=user-owned")
	f.IntVar(&port, "port", 0, "project port used in signed rendering")
	f.BoolVar(&dry, "dry-run", false, "authenticate and prepare without publication")
	for _, verb := range []string{"continue", "abort"} {
		c.AddCommand(newLinkRecoveryCmd(action, verb))
	}
	return withResult(c, op)
}
func linkData(action string, dry bool, ref string, report linkcmd.Report) resultdto.ProjectLinkData {
	data := resultdto.ProjectLinkData{Action: action, DryRun: dry, Ref: ref, TrackedConflicts: []resultdto.LinkOwnershipChoice{}}
	for _, v := range report.Conflicts {
		choice := resultdto.LinkOwnershipChoice{Path: v.Path, State: v.State, Choice: v.Choice}
		data.OwnershipChoices = append(data.OwnershipChoices, choice)
		if v.Choice == "track" {
			data.TrackedConflicts = append(data.TrackedConflicts, choice)
		} else if v.Choice == "user-owned" {
			data.ExcludedPaths = append(data.ExcludedPaths, v.Path)
		}
	}
	return data
}
func newLinkRecoveryCmd(action, verb string) *cobra.Command {
	var key, dir string
	op := linkOperation(action)
	c := &cobra.Command{Use: verb + " <transaction-id>", Short: "Recover authenticated first-marker state and registry transaction", Args: cobra.ExactArgs(1), Annotations: prerunAnnotations(prerunTrustOwned)}
	c.RunE = func(cmd *cobra.Command, args []string) error {
		r, err := composeRuntimeForProject(cmd.Context(), key)
		if err != nil {
			return err
		}
		defer r.Close()
		if dir != "" {
			abs, e := filepath.Abs(dir)
			if e != nil || abs != r.ProjectContext().RootPath {
				return linkError(linkcmd.ErrInput)
			}
		}
		home, err := readonlyHome()
		if err != nil {
			return err
		}
		tx, err := linktx.Open(cmd.Context(), r, home, args[0], resolveVersion())
		if err != nil {
			return resultdto.NewError("TPL-E-LINK-TRANSACTION", resultdto.ExitTransaction, err)
		}
		defer tx.Release()
		if tx.Report().Action != action {
			return linkError(linkcmd.ErrInput)
		}
		if verb == "abort" {
			err = tx.Abort(cmd.Context())
		} else {
			err = tx.Commit(cmd.Context())
		}
		if err != nil {
			return resultdto.NewError("TPL-E-LINK-TRANSACTION", resultdto.ExitTransaction, err)
		}
		env := newResult(op)
		env.Project = trustProject(r.ProjectContext())
		id := tx.ID()
		env.TransactionID = &id
		if err = env.SetData(linkData(verb, false, tx.Ref(), tx.Report())); err != nil {
			return err
		}
		if jsonMode(cmd) {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s transaction %s\n", action, verb, id)
		return err
	}
	c.Flags().StringVar(&key, "project-context", "", "authenticated installed project context")
	c.Flags().StringVar(&dir, "dir", "", "exact installed project root")
	return withResult(c, op)
}
