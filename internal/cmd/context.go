package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextcmd"
	"github.com/tplAIter/tplaiter/internal/mcpsrv"
	"github.com/tplAIter/tplaiter/internal/resultdto"
)

func init() { registerCommand(newContextCmd) }

func newContextCmd() *cobra.Command {
	c := &cobra.Command{Use: "context", Short: "Read bounded context from installed signed sources", Annotations: prerunAnnotations(prerunReadonly)}
	for _, action := range []string{"discover", "search", "get", "plan", "continue", "schema"} {
		c.AddCommand(newContextActionCmd(action))
	}
	return c
}

func newContextActionCmd(action string) *cobra.Command {
	var req contextcmd.Request
	var key, dir, requestJSON string
	c := &cobra.Command{Use: action, Short: "Context " + action, Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunReadonly)}
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if requestJSON != "" {
			for _, name := range []string{"id", "kind", "path", "text", "catalog-path", "required", "limit", "max-records", "max-bytes", "max-excerpt-bytes", "cursor", "snapshot"} {
				if cmd.Flags().Changed(name) {
					return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
				}
			}
			if err := canonicaljson.DecodeStrict([]byte(requestJSON), &req); err != nil {
				return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
			}
			if req.Action != "" && req.Action != action {
				return resultdto.NewError(contextcmd.Invalid, resultdto.ExitUsage, nil)
			}
		}
		req.Action = action
		if action == "schema" {
			// Full schemas are pulled on demand, never repeated in every descriptor.
			raw, err := mcpsrv.ContextFullSchema()
			if err != nil {
				return err
			}
			data := resultdto.ContextData{Action: action, Entries: []resultdto.ContextEntry{}, WindowState: "unknown", WindowReason: contextcmd.WindowUnknown, Schema: raw}
			for range 32 {
				b, e := json.Marshal(data)
				if e != nil {
					return e
				}
				if data.Bytes == len(b) {
					break
				}
				data.Bytes = len(b)
			}
			return emitData(cmd, resultdto.OperationContextQuery, nil, data)
		}
		r, err := nativeGenRuntime(cmd, nativeGenControls{key: key, dir: dir})
		if err != nil {
			return err
		}
		defer r.Close()
		data, err := contextcmd.Run(cmd.Context(), r, req)
		if err != nil {
			exit := resultdto.ExitTrust
			var invalid *contextcmd.Error
			if errors.As(err, &invalid) && invalid.Code == contextcmd.Invalid {
				exit = resultdto.ExitUsage
			}
			return resultdto.NewError(contextcmd.Code(err), exit, err)
		}
		env := newResult(resultdto.OperationContextQuery)
		env.Project = trustProject(r.ProjectContext())
		if err = env.SetData(data); err != nil {
			return err
		}
		if action == "plan" {
			env.Status = resultdto.StatusBlocked
			env.Diagnostics = []resultdto.Diagnostic{{Code: contextcmd.WindowUnknown, Severity: "error", Message: "Local byte retrieval plan completed; trusted model window remains unknown and no token allowance is issued", Details: map[string]any{}}}
			return emitResult(cmd, env, resultdto.ExitUnavailable, nil)
		}
		if jsonMode(cmd) {
			return emitResult(cmd, env, resultdto.ExitSuccess, nil)
		}
		raw, err := json.Marshal(data)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
		return err
	}
	f := c.Flags()
	f.StringVar(&key, "project-context", "", "exact installed project-context key")
	f.StringVar(&dir, "dir", "", "locator that must equal the registered project root")
	f.StringVar(&requestJSON, "request", "", "typed selector/bounds JSON; never catalog or authority material")
	f.StringVar(&req.ID, "id", "", "exact namespaced item/path ID")
	f.StringVar(&req.Kind, "kind", "", "block, skill, resource or path")
	f.StringVar(&req.Path, "path", "", "exact signed source path")
	f.StringVar(&req.Text, "text", "", "literal case-sensitive metadata substring")
	f.StringVar(&req.CatalogPath, "catalog-path", "", "catalog inside the signed snapshot; no filesystem JSON reader")
	f.StringArrayVar(&req.Required, "required", nil, "mandatory context ID (repeatable)")
	f.IntVar(&req.Limit, "limit", 0, "primary entries per page (default 8, maximum 16)")
	f.IntVar(&req.MaxRecords, "max-records", 0, "records plus pinned sources (default 64, maximum 256)")
	f.IntVar(&req.MaxBytes, "max-bytes", 0, "local wire/output obligations and compact data JSON byte bound (default/maximum 32768)")
	f.IntVar(&req.MaxExcerptBytes, "max-excerpt-bytes", 0, "complete-line excerpt byte bound (default 512, maximum 2048)")
	f.StringVar(&req.Cursor, "cursor", "", "snapshot/query/scope/bounds-bound continuation")
	f.StringVar(&req.Snapshot, "snapshot", "", "require this exact observed snapshot")
	return withResult(c, resultdto.OperationContextQuery)
}
