package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/gen"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type nativeGenControls struct {
	key, dir                     string
	noBuild, format, hooks, help bool
}

// These names belong to the command even if a manifest declares them as params.
func nativeGenControl(name string) bool {
	switch name {
	case "project-context", "dir", "no-build", "format", "hooks", "json", "help", "operations":
		return true
	}
	return false
}

func addNativeGenFlags(c *cobra.Command, controls *nativeGenControls) {
	if controls == nil {
		controls = &nativeGenControls{}
	}
	f := c.Flags()
	f.StringVar(&controls.key, "project-context", "", "key of an authenticated installed project context")
	f.StringVar(&controls.dir, "dir", "", "locator; must match the installed project root")
	f.BoolVar(&controls.noBuild, "no-build", false, "request file-only generation without the build gate")
	f.BoolVar(&controls.format, "format", false, "request formatter execution (currently unavailable)")
	f.BoolVar(&controls.hooks, "hooks", false, "request hook execution (currently unavailable)")
}

// Split only command controls. Generator values are parsed later against the
// authenticated manifest; no unknown flag is silently dropped.
func parseNativeGenControls(cmd *cobra.Command, args []string) (nativeGenControls, []string, error) {
	var c nativeGenControls
	fs := pflag.NewFlagSet("gen controls", pflag.ContinueOnError)
	fs.SetOutput(cmd.ErrOrStderr())
	fs.StringVar(&c.key, "project-context", "", "")
	fs.StringVar(&c.dir, "dir", "", "")
	fs.BoolVar(&c.noBuild, "no-build", false, "")
	fs.BoolVar(&c.format, "format", false, "")
	fs.BoolVar(&c.hooks, "hooks", false, "")
	fs.BoolVarP(&c.help, "help", "h", false, "")
	json := fs.Bool("json", false, "")
	var controlArgs, rest []string
	var awaiting string
	terminated := false
	for _, arg := range args {
		if awaiting != "" {
			if strings.HasPrefix(arg, "-") {
				return c, nil, fmt.Errorf("gen: --%s requires a value", awaiting)
			}
			controlArgs = append(controlArgs, arg)
			awaiting = ""
			continue
		}
		if terminated || arg == "--" {
			terminated = true
			rest = append(rest, arg)
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		name, _, hasValue := strings.Cut(name, "=")
		if arg == "-h" {
			name = "help"
		}
		if (strings.HasPrefix(arg, "--") || arg == "-h") && fs.Lookup(name) != nil {
			controlArgs = append(controlArgs, arg)
			if (name == "project-context" || name == "dir") && !hasValue {
				awaiting = name
			}
		} else {
			rest = append(rest, arg)
		}
	}
	if awaiting != "" {
		return c, nil, fmt.Errorf("gen: --%s requires a value", awaiting)
	}
	if err := fs.Parse(controlArgs); err != nil {
		return c, nil, err
	}
	if fs.Changed("json") {
		if cmd.Flags().Lookup("json") == nil {
			cmd.Flags().Bool("json", false, "")
		}
		if err := cmd.Flags().Set("json", strconv.FormatBool(*json)); err != nil {
			return c, nil, err
		}
	}
	return c, rest, nil
}

func nativeGenUnavailable() error {
	return resultdto.NewError("TRUST_GENERATION_EXECUTION_UNAVAILABLE", resultdto.ExitUnavailable, gen.ErrExecutionUnavailable)
}

func nativeGenOwnership() error {
	return resultdto.NewError("TRUST_NATIVE_OWNERSHIP_UNCERTAIN", resultdto.ExitTrust, nil)
}

func nativeGenRuntime(cmd *cobra.Command, c nativeGenControls) (*trustload.Runtime, error) {
	if err := readonlyContext(cmd.Context()); err != nil {
		return nil, err
	}
	r, err := composeRuntimeForProject(cmd.Context(), c.key)
	if err != nil {
		return nil, err
	}
	if c.dir != "" {
		abs, err := filepath.Abs(c.dir)
		if err != nil || filepath.Clean(abs) != r.ProjectContext().RootPath {
			r.Close()
			return nil, resultdto.NewError("TRUST_PROJECT_CONTEXT_MISMATCH", resultdto.ExitTrust, nil)
		}
	}
	return r, nil
}

// Read a finite, registered metadata set through existing no-follow readers.
// VerifyStable authenticates its ownership; the source closure comes only from
// the concrete runtime's signed snapshot, never from a legacy manifest/CWD.
func nativeGenCatalog(ctx context.Context, r *trustload.Runtime) (*manifest.Template, settings.Values, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, nil, nativeGenOwnership()
	}
	root := r.ProjectContext().RootPath
	if _, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return nil, nil, err
	}
	read := func(name string) ([]byte, error) {
		return readFixedTrustDocument(ctx, filepath.Join(root, ".tplaiter", name))
	}
	markerRaw, err := read("project.yaml")
	if err != nil {
		return nil, nil, nativeGenOwnership()
	}
	var marker stateledger.ProjectV2
	if err := yaml.Unmarshal(markerRaw, &marker); err != nil {
		return nil, nil, nativeGenOwnership()
	}
	if err := r.TrustRuntime().CheckProjectIdentity(ctx, root, marker.ID); err != nil {
		return nil, nil, err
	}
	rootRaw, err := readRegisteredLock(ctx, root, "root-template.lock.json")
	if err != nil {
		return nil, nil, nativeGenOwnership()
	}
	lock, err := provenance.DecodeRootTemplateLock(rootRaw)
	if err != nil {
		return nil, nil, nativeGenOwnership()
	}
	s := lock.Root
	resolution, err := r.TrustRuntime().VerifySubject(ctx, trustverify.Subject{Origin: s.Origin, TemplatePath: s.TemplatePath, RequestedRef: s.RequestedRef, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}, trustverify.EvidenceRefs{Format: bootstrap.PublisherStatementAPIVersion, StatementCAS: s.StatementCAS, SignatureCAS: s.SignatureCAS, KeyFingerprint: s.KeyFingerprint, CheckpointCAS: s.CheckpointCAS, InclusionProofCAS: s.InclusionProofCAS})
	if err != nil {
		return nil, nil, err
	}
	images, err := resources.PlanNativeGeneratorImages(r.TrustRuntime(), resolution, *lock)
	if err != nil {
		return nil, nil, err
	}
	actualLock, err := read("resources.lock.json")
	if err != nil {
		return nil, nil, nativeGenOwnership()
	}
	expectedLock, err := canonicaljson.Canonical(images.Lock)
	if err != nil || !bytes.Equal(actualLock, expectedLock) {
		return nil, nil, nativeGenOwnership()
	}
	for name, expected := range images.Files {
		actual, err := readRegisteredPreimageFile(ctx, root, name, 64<<20)
		if err != nil || !bytes.Equal(actual, expected) {
			return nil, nil, nativeGenOwnership()
		}
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(resolution)
	if err != nil {
		return nil, nil, err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return nil, nil, nativeGenOwnership()
	}
	if _, err := operationtrust.DecodeNativeContract(snapshot.ContractBytes(), raw); err != nil {
		return nil, nil, err
	}
	tpl, err := manifest.ParseTemplate(raw)
	if err != nil {
		return nil, nil, err
	}
	if err := tpl.Validate(); err != nil {
		return nil, nil, err
	}
	values := settings.Values{}
	for k, a := range marker.Answers {
		values[k] = a.Value
	}
	resolved, err := settings.Resolve(tpl, values)
	if err != nil {
		return nil, nil, err
	}
	// No returned settings can outlive a changed sealed marker or root lock.
	for name, expected := range map[string][]byte{"project.yaml": markerRaw, "root-template.lock.json": rootRaw, "resources.lock.json": actualLock} {
		actual, err := read(name)
		if err != nil || !bytes.Equal(actual, expected) {
			return nil, nil, nativeGenOwnership()
		}
	}
	if _, err := stateledger.VerifyStable(ctx, root, r.TrustRuntime(), stateledger.StableVerifyOptions{}); err != nil {
		return nil, nil, err
	}
	return tpl, resolved.Values, nil
}

func parseNativeGenParams(cmd *cobra.Command, g *manifest.Generator, args []string) (map[string]string, error) {
	fs := pflag.NewFlagSet("gen "+g.Kind, pflag.ContinueOnError)
	fs.SetOutput(cmd.ErrOrStderr())
	for _, p := range g.Params {
		if nativeGenControl(p.Name) || fs.Lookup(p.Name) != nil {
			return nil, fmt.Errorf("gen: reserved or duplicate parameter --%s", p.Name)
		}
		fs.String(p.Name, gen.DefaultFor(&p), paramUsage(&p))
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, errors.New("gen: unexpected positional parameter")
	}
	provided := map[string]string{}
	fs.Visit(func(f *pflag.Flag) { provided[f.Name] = f.Value.String() })
	return provided, nil
}

func nativeGenActionPolicy(tpl *manifest.Template, c nativeGenControls) error {
	// --no-build is an explicit file-only request. Default build must never be
	// silently omitted, including when the manifest has no build command.
	if !c.noBuild || c.format || c.hooks {
		return nativeGenUnavailable()
	}
	// Configured actions cannot be treated as successful or skipped implicitly.
	if len(tpl.Hooks.PostCreate) != 0 || len(tpl.Hooks.PostUpdate) != 0 || len(tpl.Requires.Tools) != 0 || len(tpl.Environment.Playbooks) != 0 || tpl.AIConfig.Path != "" {
		return nativeGenUnavailable()
	}
	if len(tpl.Commands) != 0 {
		return nativeGenUnavailable()
	}
	return nil
}

func runNativeGen(cmd *cobra.Command, c nativeGenControls, input []genBatchInput, dynamic []string) error {
	if !c.noBuild || c.format || c.hooks {
		return nativeGenUnavailable()
	}
	r, err := nativeGenRuntime(cmd, c)
	if err != nil {
		return err
	}
	defer r.Close()
	tpl, _, err := nativeGenCatalog(cmd.Context(), r)
	if err != nil {
		return err
	}
	if err := nativeGenActionPolicy(tpl, c); err != nil {
		return err
	}
	operations := make([]gen.NativeOperation, 0, len(input))
	for i, item := range input {
		g, err := gen.Lookup(tpl, item.Kind)
		if err != nil {
			return err
		}
		provided := item.Params
		if dynamic != nil || resultOperation(cmd) != resultdto.OperationGenBatch {
			provided, err = parseNativeGenParams(cmd, g, dynamic)
			if err != nil {
				return err
			}
		}
		for _, p := range g.Params {
			if nativeGenControl(p.Name) {
				return fmt.Errorf("gen: reserved parameter --%s", p.Name)
			}
		}
		for name := range provided {
			if nativeGenControl(name) {
				return fmt.Errorf("gen batch: control --%s is not a parameter", name)
			}
		}
		if err := validateGenBatchParams(g.Params, provided); err != nil {
			return fmt.Errorf("gen: operation %d: %w", i+1, err)
		}
		// Validate patterns/required params before opening a transaction. NativePlan
		// repeats this validation using its own authenticated inputs.
		if _, _, err := gen.ResolveParams(g, provided); err != nil {
			return err
		}
		operations = append(operations, gen.NativeOperation{Kind: item.Kind, Name: item.Name, Provided: provided})
	}
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	if home == "" {
		return resultdto.NewError("TPL-E-NATIVE-HOME-001", resultdto.ExitOperational, nil)
	}
	plan, err := gen.PlanNative(cmd.Context(), r, home, operations)
	if err != nil {
		return err
	}
	// Detached reporting data is captured before any effect but emitted only
	// after the concrete transaction confirms commit.
	res := plan.Result()
	tx, err := projecttransaction.BeginNative(cmd.Context(), plan)
	if tx != nil {
		defer tx.Release()
	}
	if err != nil {
		return err
	}
	if err := tx.Apply(cmd.Context()); err != nil {
		return rollbackNativeGen(cmd.Context(), tx, err)
	}
	if err := tx.Commit(cmd.Context()); err != nil {
		return rollbackNativeGen(cmd.Context(), tx, err)
	}
	return emitNativeGenResult(cmd, r.ProjectContext(), res, c.noBuild)
}

func rollbackNativeGen(ctx context.Context, tx *projecttransaction.Transaction, cause error) error {
	// Cancellation must not prevent the exact native owner from attempting
	// rollback. A rollback conflict is surfaced with the original failure.
	if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil {
		return resultdto.NewError("TPL-E-NATIVE-ROLLBACK-001", resultdto.ExitTransaction, errors.Join(cause, err))
	}
	return cause
}

func emitNativeGenResult(cmd *cobra.Command, project trustload.ProjectContext, res gen.BatchResult, noBuild bool) error {
	if !jsonMode(cmd) {
		return printGenBatchResult(cmd, &res)
	}
	op := resultOperation(cmd)
	if op == "" {
		op = resultdto.OperationGenRun
	}
	env := newResult(op)
	env.Project = trustProject(project)
	for _, path := range res.CreatedFiles {
		env.Changes = append(env.Changes, resultdto.Change{Path: path, Action: "write"})
	}
	for _, path := range res.EditedFiles {
		env.Changes = append(env.Changes, resultdto.Change{Path: path, Action: "write"})
	}
	if len(env.Changes) != 0 {
		env.Status = resultdto.StatusChanges
	}
	if err := env.SetData(resultdto.GenRunData{Created: nonNil(res.CreatedFiles), Edited: nonNil(res.EditedFiles), NoBuild: noBuild}); err != nil {
		return err
	}
	return emitResult(cmd, env, resultdto.ExitSuccess, nil)
}

func listNativeGen(cmd *cobra.Command, c nativeGenControls) error {
	r, err := nativeGenRuntime(cmd, c)
	if err != nil {
		return err
	}
	defer r.Close()
	tpl, values, err := nativeGenCatalog(cmd.Context(), r)
	if err != nil {
		return err
	}
	statuses := gen.List(tpl, values)
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Kind < statuses[j].Kind })
	if !jsonMode(cmd) {
		return printGenList(cmd, statuses)
	}
	data := resultdto.GenListData{Generators: []resultdto.GeneratorInfo{}}
	for _, st := range statuses {
		data.Generators = append(data.Generators, resultdto.GeneratorInfo{Kind: st.Kind, Description: st.Description, Available: st.Available, Reason: st.Reason})
	}
	return emitData(cmd, resultdto.OperationGenList, trustProject(r.ProjectContext()), data)
}
