// Package formatproof connects real formatter execution with authenticated
// retained effects. Transport references never construct a publication permit.
package formatproof

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sort"

	"github.com/tplAIter/tplaiter/internal/blockformatter"
	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextauth"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var (
	ErrUnavailable = errors.New("managed formatter: authenticated projection unavailable")
	ErrInDoubt     = engine.ErrFormatterInDoubt
)

type Prepared struct {
	updateMerged           *operationtrust.ContextUpdateMergedFormatterCalculation
	nativeUpdate           *contextsource.PreparedNativeUpdate
	updateCalculation      *operationtrust.ContextUpdateFormatterCalculation
	nativeIntent           *contextsource.PreparedNativeNew
	sources                *contextauth.VerifiedSourceClosure
	runtime                *trustload.Runtime
	adapter                *blockformatter.RuntimeAdapter
	provider, toolProvider *trustverify.VerifiedResolution
	bound                  *blockformatter.PreparedFormat
	frame                  engine.FormatFrame
	digest                 string
}
type VerifiedPair struct {
	runtime     *trustload.Runtime
	frameDigest string
	output      []byte
	passes      [2]*engine.FormatterPass
}
type Reference struct {
	APIVersion  string `json:"apiVersion"`
	FrameSHA256 string `json:"frameSHA256"`
}

func Prepare(ctx context.Context, r *trustload.Runtime, provider, toolProvider *trustverify.VerifiedResolution, plan blockformatter.Plan, input, contextJSON []byte, operation trustverify.OperationInputs) (*Prepared, error) {
	adapter, err := blockformatter.NewRuntimeAdapter(r)
	if err != nil {
		return nil, err
	}
	selection, err := adapter.SelectManaged(ctx, provider, toolProvider, plan, input, contextJSON)
	if err != nil {
		return nil, err
	}
	// The lifecycle owner supplies actual preimage/answer digests and selected
	// subjects; the formatter adds its two exact selected actions only.
	operation.Actions = append(operation.Actions, selection.Actions()...)
	bound, err := adapter.Bind(ctx, selection, operation)
	if err != nil {
		return nil, err
	}
	raw, err := canonicaljson.Canonical(plan)
	if err != nil {
		return nil, err
	}
	frame := engine.FormatFrame{APIVersion: "tplaiter.dev/formatter-frame/v1", Operation: operation, Requests: bound.Requests(), Plan: raw, Context: append(engine.Bytes{}, contextJSON...), Input: append(engine.Bytes{}, input...)}
	digest, err := frame.Digest()
	if err != nil {
		return nil, err
	}
	return &Prepared{runtime: r, adapter: adapter, provider: provider, toolProvider: toolProvider, bound: bound, frame: frame, digest: digest}, nil
}

func (p *Prepared) Requests() []trustverify.ExecutionRequest {
	if p == nil {
		return nil
	}
	return p.bound.Requests()
}

// PendingRequests reads actual retained ordinal records without creating
// evidence or permits. Displayed requests never confer execution authority.
func (p *Prepared) PendingRequests(ctx context.Context) ([]trustverify.ExecutionRequest, error) {
	if err := p.valid(ctx); err != nil {
		return nil, err
	}
	requests := p.Requests()
	pending := []trustverify.ExecutionRequest{}
	for i, request := range requests {
		pass, err := engine.ReadFormatterEvidence(ctx, p.runtime, p.frame, i+1)
		if os.IsNotExist(err) {
			pending = append(pending, request)
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, err := verifyPass(ctx, p, pass); err != nil {
			return nil, err
		}
	}
	return pending, nil
}

func (p *Prepared) Reference() Reference {
	if p == nil {
		return Reference{}
	}
	version := "tplaiter.dev/formatter-reference/v1"
	if p.frame.APIVersion == "tplaiter.dev/formatter-frame/v3" {
		version = "tplaiter.dev/formatter-reference/v3"
	}
	return Reference{APIVersion: version, FrameSHA256: p.digest}
}

func (p *Prepared) valid(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p == nil || p.runtime == nil || p.runtime.TrustRuntime() == nil {
		return ErrUnavailable
	}
	if p.nativeUpdate != nil {
		if p.nativeIntent != nil || p.updateCalculation == nil {
			return ErrUnavailable
		}
		if err := p.nativeUpdate.RecheckFor(ctx, p.runtime); err != nil {
			return err
		}
		if err := p.updateCalculation.RecheckFor(ctx, p.runtime); err != nil {
			return err
		}
	}
	if p.sources != nil {
		if p.nativeIntent == nil {
			return ErrUnavailable
		}
		if err := p.nativeIntent.RecheckFor(ctx, p.runtime); err != nil {
			return err
		}
		// This guard also covers evidence writes and completed-pass reopening,
		// which do not necessarily issue a new execution permit.
		if err := p.sources.RecheckFor(ctx, p.runtime); err != nil {
			return err
		}
	}
	for _, old := range []*trustverify.VerifiedResolution{p.provider, p.toolProvider} {
		fresh, err := p.runtime.TrustRuntime().VerifySubject(ctx, old.Subject(), old.Evidence())
		if err != nil || fresh == nil || fresh.Subject() != old.Subject() {
			return ErrUnavailable
		}
	}
	digest, err := p.frame.Digest()
	if err != nil || digest != p.digest {
		return ErrUnavailable
	}
	return nil
}

func verifyPass(ctx context.Context, p *Prepared, pass *engine.FormatterPass) (blockformatter.PassData, error) {
	data, err := pass.Data()
	if err != nil {
		return data, err
	}
	err = p.runtime.TrustRuntime().VerifyRetainedApproval(ctx, p.provider, data.Operation, data.Request, data.Approval, data.ObservedAt)
	return data, err
}

func OpenPair(ctx context.Context, p *Prepared, reference Reference) (*VerifiedPair, error) {
	if err := p.valid(ctx); err != nil {
		return nil, err
	}
	if reference != p.Reference() {
		return nil, ErrUnavailable
	}
	var passes [2]*engine.FormatterPass
	var data [2]blockformatter.PassData
	for i := range passes {
		var err error
		passes[i], err = engine.ReadFormatterEvidence(ctx, p.runtime, p.frame, i+1)
		if err != nil {
			return nil, err
		}
		data[i], err = verifyPass(ctx, p, passes[i])
		if err != nil {
			return nil, err
		}
	}
	check, err := blockformatter.CheckRetainedPair(data[0], data[1])
	if err != nil {
		return nil, err
	}
	if err := p.valid(ctx); err != nil {
		return nil, err
	}
	return &VerifiedPair{runtime: p.runtime, frameDigest: p.digest, output: append([]byte(nil), check.Formatted...), passes: passes}, nil
}

// Stage owns the full start/fsync/Execute/cleanup/receipt/completion sequence.
// It never publishes project or registry bytes. Reopened completed effects are
// verified and skipped; an in-doubt effect is never executed again.
func Stage(ctx context.Context, p *Prepared, refs []trustverify.ApprovalRefs) (*VerifiedPair, error) {
	if err := p.valid(ctx); err != nil {
		return nil, err
	}
	store, err := engine.BeginFormatterEvidence(ctx, p.runtime, p.frame)
	if err != nil {
		return nil, err
	}
	defer store.Release()
	var missing [2]bool
	needsExecution := false
	for i := range missing {
		pass, e := store.ReadPass(i + 1)
		if os.IsNotExist(e) {
			missing[i] = true
			needsExecution = true
			continue
		}
		if e != nil {
			return nil, e
		}
		if _, err := verifyPass(ctx, p, pass); err != nil {
			return nil, err
		}
	}
	if needsExecution {
		if len(refs) != 2 {
			return nil, ErrUnavailable
		}
		selected := map[int]trustverify.ApprovalRefs{}
		for i, needed := range missing {
			if needed {
				selected[i+1] = refs[i]
			}
		}
		authorized, err := p.adapter.AuthorizeSelectedPasses(ctx, p.bound, selected)
		if err != nil {
			return nil, err
		}
		for i, needed := range missing {
			if !needed {
				continue
			}
			start, err := store.Start(i + 1)
			if err != nil {
				return nil, err
			}
			pass, err := p.adapter.RunPass(ctx, authorized, i+1)
			if err != nil {
				return nil, err
			}
			if _, err = store.Complete(start, pass); err != nil {
				return nil, err
			}
		}
	}
	return OpenPair(ctx, p, p.Reference())
}

func (v *VerifiedPair) FormattedFor(ctx context.Context, p *Prepared) ([]byte, error) {
	if v == nil || p == nil || v.runtime != p.runtime || v.frameDigest != p.digest {
		return nil, ErrUnavailable
	}
	if err := p.valid(ctx); err != nil {
		return nil, err
	}
	return append([]byte(nil), v.output...), nil
}

// RevalidatePublication grants no process capability. It freshly authorizes
// the retained pair references before a lifecycle owner's existing writer gate.
func RevalidatePublication(ctx context.Context, p *Prepared, pair *VerifiedPair) error {
	if _, err := pair.FormattedFor(ctx, p); err != nil {
		return err
	}
	for _, pass := range pair.passes {
		data, err := verifyPass(ctx, p, pass)
		if err != nil {
			return err
		}
		if err := p.runtime.TrustRuntime().VerifyPublicationApproval(ctx, p.provider, data.Operation, data.Request, data.Approval); err != nil {
			return err
		}
	}
	return p.valid(ctx)
}

// PrepareRootGoFile derives the exact native tool identity from its verified
// source record. The fixed material binder independently verifies that record,
// executable bytes, native envelope and the complete four-entry closure.
func PrepareRootGoFile(ctx context.Context, r *trustload.Runtime, provider, toolProvider *trustverify.VerifiedResolution, path string, input []byte, managed operationtrust.ManagedFormatterContext, operation trustverify.OperationInputs) (*Prepared, error) {
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, path, input)
	if err != nil || len(markers) == 0 {
		return nil, ErrUnavailable
	}
	return prepareRootGoFormat(ctx, r, provider, toolProvider, path, input, managed, operation)
}

// prepareRootGoFormat is also used by the opaque Update preparation for a
// source-managed file whose target removes its last block. The public New/Link
// entry retains its nonempty marker requirement.
func prepareRootGoFormat(ctx context.Context, r *trustload.Runtime, provider, toolProvider *trustverify.VerifiedResolution, path string, input []byte, managed operationtrust.ManagedFormatterContext, operation trustverify.OperationInputs) (*Prepared, error) {
	plan, err := rootGoFormatterPlan(ctx, r, toolProvider, path, input)
	if err != nil {
		return nil, err
	}

	contextJSON, err := canonicaljson.Canonical(managed)
	if err != nil {
		return nil, err
	}
	return Prepare(ctx, r, provider, toolProvider, plan, input, contextJSON, operation)
}

func rootGoFormatterPlan(ctx context.Context, r *trustload.Runtime, toolProvider *trustverify.VerifiedResolution, path string, input []byte) (blockformatter.Plan, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || toolProvider == nil {
		return blockformatter.Plan{}, ErrUnavailable
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(toolProvider)
	if err != nil {
		return blockformatter.Plan{}, err
	}
	raw, exists := snapshot.Blob("formatter/tool.json")
	if !exists || len(raw) > 1<<20 {
		return blockformatter.Plan{}, ErrUnavailable
	}
	var record struct {
		APIVersion      string `json:"apiVersion"`
		Adapter         string `json:"adapter"`
		ToolID          string `json:"toolID"`
		ToolVersion     string `json:"toolVersion"`
		BinarySHA256    string `json:"binarySHA256"`
		VersionEvidence struct {
			Kind     string `json:"kind"`
			Identity string `json:"identity"`
		} `json:"versionEvidence"`
		NativeEnvelope string `json:"nativeEnvelope"`
	}
	if canonicaljson.DecodeStrict(raw, &record) != nil || record.Adapter != "gofmt-stdin-v1" || record.ToolID != "gofmt" {
		return blockformatter.Plan{}, ErrUnavailable
	}
	options := []string{}
	optionsDigest, err := trustverify.ComputeToolOptionsSHA256(options)
	if err != nil {
		return blockformatter.Plan{}, err
	}
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, path, input)
	if err != nil {
		return blockformatter.Plan{}, ErrUnavailable
	}
	plan, err := blockformatter.BuildPlan(blockformatter.PlanInput{Path: path, Language: "go", Adapter: "gofmt-stdin-v1", Tool: trustverify.Tool{ID: record.ToolID, Version: record.ToolVersion, BinarySHA256: record.BinarySHA256, OptionsSHA256: optionsDigest}, Options: options, InputMode: "100644", Markers: markers, TimeoutMillis: 5000, OutputLimitBytes: 16 << 20, Input: input})
	if err != nil {
		return blockformatter.Plan{}, err
	}
	return plan, nil
}

// PrepareContextNativeNewFile consumes a genuine managed calculation and its
// retained closure. Caller paths select only its admitted managed inventory;
// caller bytes, source labels and actions-empty digests cannot become a frame.
func PrepareContextNativeNewFile(ctx context.Context, r *trustload.Runtime, intent *contextsource.PreparedNativeNew, toolProvider *trustverify.VerifiedResolution, path string, registryDigest string, render renderref.Input, renderer string) (*Prepared, error) {
	if ctx == nil || r == nil || intent == nil || !validLinkObservationDigest(registryDigest) {
		return nil, ErrUnavailable
	}
	if err := intent.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	sources, err := intent.FormatterSources(ctx, r)
	if err != nil {
		return nil, err
	}
	inventory, err := intent.ManagedFiles(ctx, r)
	if err != nil {
		return nil, err
	}
	found := false
	for _, file := range inventory {
		if file.Path == path && file.Mode == "100644" {
			found = true
		}
	}
	if !found {
		return nil, ErrUnavailable
	}
	rendered, err := intent.Rendered(ctx, r)
	if err != nil {
		return nil, err
	}
	if rendered.Template.ManagedBlocks != nil && len(rendered.Template.ManagedBlocks.Replacements) != 0 {
		return nil, ErrUnavailable
	}
	input, ok := rendered.Files[path]
	if !ok {
		return nil, ErrUnavailable
	}
	for _, file := range inventory {
		if file.Path == path && file.InputSHA256 != evidencecas.Digest(input) {
			return nil, ErrUnavailable
		}
	}
	root, err := intent.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	dependencies, err := intent.DependencyLock(ctx, r)
	if err != nil {
		return nil, err
	}
	contextDigest, err := intent.ContextDigest(ctx, r)
	if err != nil {
		return nil, err
	}
	graph, err := intent.SourceGraph(ctx, r)
	if err != nil {
		return nil, err
	}
	graphDigest, err := bootstrap.DomainDigest("tplaiter.dev/managed-formatter-source-graph/v2", graph)
	if err != nil {
		return nil, err
	}
	operation, err := intent.OperationBase(ctx, r)
	if err != nil {
		return nil, err
	}
	if len(operation.Actions) != 0 || operation.Scope != "new" {
		return nil, ErrUnavailable
	}
	if toolProvider == nil || !toolProvider.ValidFor(r.TrustRuntime(), r.TrustRuntime().Binding()) {
		return nil, ErrUnavailable
	}
	tool := toolProvider.Subject()
	operation.Subjects = append(operation.Subjects, trustverify.Provider{Origin: tool.Origin, TemplatePath: tool.TemplatePath, Commit: tool.Commit, TreeSHA256: tool.TreeSHA256, ContractSHA256: tool.ContractSHA256})
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	sort.Slice(operation.Subjects, func(i, j int) bool { return key(operation.Subjects[i]) < key(operation.Subjects[j]) })
	subjects := []trustverify.Provider{}
	for _, subject := range operation.Subjects {
		if len(subjects) > 0 && key(subjects[len(subjects)-1]) == key(subject) {
			if subjects[len(subjects)-1] != subject {
				return nil, ErrUnavailable
			}
			continue
		}
		subjects = append(subjects, subject)
	}
	operation.Subjects = subjects
	contextData := operationtrust.ContextNewFormatterContext{APIVersion: "tplaiter.dev/managed-formatter-context/v2", Role: "clean-target", SourceRootLockSHA256: root.RootLockSHA256, TargetRootLockSHA256: root.RootLockSHA256, ReplacementDeclarationsSHA256: evidencecas.Digest([]byte(`{"replacements":[],"version":1}`)), DecisionsSHA256: evidencecas.Digest([]byte(`{"apiVersion":"tplaiter.dev/managed-decisions/v1","decisions":[]}`)), ObservedProjectSHA256: evidencecas.Digest(nil), ObservedRegistrySHA256: registryDigest, RendererAnswersSHA256: operation.AnswersSHA256, DependencyLockSHA256: dependencies.LockSHA256, SourceGraphSHA256: graphDigest, NativeContextSHA256: contextDigest}
	raw, err := canonicaljson.Canonical(contextData)
	if err != nil {
		return nil, err
	}
	plan, err := rootGoFormatterPlan(ctx, r, toolProvider, path, input)
	if err != nil {
		return nil, err
	}
	adapter, err := blockformatter.NewRuntimeAdapter(r)
	if err != nil {
		return nil, err
	}
	calculation, err := operationtrust.PrepareContextNewFormatterCalculation(ctx, r, sources, render, renderer)
	if err != nil {
		return nil, err
	}
	selection, err := adapter.SelectContextNativeNew(ctx, calculation, toolProvider, plan, input, raw)
	if err != nil {
		return nil, err
	}
	operation.Actions = append(operation.Actions, selection.Actions()...)
	bound, err := adapter.BindContextNativeNew(ctx, selection, operation)
	if err != nil {
		return nil, err
	}
	planRaw, err := canonicaljson.Canonical(plan)
	if err != nil {
		return nil, err
	}
	frame := engine.FormatFrame{APIVersion: "tplaiter.dev/formatter-frame/v2", Operation: operation, Requests: bound.Requests(), Plan: planRaw, Context: append(engine.Bytes{}, raw...), Input: append(engine.Bytes{}, input...)}
	digest, err := frame.Digest()
	if err != nil {
		return nil, err
	}
	provider, err := sources.RootResolution(ctx, r)
	if err != nil {
		return nil, err
	}
	return &Prepared{runtime: r, adapter: adapter, provider: provider, toolProvider: toolProvider, bound: bound, frame: frame, digest: digest, nativeIntent: intent, sources: sources}, nil
}

// PrepareContextNativeUpdateFile binds the genuine recorded two-closure intent
// to one clean target's two real requests. The action-empty base is not a grant.
func PrepareContextNativeUpdateFile(ctx context.Context, r *trustload.Runtime, intent *contextsource.PreparedNativeUpdate, calculation *operationtrust.ContextUpdateFormatterCalculation, toolProvider *trustverify.VerifiedResolution, path string) (*Prepared, error) {
	if intent == nil || calculation == nil || r == nil {
		return nil, ErrUnavailable
	}
	if err := intent.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	c, err := calculation.Context(ctx, r)
	if err != nil {
		return nil, err
	}
	source, err := intent.SourceSnapshot(ctx, r)
	if err != nil {
		return nil, err
	}
	target, err := intent.TargetSnapshot(ctx, r)
	if err != nil {
		return nil, err
	}
	sourceRoot, err := source.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	targetRoot, err := target.RootLock(ctx, r)
	if err != nil {
		return nil, err
	}
	sourceDeps, err := source.DependencyLock(ctx, r)
	if err != nil {
		return nil, err
	}
	targetDeps, err := target.DependencyLock(ctx, r)
	if err != nil {
		return nil, err
	}
	sourceDigest, err := source.ContextDigest(ctx, r)
	if err != nil {
		return nil, err
	}
	targetDigest, err := target.ContextDigest(ctx, r)
	if err != nil {
		return nil, err
	}
	operation, err := intent.OperationBase(ctx, r)
	if err != nil {
		return nil, err
	}
	if c.SourceRootLockSHA256 != sourceRoot.RootLockSHA256 || c.TargetRootLockSHA256 != targetRoot.RootLockSHA256 || c.SourceDependencyLockSHA256 != sourceDeps.LockSHA256 || c.TargetDependencyLockSHA256 != targetDeps.LockSHA256 || c.SourceNativeContextSHA256 != sourceDigest || c.TargetNativeContextSHA256 != targetDigest || c.RendererAnswersSHA256 != operation.AnswersSHA256 || c.ObservedProjectSHA256 != operation.PreimageSHA256 || len(operation.Actions) != 0 {
		return nil, ErrUnavailable
	}
	result, err := target.Rendered(ctx, r)
	if err != nil {
		return nil, err
	}
	input, ok := result.Files[path]
	if !ok {
		return nil, ErrUnavailable
	}
	raw, err := canonicaljson.Canonical(c)
	if err != nil {
		return nil, err
	}
	plan, err := rootGoFormatterPlan(ctx, r, toolProvider, path, input)
	if err != nil {
		return nil, err
	}
	adapter, err := blockformatter.NewRuntimeAdapter(r)
	if err != nil {
		return nil, err
	}
	selection, err := adapter.SelectContextNativeUpdate(ctx, calculation, toolProvider, plan, input, raw)
	if err != nil {
		return nil, err
	}
	subjects, err := calculation.OperationSubjects(ctx, r)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(subjects, operation.Subjects) {
		return nil, ErrUnavailable
	}
	tool := toolProvider.Subject()
	provider := trustverify.Provider{Origin: tool.Origin, TemplatePath: tool.TemplatePath, Commit: tool.Commit, TreeSHA256: tool.TreeSHA256, ContractSHA256: tool.ContractSHA256}
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	found := false
	for _, subject := range operation.Subjects {
		if key(subject) == key(provider) && subject != provider {
			return nil, ErrUnavailable
		}
		if subject == provider {
			found = true
		}
	}
	if !found {
		operation.Subjects = append(operation.Subjects, provider)
	}
	sort.Slice(operation.Subjects, func(i, j int) bool { return key(operation.Subjects[i]) < key(operation.Subjects[j]) })
	operation.Actions = selection.Actions()
	bound, err := adapter.BindContextNativeUpdate(ctx, selection, operation)
	if err != nil {
		return nil, err
	}
	planRaw, err := canonicaljson.Canonical(plan)
	if err != nil {
		return nil, err
	}
	frame := engine.FormatFrame{APIVersion: "tplaiter.dev/formatter-frame/v3", Operation: operation, Requests: bound.Requests(), Plan: planRaw, Context: append(engine.Bytes{}, raw...), Input: append(engine.Bytes{}, input...)}
	digest, err := frame.Digest()
	if err != nil {
		return nil, err
	}
	rootProvider, err := calculation.RootResolution(ctx, r)
	if err != nil {
		return nil, err
	}
	return &Prepared{runtime: r, adapter: adapter, provider: rootProvider, toolProvider: toolProvider, bound: bound, frame: frame, digest: digest, nativeUpdate: intent, updateCalculation: calculation}, nil
}

func prepareContextNativeUpdateMergedFile(ctx context.Context, r *trustload.Runtime, intent *contextsource.PreparedNativeUpdate, clean *operationtrust.ContextUpdateFormatterCalculation, calculation *operationtrust.ContextUpdateMergedFormatterCalculation, toolProvider *trustverify.VerifiedResolution, path string, input []byte) (*Prepared, error) {
	if intent == nil || clean == nil || calculation == nil {
		return nil, ErrUnavailable
	}
	if err := intent.RecheckFor(ctx, r); err != nil {
		return nil, err
	}
	c, err := calculation.Context(ctx, r)
	if err != nil {
		return nil, err
	}
	raw, err := canonicaljson.Canonical(c)
	if err != nil {
		return nil, err
	}
	plan, err := rootGoFormatterPlan(ctx, r, toolProvider, path, input)
	if err != nil {
		return nil, err
	}
	adapter, err := blockformatter.NewRuntimeAdapter(r)
	if err != nil {
		return nil, err
	}
	selection, err := adapter.SelectContextNativeUpdateMerged(ctx, clean, calculation, toolProvider, plan, input, raw)
	if err != nil {
		return nil, err
	}
	operation, err := intent.OperationBase(ctx, r)
	if err != nil {
		return nil, err
	}
	tool := toolProvider.Subject()
	provider := trustverify.Provider{Origin: tool.Origin, TemplatePath: tool.TemplatePath, Commit: tool.Commit, TreeSHA256: tool.TreeSHA256, ContractSHA256: tool.ContractSHA256}
	key := func(p trustverify.Provider) string { return p.Origin + "\x00" + p.TemplatePath + "\x00" + p.Commit }
	found := false
	for _, subject := range operation.Subjects {
		if key(subject) == key(provider) && subject != provider {
			return nil, ErrUnavailable
		}
		if subject == provider {
			found = true
		}
	}
	if !found {
		operation.Subjects = append(operation.Subjects, provider)
	}
	sort.Slice(operation.Subjects, func(i, j int) bool { return key(operation.Subjects[i]) < key(operation.Subjects[j]) })
	operation.Actions = selection.Actions()
	bound, err := adapter.BindContextNativeUpdate(ctx, selection, operation)
	if err != nil {
		return nil, err
	}
	planRaw, err := canonicaljson.Canonical(plan)
	if err != nil {
		return nil, err
	}
	frame := engine.FormatFrame{APIVersion: "tplaiter.dev/formatter-frame/v3", Operation: operation, Requests: bound.Requests(), Plan: planRaw, Context: append(engine.Bytes{}, raw...), Input: append(engine.Bytes{}, input...)}
	digest, err := frame.Digest()
	if err != nil {
		return nil, err
	}
	rootProvider, err := calculation.RootResolution(ctx, r)
	if err != nil {
		return nil, err
	}
	return &Prepared{runtime: r, adapter: adapter, provider: rootProvider, toolProvider: toolProvider, bound: bound, frame: frame, digest: digest, nativeUpdate: intent, updateCalculation: clean, updateMerged: calculation}, nil
}
