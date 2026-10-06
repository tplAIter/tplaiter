// Package formatproof connects real formatter execution with authenticated
// retained effects. Transport references never construct a publication permit.
package formatproof

import (
	"context"
	"errors"
	"os"

	"github.com/tplAIter/tplaiter/internal/blockformatter"
	"github.com/tplAIter/tplaiter/internal/blockmarkers"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/projecttransaction/internal/engine"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

var (
	ErrUnavailable = errors.New("managed formatter: authenticated projection unavailable")
	ErrInDoubt     = engine.ErrFormatterInDoubt
)

type Prepared struct {
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
	return Reference{APIVersion: "tplaiter.dev/formatter-reference/v1", FrameSHA256: p.digest}
}

func (p *Prepared) valid(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p == nil || p.runtime == nil || p.runtime.TrustRuntime() == nil {
		return ErrUnavailable
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
	return nil
}

// PrepareRootGoFile derives the exact native tool identity from its verified
// source record. The fixed material binder independently verifies that record,
// executable bytes, native envelope and the complete four-entry closure.
func PrepareRootGoFile(ctx context.Context, r *trustload.Runtime, provider, toolProvider *trustverify.VerifiedResolution, path string, input []byte, managed operationtrust.ManagedFormatterContext, operation trustverify.OperationInputs) (*Prepared, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil || toolProvider == nil {
		return nil, ErrUnavailable
	}
	snapshot, err := r.TrustRuntime().VerifiedSnapshot(toolProvider)
	if err != nil {
		return nil, err
	}
	raw, exists := snapshot.Blob("formatter/tool.json")
	if !exists || len(raw) > 1<<20 {
		return nil, ErrUnavailable
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
		return nil, ErrUnavailable
	}
	options := []string{}
	optionsDigest, err := trustverify.ComputeToolOptionsSHA256(options)
	if err != nil {
		return nil, err
	}
	markers, err := blockmarkers.Validate(blockmarkers.LanguageGo, path, input)
	if err != nil || len(markers) == 0 {
		return nil, ErrUnavailable
	}
	plan, err := blockformatter.BuildPlan(blockformatter.PlanInput{Path: path, Language: "go", Adapter: "gofmt-stdin-v1", Tool: trustverify.Tool{ID: record.ToolID, Version: record.ToolVersion, BinarySHA256: record.BinarySHA256, OptionsSHA256: optionsDigest}, Options: options, InputMode: "100644", Markers: markers, TimeoutMillis: 5000, OutputLimitBytes: 16 << 20, Input: input})
	if err != nil {
		return nil, err
	}
	contextJSON, err := canonicaljson.Canonical(managed)
	if err != nil {
		return nil, err
	}
	return Prepare(ctx, r, provider, toolProvider, plan, input, contextJSON, operation)
}
