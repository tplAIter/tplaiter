package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/blockformatter"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

const formatterEvidenceKind = "native-formatter-evidence/v1"

var ErrFormatterInDoubt = errors.New("formatter evidence: started effect has no authenticated completion")

// FormatFrame is transport. Only the formatter owner constructs it from its
// freshly bound opaque prepared material; its digest is never execution authority.
type FormatFrame struct {
	APIVersion string                         `json:"apiVersion"`
	Operation  trustverify.OperationInputs    `json:"operation"`
	Requests   []trustverify.ExecutionRequest `json:"requests"`
	Plan       json.RawMessage                `json:"plan"`
	Context    Bytes                          `json:"context"`
	Input      Bytes                          `json:"input"`
}
type formatterCompleted struct {
	Ordinal       int                                     `json:"ordinal"`
	RequestSHA256 string                                  `json:"requestSHA256"`
	Approval      trustverify.PersistentApprovalReference `json:"approval"`
	ObservedAt    string                                  `json:"observedAt"`
	CompletedAt   string                                  `json:"completedAt"`
	Output        Bytes                                   `json:"output"`
	OutputSHA256  string                                  `json:"outputSHA256"`
}
type FormatterStore struct {
	tx     *Transaction
	frame  FormatFrame
	digest string
	lease  *os.File
}
type FormatterStart struct {
	owner    *FormatterStore
	ordinal  int
	consumed bool
}

// FormatterPass is created only by verified storage or a real completion.
type FormatterPass struct {
	frame     FormatFrame
	completed formatterCompleted
	digest    string
}

func (f FormatFrame) Digest() (string, error) {
	if (f.APIVersion != "tplaiter.dev/formatter-frame/v1" && f.APIVersion != "tplaiter.dev/formatter-frame/v2") || len(f.Requests) != 2 || len(f.Input) > 16<<20 || len(f.Context) > 1<<20 {
		return "", ErrAuthentication
	}
	plan, err := blockformatter.ParsePlan(f.Plan)
	if err != nil || plan.InputSHA256 != evidencecas.Digest(f.Input) {
		return "", ErrAuthentication
	}
	if f.APIVersion == "tplaiter.dev/formatter-frame/v1" {
		if _, err := operationtrust.ParseManagedFormatterContext(f.Context); err != nil {
			return "", ErrAuthentication
		}
	} else {
		if f.Operation.Scope != "new" {
			return "", ErrAuthentication
		}
		if _, err := operationtrust.ParseContextNewFormatterContext(f.Context); err != nil {
			return "", ErrAuthentication
		}
	}
	op, err := trustverify.ComputeOperationInputsSHA256(f.Operation)
	if err != nil {
		return "", err
	}
	for _, q := range f.Requests {
		if q.VerifyRequestSHA256() != nil || q.OperationInputsSHA256 != op || q.ProjectID != f.Operation.ProjectID || q.ProfileBindingSHA256 != f.Operation.ProfileBindingSHA256 || q.Scope != f.Operation.Scope {
			return "", ErrAuthentication
		}
	}
	if f.Requests[0].RequestSHA256 == f.Requests[1].RequestSHA256 || f.Requests[0].Action.ID == f.Requests[1].Action.ID {
		return "", ErrAuthentication
	}
	return bootstrap.DomainDigest(f.APIVersion, f)
}

func formatterStorage(ctx context.Context, r *trustload.Runtime, f FormatFrame, create bool) (*FormatterStore, error) {
	if ctx == nil || r == nil || r.TrustRuntime() == nil {
		return nil, ErrAuthentication
	}
	raw, err := canonicaljson.Canonical(f)
	if err != nil {
		return nil, err
	}
	var copied FormatFrame
	if err = canonicaljson.DecodeStrict(raw, &copied); err != nil {
		return nil, err
	}
	f = copied
	digest, err := f.Digest()
	if err != nil {
		return nil, err
	}
	pc := r.ProjectContext()
	binding, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, r.TrustRuntime().Binding())
	if err != nil || pc.ProjectID != f.Operation.ProjectID || binding != f.Operation.ProfileBindingSHA256 || r.TrustRuntime().CheckProjectIdentity(ctx, pc.RootPath, pc.ProjectID) != nil {
		return nil, ErrAuthentication
	}
	var key []byte
	if create {
		key, err = runtimeKey(ctx, r, pc.ProjectID, true)
	} else {
		key, err = privateRead(filepath.Join(r.ScratchRoot(), "project-transaction-authority", "seal.key"), 32)
	}
	dir := filepath.Join(r.ScratchRoot(), "formatter-evidence", strings.TrimPrefix(digest, "sha256:"))
	if err != nil || len(key) != 32 {
		clear(key)
		// A genuinely fresh, absent frame is pending, not an authenticated
		// effect. Existing evidence with absent authority still refuses. The
		// confined observation creates neither authority nor evidence.
		if !create && os.IsNotExist(err) {
			if _, frameErr := confinedLstat(dir); os.IsNotExist(frameErr) {
				return nil, os.ErrNotExist
			}
		}
		return nil, ErrAuthentication
	}
	s := &FormatterStore{frame: f, digest: digest, tx: &Transaction{runtime: r, key: key, dir: dir, plan: immutable{Kind: formatterEvidenceKind}}}
	if create {
		s.lease, err = acquireLease(r, "formatter-evidence/"+digest)
		if err == nil {
			err = privateDirectory(dir)
		}
		if err == nil {
			err = s.tx.writeSigned("frame.json", f, true)
			if os.IsExist(err) {
				var prior FormatFrame
				err = s.tx.readSigned("frame.json", &prior)
				if err == nil && !reflect.DeepEqual(prior, f) {
					err = ErrAuthentication
				}
			}
		}
	} else {
		var prior FormatFrame
		err = s.tx.readSigned("frame.json", &prior)
		if err == nil && !reflect.DeepEqual(prior, f) {
			err = ErrAuthentication
		}
	}
	if err != nil {
		s.Release()
		return nil, err
	}
	return s, nil
}

func BeginFormatterEvidence(ctx context.Context, r *trustload.Runtime, f FormatFrame) (*FormatterStore, error) {
	return formatterStorage(ctx, r, f, true)
}

func (s *FormatterStore) Release() {
	if s == nil {
		return
	}
	if s.lease != nil {
		_ = s.lease.Close()
		s.lease = nil
	}
	if s.tx != nil {
		clear(s.tx.key)
		s.tx.key = nil
	}
}

type formatterStarted struct {
	FrameSHA256   string `json:"frameSHA256"`
	Ordinal       int    `json:"ordinal"`
	RequestSHA256 string `json:"requestSHA256"`
}

func (s *FormatterStore) checkStarted(ordinal int) error {
	var started formatterStarted
	if err := s.tx.readSigned(fmt.Sprintf("pass-%d-started.json", ordinal), &started); err != nil {
		return err
	}
	if started.FrameSHA256 != s.digest || started.Ordinal != ordinal || started.RequestSHA256 != s.frame.Requests[ordinal-1].RequestSHA256 {
		return ErrAuthentication
	}
	return nil
}

func (s *FormatterStore) Start(ordinal int) (*FormatterStart, error) {
	if s == nil || s.tx == nil || s.lease == nil || ordinal < 1 || ordinal > 2 {
		return nil, ErrAuthentication
	}
	req := s.frame.Requests[ordinal-1]
	err := s.tx.writeSigned(fmt.Sprintf("pass-%d-started.json", ordinal), formatterStarted{s.digest, ordinal, req.RequestSHA256}, true)
	if os.IsExist(err) {
		return nil, ErrFormatterInDoubt
	}
	if err != nil {
		return nil, err
	}
	return &FormatterStart{owner: s, ordinal: ordinal}, nil
}

func (s *FormatterStore) Complete(start *FormatterStart, pass *blockformatter.CompletedPass) (*FormatterPass, error) {
	if s == nil || start == nil || start.owner != s || start.consumed || s.lease == nil {
		return nil, ErrAuthentication
	}
	start.consumed = true
	data, err := pass.DataFor(s.tx.runtime)
	if err != nil {
		return nil, err
	}
	plan, err := blockformatter.ParsePlan(s.frame.Plan)
	if err != nil {
		return nil, err
	}
	if data.Ordinal != start.ordinal || !reflect.DeepEqual(data.Operation, s.frame.Operation) || !reflect.DeepEqual(data.Request, s.frame.Requests[start.ordinal-1]) || !bytes.Equal(data.Context, s.frame.Context) || !bytes.Equal(data.Input, s.frame.Input) || data.Plan.PlanSHA256 != plan.PlanSHA256 || data.CompletedAt.Before(data.ObservedAt) {
		return nil, ErrAuthentication
	}
	record := formatterCompleted{Ordinal: data.Ordinal, RequestSHA256: data.Request.RequestSHA256, Approval: data.Approval, ObservedAt: data.ObservedAt.UTC().Format(time.RFC3339Nano), CompletedAt: data.CompletedAt.UTC().Format(time.RFC3339Nano), Output: append(Bytes{}, data.Output...), OutputSHA256: evidencecas.Digest(data.Output)}
	if err := s.tx.writeSigned(fmt.Sprintf("pass-%d-completed.json", start.ordinal), record, true); err != nil {
		return nil, err
	}
	return &FormatterPass{frame: s.frame, completed: record, digest: s.digest}, nil
}

func (s *FormatterStore) ReadPass(ordinal int) (*FormatterPass, error) {
	if s == nil || s.tx == nil || ordinal < 1 || ordinal > 2 {
		return nil, ErrAuthentication
	}
	var completed formatterCompleted
	err := s.tx.readSigned(fmt.Sprintf("pass-%d-completed.json", ordinal), &completed)
	if os.IsNotExist(err) {
		if e := s.checkStarted(ordinal); e == nil {
			return nil, ErrFormatterInDoubt
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkStarted(ordinal); err != nil {
		return nil, err
	}
	if completed.Ordinal != ordinal || completed.RequestSHA256 != s.frame.Requests[ordinal-1].RequestSHA256 || len(completed.Output) > 16<<20 || completed.OutputSHA256 != evidencecas.Digest(completed.Output) {
		return nil, ErrAuthentication
	}
	return &FormatterPass{frame: s.frame, completed: completed, digest: s.digest}, nil
}

func ReadFormatterEvidence(ctx context.Context, r *trustload.Runtime, f FormatFrame, ordinal int) (*FormatterPass, error) {
	s, err := formatterStorage(ctx, r, f, false)
	if err != nil {
		return nil, err
	}
	defer s.Release()
	return s.ReadPass(ordinal)
}

func (p *FormatterPass) Data() (blockformatter.PassData, error) {
	if p == nil {
		return blockformatter.PassData{}, ErrAuthentication
	}
	plan, err := blockformatter.ParsePlan(p.frame.Plan)
	if err != nil {
		return blockformatter.PassData{}, err
	}
	start, e1 := time.Parse(time.RFC3339Nano, p.completed.ObservedAt)
	end, e2 := time.Parse(time.RFC3339Nano, p.completed.CompletedAt)
	if e1 != nil || e2 != nil || end.Before(start) || p.completed.Ordinal < 1 || p.completed.Ordinal > 2 {
		return blockformatter.PassData{}, ErrAuthentication
	}
	// Round-trip through canonical JSON returns defensive copies of all arrays.
	raw, err := canonicaljson.Canonical(p.frame)
	if err != nil {
		return blockformatter.PassData{}, err
	}
	var frame FormatFrame
	if err = canonicaljson.DecodeStrict(raw, &frame); err != nil {
		return blockformatter.PassData{}, err
	}
	return blockformatter.PassData{Ordinal: p.completed.Ordinal, Operation: frame.Operation, Request: frame.Requests[p.completed.Ordinal-1], Approval: p.completed.Approval, ObservedAt: start, CompletedAt: end, Plan: plan, Input: append([]byte{}, frame.Input...), Output: append([]byte{}, p.completed.Output...), Context: append([]byte{}, frame.Context...)}, nil
}
