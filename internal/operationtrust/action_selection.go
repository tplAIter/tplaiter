package operationtrust

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"gopkg.in/yaml.v3"
)

const (
	TemplateActionsPath   = "actions/run/actions.json"
	ActionToolPath        = "actions/tool.json"
	ActionClass           = "staged-native-readonly/v1"
	actionCapsulePath     = "actions/run/capsule.json"
	actionMetadataLimit   = 64 << 10
	actionProjectionLimit = 16 << 20
)

var ErrActionSelection = errors.New("TRUST_ACTION_SELECTION_UNAVAILABLE")

// ActionInput is untrusted selection data, never a path, reader, approval or
// tool capability. Every parameter must match a finite signed typed enum.
type ActionInput struct {
	Name           string
	ParametersJSON []byte
}

// ActionProjection is detached data, never execution authority. ActionFor on
// an owner-bound ExecutionMaterial is the only runner acquisition path.
type (
	ActionInputFile struct {
		Root, Path, Mode, SHA256 string
		Bytes                    []byte
	}
	ActionProjection struct {
		Profile string
		Stdin   []byte
		Files   []ActionInputFile
	}
)

// ResolveActionTool derives the separately authenticated tool locator only
// from this runtime's verified source metadata. The caller cannot supply it.
func ResolveActionTool(ctx context.Context, owner *trustload.Runtime, source *trustverify.VerifiedResolution, name string) (*trustverify.VerifiedResolution, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || owner.TrustRuntime() == nil || !source.ValidFor(owner.TrustRuntime(), owner.TrustRuntime().Binding()) {
		return nil, ErrActionSelection
	}
	stable := owner.TrustRuntime()
	fresh, e := stable.VerifySubject(ctx, source.Subject(), source.Evidence())
	if e != nil {
		return nil, e
	}
	snapshot, e := stable.VerifiedSnapshot(fresh)
	if e != nil {
		return nil, e
	}
	raw, ok := actionSnapshotBlob(snapshot, TemplateActionsPath, "100644")
	if !ok {
		return nil, ErrActionSelection
	}
	document, e := decodeActionDocument(raw)
	if e != nil {
		return nil, e
	}
	for _, a := range document.Actions {
		if a.ID == name {
			p := a.Tool.Provider
			r := a.Tool.Evidence
			if document.APIVersion == "tplaiter.dev/template-actions/v2" {
				return owner.ResolveEnrolledSource(ctx, actionToolSubject(p), actionPublisher(r))
			}
			return stable.VerifySubject(ctx, trustverify.Subject{Origin: p.Origin, TemplatePath: p.TemplatePath, RequestedRef: p.Commit, Commit: p.Commit, TreeSHA256: p.TreeSHA256, ContractSHA256: p.ContractSHA256}, trustverify.EvidenceRefs{Format: r.Format, StatementCAS: r.StatementCAS, SignatureCAS: r.SignatureCAS, KeyFingerprint: r.KeyFingerprint, CheckpointCAS: r.CheckpointCAS, InclusionProofCAS: r.InclusionProofCAS})
		}
	}
	return nil, ErrActionSelection
}

type actionDocument struct {
	APIVersion string              `json:"apiVersion"`
	Actions    []actionDeclaration `json:"actions"`
}
type actionDeclaration struct {
	ID               string                            `json:"id"`
	Purpose          string                            `json:"purpose"`
	Class            string                            `json:"class"`
	Profile          string                            `json:"profile"`
	Version          int                               `json:"version"`
	Kind             string                            `json:"kind"`
	Phase            string                            `json:"phase"`
	Shell            bool                              `json:"shell"`
	Parameters       []actionParameter                 `json:"parameters"`
	Argv             []actionArg                       `json:"argv"`
	Inputs           []actionFile                      `json:"inputs"`
	Stdin            actionFile                        `json:"stdin"`
	Tool             actionToolSelection               `json:"tool"`
	Environment      trustverify.EnvironmentPolicy     `json:"environment"`
	WorkingDirectory trustverify.WorkingDirectoryScope `json:"workingDirectory"`
	TimeoutMillis    int64                             `json:"timeoutMillis"`
	StdoutLimit      int                               `json:"stdoutLimit"`
	StderrLimit      int                               `json:"stderrLimit"`
}
type actionParameter struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Values []json.RawMessage `json:"values"`
}
type actionArg struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type actionFile struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}
type actionToolSelection struct {
	Provider     trustverify.Provider `json:"provider"`
	Evidence     SelectionEvidence    `json:"evidence"`
	ID           string               `json:"id"`
	Version      string               `json:"version"`
	RecordSHA256 string               `json:"recordSHA256"`
}
type actionToolRecord struct {
	APIVersion   string       `json:"apiVersion"`
	ID           string       `json:"id"`
	Version      string       `json:"version"`
	Class        string       `json:"class"`
	Profile      string       `json:"profile"`
	BinaryPath   string       `json:"binaryPath"`
	BinarySHA256 string       `json:"binarySHA256"`
	Assets       []actionFile `json:"assets"`
}
type actionCapsule struct {
	APIVersion       string                     `json:"apiVersion"`
	Declaration      actionDeclaration          `json:"declaration"`
	MetadataSHA256   string                     `json:"metadataSHA256"`
	ToolRecordSHA256 string                     `json:"toolRecordSHA256"`
	Parameters       map[string]json.RawMessage `json:"parameters"`
	Argv             []string                   `json:"argv"`
	Inputs           []trustverify.ContentEntry `json:"inputs"`
	AnswersSHA256    string                     `json:"answersSHA256"`
	PreimageSHA256   string                     `json:"preimageSHA256"`
	ProfileSHA256    string                     `json:"profileSHA256"`
}

// ActionSelection owns one operation-local observation. It cannot authorize or
// launch, has no decoder and never accepts reconstructed caller authority.
// The connected command owner must additionally retain runtimeassembly writer
// coordination outside this package (importing it here forms a cycle). It keeps
// this selection open through approval, execution and final emission.
type ActionSelection struct {
	owner                           *trustload.Runtime
	stable                          *trustverify.Runtime
	source, toolSource              *trustverify.VerifiedResolution
	input                           ActionInput
	operation                       trustverify.OperationInputs
	request                         trustverify.ExecutionRequest
	capsule, metadata, record, tool []byte
	projection                      ActionProjection
	content                         []trustverify.ContentEntry
	contentBytes                    [][]byte
	files                           *actionFiles
	ledger                          *stateledger.Snapshot
	closed                          bool
}

func PrepareAction(ctx context.Context, owner *trustload.Runtime, source, toolSource *trustverify.VerifiedResolution, input ActionInput) (*ActionSelection, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || owner.TrustRuntime() == nil || source == nil || toolSource == nil || !actionToken(input.Name) {
		return nil, ErrActionSelection
	}
	stable := owner.TrustRuntime()
	if !source.ValidFor(stable, stable.Binding()) || !toolSource.ValidFor(stable, stable.Binding()) || provider(source.Subject()) == provider(toolSource.Subject()) {
		return nil, ErrActionSelection
	}
	// VerifiedSnapshot alone does not refresh evidence, policy or CAS.
	freshSource, err := stable.VerifySubject(ctx, source.Subject(), source.Evidence())
	if err != nil {
		return nil, err
	}
	freshTool, err := stable.VerifySubject(ctx, toolSource.Subject(), toolSource.Evidence())
	if err != nil {
		return nil, err
	}
	ps, err := stable.VerifiedSnapshot(freshSource)
	if err != nil {
		return nil, err
	}
	ts, err := stable.VerifiedSnapshot(freshTool)
	if err != nil {
		return nil, err
	}
	manifestRaw, ok := actionSnapshotBlob(ps, "template.manifest.yaml", "100644")
	if !ok {
		return nil, ErrActionSelection
	}
	if _, err := requireNativeContract(ps.ContractBytes(), manifestRaw); err != nil {
		return nil, err
	}
	tpl, err := manifest.ParseTemplate(manifestRaw)
	if err != nil {
		return nil, err
	}
	metadata, ok := actionSnapshotBlob(ps, TemplateActionsPath, "100644")
	if !ok {
		return nil, ErrActionSelection
	}
	doc, err := decodeActionDocument(metadata)
	if err != nil {
		return nil, err
	}
	var declaration *actionDeclaration
	for i := range doc.Actions {
		if doc.Actions[i].ID == input.Name {
			declaration = &doc.Actions[i]
		}
	}
	if declaration != nil && doc.APIVersion == "tplaiter.dev/template-actions/v2" {
		current, e := owner.ResolveEnrolledSource(ctx, actionToolSubject(declaration.Tool.Provider), actionPublisher(declaration.Tool.Evidence))
		if e != nil {
			return nil, e
		}
		if current.Subject() != freshTool.Subject() || current.Evidence() != freshTool.Evidence() {
			return nil, ErrActionSelection
		}
	}
	if declaration == nil || !actionSupportsHostProfile(declaration.Profile) || declaration.Tool.Provider != provider(freshTool.Subject()) || !actionEvidenceMatches(doc.APIVersion, declaration.Tool.Evidence, freshTool.Evidence()) {
		return nil, ErrActionSelection
	}
	command, ok := tpl.Commands[input.Name]
	// Run is an exact inert declaration marker, never shell text to split.
	if !ok || command.Run != "tplaiter-action:"+input.Name {
		return nil, ErrActionSelection
	}
	params, argv, err := actionArguments(*declaration, input.ParametersJSON)
	if err != nil {
		return nil, err
	}
	recordRaw, ok := actionSnapshotBlob(ts, ActionToolPath, "100644")
	if !ok || evidencecas.Digest(recordRaw) != declaration.Tool.RecordSHA256 {
		return nil, ErrActionSelection
	}
	var record actionToolRecord
	if decodeActionJSON(recordRaw, &record) != nil || record.APIVersion != "tplaiter.dev/action-tool/v1" || record.Class != ActionClass || record.Profile != declaration.Profile || record.ID != declaration.Tool.ID || record.Version != declaration.Tool.Version || !actionPath(record.BinaryPath) || !validBuildDigest(record.BinarySHA256) || record.Assets == nil || len(record.Assets) > 128 {
		return nil, ErrActionSelection
	}
	tool, ok := actionSnapshotBlob(ts, record.BinaryPath, "100755")
	if !ok || len(tool) == 0 || len(tool) > 16<<20 || evidencecas.Digest(tool) != record.BinarySHA256 || !actionNativeImage(tool, record.Profile) {
		return nil, ErrActionSelection
	}
	ledger, err := stateledger.VerifyStable(ctx, owner.ProjectContext().RootPath, stable, stateledger.StableVerifyOptions{CAS: owner})
	if err != nil {
		return nil, err
	}
	s := &ActionSelection{owner: owner, stable: stable, source: freshSource, toolSource: freshTool, input: ActionInput{Name: input.Name, ParametersJSON: append([]byte(nil), input.ParametersJSON...)}, metadata: metadata, record: recordRaw, tool: tool, ledger: ledger}
	successful := false
	defer func() {
		if !successful {
			s.Close()
		}
	}()
	s.files, err = openActionFiles(owner.ProjectContext().RootPath)
	if err != nil {
		return nil, err
	}
	marker, err := s.files.read(ctx, ".tplaiter/project.yaml", 1<<20)
	if err != nil {
		return nil, err
	}
	lockRaw, err := s.files.read(ctx, ".tplaiter/root-template.lock.json", 1<<20)
	if err != nil {
		return nil, err
	}
	var project stateledger.ProjectV2
	decoder := yaml.NewDecoder(bytes.NewReader(marker))
	decoder.KnownFields(true)
	if decoder.Decode(&project) != nil || decoder.Decode(new(any)) != io.EOF || project.APIVersion != stateledger.ProjectV2APIVersion || project.ID != owner.ProjectContext().ProjectID || project.Template.ResolvedCommit != freshSource.Subject().Commit || project.Template.RequestedRef != freshSource.Subject().RequestedRef {
		return nil, ErrActionSelection
	}
	lock, err := provenance.DecodeRootTemplateLock(lockRaw)
	if err != nil || (trustverify.Subject{Origin: lock.Root.Origin, TemplatePath: lock.Root.TemplatePath, RequestedRef: lock.Root.RequestedRef, Commit: lock.Root.Commit, TreeSHA256: lock.Root.TreeSHA256, ContractSHA256: lock.Root.ContractSHA256}) != freshSource.Subject() {
		return nil, ErrActionSelection
	}
	values := settings.Values{}
	for k, answer := range project.Answers {
		values[k] = answer.Value
	}
	resolved, err := settings.ResolveRecorded(tpl, values, values)
	if err != nil {
		return nil, err
	}
	if command.When != "" {
		condition, e := manifest.ParseCondition(command.When)
		if e != nil {
			return nil, e
		}
		on, e := settings.Eval(condition, resolved.Values)
		if e != nil || !on {
			return nil, ErrActionSelection
		}
	}
	answers, err := canonicaljson.Canonical(resolved.Values)
	if err != nil {
		return nil, err
	}
	// Original answers are preserved; parameters and purpose belong to capsule.
	entries := []trustverify.ContentEntry{}
	data := [][]byte{}
	add := func(root, p, mode string, b []byte) {
		entries = append(entries, trustverify.ContentEntry{Root: root, Path: p, Mode: mode, ContentSHA256: evidencecas.Digest(b)})
		data = append(data, append([]byte(nil), b...))
	}
	add("project", ".tplaiter/project.yaml", "100644", marker)
	add("project", ".tplaiter/root-template.lock.json", "100644", lockRaw)
	var total int
	lastAsset := ""
	for _, asset := range record.Assets {
		if asset.Root != "tool" || asset.Path <= lastAsset || !validActionFile(asset) {
			return nil, ErrActionSelection
		}
		lastAsset = asset.Path
	}
	allInputs := append(append(append([]actionFile(nil), declaration.Inputs...), declaration.Stdin), record.Assets...)
	if len(allInputs) > 128 {
		return nil, ErrActionSelection
	}
	s.projection.Profile = declaration.Profile
	seen := map[string]bool{}
	for _, inputFile := range allInputs {
		key := inputFile.Root + "\x00" + inputFile.Path
		if !validActionFile(inputFile) || seen[key] || inputFile.Path == record.BinaryPath && inputFile.Root == "tool" {
			return nil, ErrActionSelection
		}
		seen[key] = true
		var b []byte
		switch inputFile.Root {
		case "project":
			b, err = s.files.read(ctx, inputFile.Path, actionProjectionLimit)
		case "provider":
			b, ok = actionSnapshotBlob(ps, inputFile.Path, inputFile.Mode)
			if !ok {
				err = ErrActionSelection
			}
		case "tool":
			b, ok = actionSnapshotBlob(ts, inputFile.Path, inputFile.Mode)
			if !ok {
				err = ErrActionSelection
			}
		}
		if err != nil || evidencecas.Digest(b) != inputFile.SHA256 {
			return nil, ErrActionSelection
		}
		if inputFile == declaration.Stdin && len(b) > 1<<20 {
			return nil, ErrActionSelection
		}
		total += len(b)
		if total > actionProjectionLimit {
			return nil, ErrActionSelection
		}
		s.projection.Files = append(s.projection.Files, ActionInputFile{Root: inputFile.Root, Path: inputFile.Path, Mode: inputFile.Mode, SHA256: inputFile.SHA256, Bytes: append([]byte(nil), b...)})
		if inputFile == declaration.Stdin {
			s.projection.Stdin = append([]byte(nil), b...)
		}
		// Tool entries are namespaced under provider for the existing closed wire.
		wireRoot, wirePath := inputFile.Root, inputFile.Path
		if wireRoot == "tool" {
			wireRoot, wirePath = "provider", "actions/tool-inputs/"+wirePath
		}
		add(wireRoot, wirePath, inputFile.Mode, b)
	}
	actionSortContent(entries, data)
	preimage, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		return nil, err
	}
	profileDigest, err := ActionProfileDigest(declaration.Profile)
	if err != nil {
		return nil, err
	}
	capsule := actionCapsule{ProfileSHA256: profileDigest, APIVersion: "tplaiter.dev/action-capsule/v1", Declaration: *declaration, MetadataSHA256: evidencecas.Digest(metadata), ToolRecordSHA256: evidencecas.Digest(recordRaw), Parameters: params, Argv: argv, Inputs: append([]trustverify.ContentEntry(nil), entries...), AnswersSHA256: evidencecas.Digest(answers), PreimageSHA256: preimage}
	s.capsule, err = canonicaljson.Canonical(capsule)
	if doc.APIVersion == "tplaiter.dev/template-actions/v2" {
		s.capsule, err = actionCurrentCapsule(capsule, metadata, freshTool, stable.Binding())
	}
	if err != nil || len(s.capsule) > actionMetadataLimit {
		return nil, ErrActionSelection
	}
	add("provider", TemplateActionsPath, "100644", metadata)
	add("provider", "actions/run/tool-record.json", "100644", recordRaw)
	add("provider", actionCapsulePath, "100644", s.capsule)
	actionSortContent(entries, data)
	closure, err := trustverify.ComputeContentClosureSHA256(entries)
	if err != nil {
		return nil, err
	}
	bd, err := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, stable.Binding())
	if err != nil {
		return nil, err
	}
	options, err := trustverify.ComputeToolOptionsSHA256(argv[1:])
	if err != nil {
		return nil, err
	}
	envHash, err := trustverify.ComputeEnvironmentPolicySHA256(declaration.Environment)
	if err != nil {
		return nil, err
	}
	p := provider(freshSource.Subject())
	a := trustverify.ActionMaterial{Provider: p, Action: trustverify.Action{ID: input.Name, Kind: "command", Phase: "standalone", Argv: argv, ContentClosureSHA256: closure}, Tool: trustverify.Tool{ID: record.ID, Version: record.Version, BinarySHA256: record.BinarySHA256, OptionsSHA256: options}, WorkingDirectoryScope: declaration.WorkingDirectory, EnvironmentPolicySHA256: envHash, TimeoutMillis: declaration.TimeoutMillis, Migration: trustverify.Migration{Kind: "none"}}
	subjects := []trustverify.Provider{p, provider(freshTool.Subject())}
	sort.Slice(subjects, func(i, j int) bool { return providerKey(subjects[i]) < providerKey(subjects[j]) })
	s.operation = trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: bd, ProjectID: owner.ProjectContext().ProjectID, Scope: "run", PreimageSHA256: preimage, AnswersSHA256: evidencecas.Digest(answers), Subjects: subjects, Actions: []trustverify.ActionMaterial{a}}
	od, err := trustverify.ComputeOperationInputsSHA256(s.operation)
	if err != nil {
		return nil, err
	}
	s.request = trustverify.ExecutionRequest{APIVersion: trustverify.ExecutionRequestAPIVersion, ProfileBindingSHA256: bd, OperationInputsSHA256: od, ProjectID: s.operation.ProjectID, Scope: "run", Provider: p, Action: a.Action, Tool: a.Tool, WorkingDirectoryScope: a.WorkingDirectoryScope, EnvironmentPolicySHA256: a.EnvironmentPolicySHA256, TimeoutMillis: a.TimeoutMillis, Migration: a.Migration}
	s.request.RequestSHA256, err = s.request.ComputeRequestSHA256()
	if err != nil {
		return nil, err
	}
	s.content, s.contentBytes = entries, data
	if err := s.checkObserved(ctx); err != nil {
		return nil, err
	}
	successful = true
	return s, nil
}

func (s *ActionSelection) Operation() trustverify.OperationInputs {
	if s == nil || s.closed {
		return trustverify.OperationInputs{}
	}
	return cloneOperation(s.operation)
}

func (s *ActionSelection) Request() trustverify.ExecutionRequest {
	if s == nil || s.closed {
		return trustverify.ExecutionRequest{}
	}
	return cloneRequest(s.request)
}

func (s *ActionSelection) Capsule() []byte {
	if s == nil || s.closed {
		return nil
	}
	return append([]byte(nil), s.capsule...)
}

func (s *ActionSelection) Close() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	if s.files != nil {
		s.files.close()
	}
}

// Recheck authenticates both subjects again and compares newly reconstructed
// semantics, while preserving the original physical observations and ledger observation.
// It is not a permit check; the connected runner must also RecheckAction.
func (s *ActionSelection) Recheck(ctx context.Context, owner *trustload.Runtime) error {
	if s == nil || s.closed || s.owner != owner || ctx == nil || ctx.Err() != nil {
		return ErrActionSelection
	}
	if err := s.checkObserved(ctx); err != nil {
		return err
	}
	fresh, err := PrepareAction(ctx, owner, s.source, s.toolSource, s.input)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if !reflect.DeepEqual(s.operation, fresh.operation) || !reflect.DeepEqual(s.request, fresh.request) || !bytes.Equal(s.capsule, fresh.capsule) || !bytes.Equal(s.tool, fresh.tool) || !reflect.DeepEqual(s.contentBytes, fresh.contentBytes) {
		return ErrActionSelection
	}
	return s.checkObserved(ctx)
}

func (s *ActionSelection) checkObserved(ctx context.Context) error {
	if s == nil || s.closed || ctx == nil || ctx.Err() != nil || s.owner.TrustRuntime() != s.stable || s.files == nil || s.ledger == nil {
		return ErrActionSelection
	}
	if err := s.files.check(ctx); err != nil {
		return err
	}
	ledger, err := stateledger.VerifyStable(ctx, s.owner.ProjectContext().RootPath, s.stable, stateledger.StableVerifyOptions{CAS: s.owner})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.ledger, ledger) {
		return ErrActionSelection
	}
	for _, old := range []*trustverify.VerifiedResolution{s.source, s.toolSource} {
		fresh, err := s.stable.VerifySubject(ctx, old.Subject(), old.Evidence())
		if err != nil {
			return err
		}
		if !fresh.ValidFor(s.stable, s.stable.Binding()) || fresh.Subject() != old.Subject() {
			return ErrActionSelection
		}
	}
	return s.files.check(ctx)
}

func decodeActionDocument(raw []byte) (actionDocument, error) {
	var d actionDocument
	normalized, current, e := actionCurrentDocument(raw)
	if e != nil {
		return d, e
	}
	if current {
		raw = normalized
	}
	if decodeActionJSON(raw, &d) != nil || (d.APIVersion != "tplaiter.dev/template-actions/v1" && d.APIVersion != "tplaiter.dev/template-actions/v2") || len(d.Actions) == 0 || len(d.Actions) > 64 {
		return d, ErrActionSelection
	}
	last := ""
	for _, a := range d.Actions {
		if a.ID <= last || !actionToken(a.ID) || a.Purpose != "run" || a.Class != ActionClass || !actionProfile(a.Profile) || a.Version != 1 || a.Kind != "command" || a.Phase != "standalone" || a.Shell || a.TimeoutMillis < 1 || a.TimeoutMillis > 5000 || a.StdoutLimit != 128<<10 || a.StderrLimit != 16<<10 || a.WorkingDirectory != (trustverify.WorkingDirectoryScope{Root: "provider", Path: ".tplaiter-execution"}) || !reflect.DeepEqual(a.Environment, fixedEnvironment()) || a.Parameters == nil || len(a.Parameters) > 16 || a.Argv == nil || len(a.Argv) == 0 || len(a.Argv) > 64 || a.Inputs == nil || len(a.Inputs) > 127 || !validActionFile(a.Stdin) || !actionToken(a.Tool.ID) || !actionText(a.Tool.Version) || !validBuildDigest(a.Tool.RecordSHA256) {
			return d, ErrActionSelection
		}
		last = a.ID
		// Provider wire grammar is checked without manufacturing any resolution.
		if _, e := trustverify.ComputeOperationInputsSHA256(trustverify.OperationInputs{APIVersion: "tplaiter.dev/operation-inputs/v1", ProfileBindingSHA256: a.Tool.RecordSHA256, ProjectID: "grammar", Scope: "run", PreimageSHA256: a.Tool.RecordSHA256, AnswersSHA256: a.Tool.RecordSHA256, Subjects: []trustverify.Provider{a.Tool.Provider}}); e != nil {
			return d, ErrActionSelection
		}
		if a.Tool.Evidence.Format != bootstrap.PublisherStatementAPIVersion || !validBuildDigest(a.Tool.Evidence.StatementCAS) || !validBuildDigest(a.Tool.Evidence.SignatureCAS) || !validBuildDigest(a.Tool.Evidence.KeyFingerprint) || (d.APIVersion == "tplaiter.dev/template-actions/v1" && (!validBuildDigest(a.Tool.Evidence.CheckpointCAS) || !validBuildDigest(a.Tool.Evidence.InclusionProofCAS))) || (d.APIVersion == "tplaiter.dev/template-actions/v2" && (a.Tool.Evidence.CheckpointCAS != "" || a.Tool.Evidence.InclusionProofCAS != "")) {
			return d, ErrActionSelection
		}
		lastPath := ""
		for _, f := range a.Inputs {
			k := f.Root + "\x00" + f.Path
			if !validActionFile(f) || k <= lastPath || f == a.Stdin {
				return d, ErrActionSelection
			}
			lastPath = k
		}
		lastParam := ""
		for _, p := range a.Parameters {
			if !actionToken(p.Name) || p.Name <= lastParam || len(p.Values) == 0 || len(p.Values) > 64 {
				return d, ErrActionSelection
			}
			lastParam = p.Name
			seen := map[string]bool{}
			for _, v := range p.Values {
				_, c, e := actionParameterText(p.Type, v)
				if e != nil || seen[string(c)] {
					return d, ErrActionSelection
				}
				seen[string(c)] = true
			}
		}
		for _, slot := range a.Argv {
			if !actionText(slot.Value) || slot.Kind != "literal" && slot.Kind != "parameter" {
				return d, ErrActionSelection
			}
			if slot.Kind == "parameter" {
				found := false
				for _, p := range a.Parameters {
					found = found || p.Name == slot.Value
				}
				if !found {
					return d, ErrActionSelection
				}
			}
		}
		if a.Argv[0] != (actionArg{Kind: "literal", Value: a.Tool.ID}) {
			return d, ErrActionSelection
		}
	}
	return d, nil
}

func decodeActionJSON(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > actionMetadataLimit {
		return ErrActionSelection
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil || !bytes.Equal(canonical, raw) || canonicaljson.DecodeStrict(raw, dst) != nil {
		return ErrActionSelection
	}
	return actionRequiredFields(raw, reflect.TypeOf(dst).Elem())
}

func actionRequiredFields(raw []byte, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return ErrActionSelection
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name == "-" {
				continue
			}
			value, ok := fields[name]
			if !ok || bytes.Equal(value, []byte("null")) || actionRequiredFields(value, f.Type) != nil {
				return ErrActionSelection
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return ErrActionSelection
		}
		for _, v := range values {
			if actionRequiredFields(v, t.Elem()) != nil {
				return ErrActionSelection
			}
		}
	}
	return nil
}

func actionArguments(a actionDeclaration, raw []byte) (map[string]json.RawMessage, []string, error) {
	if len(raw) == 0 || len(raw) > actionMetadataLimit {
		return nil, nil, ErrActionSelection
	}
	params := map[string]json.RawMessage{}
	if canonicaljson.DecodeStrict(raw, &params) != nil || len(params) != len(a.Parameters) {
		return nil, nil, ErrActionSelection
	}
	text := map[string]string{}
	for _, p := range a.Parameters {
		v, ok := params[p.Name]
		if !ok {
			return nil, nil, ErrActionSelection
		}
		x, c, e := actionParameterText(p.Type, v)
		if e != nil {
			return nil, nil, e
		}
		allowed := false
		for _, value := range p.Values {
			_, b, e := actionParameterText(p.Type, value)
			allowed = allowed || e == nil && bytes.Equal(c, b)
		}
		if !allowed {
			return nil, nil, ErrActionSelection
		}
		params[p.Name] = c
		text[p.Name] = x
	}
	argv := make([]string, len(a.Argv))
	total := 0
	for i, slot := range a.Argv {
		v := slot.Value
		if slot.Kind == "parameter" {
			v = text[v]
		}
		if !actionText(v) {
			return nil, nil, ErrActionSelection
		}
		argv[i] = v
		total += len(v)
	}
	if total > 16<<10 {
		return nil, nil, ErrActionSelection
	}
	return params, argv, nil
}

func actionParameterText(kind string, raw []byte) (string, []byte, error) {
	c, e := canonicaljson.Canonicalize(raw)
	if e != nil {
		return "", nil, ErrActionSelection
	}
	var text string
	switch kind {
	case "string":
		if canonicaljson.DecodeStrict(c, &text) != nil || !actionText(text) {
			return "", nil, ErrActionSelection
		}
	case "boolean":
		var b bool
		if canonicaljson.DecodeStrict(c, &b) != nil {
			return "", nil, ErrActionSelection
		}
		text = strconv.FormatBool(b)
	case "integer":
		var n int64
		if canonicaljson.DecodeStrict(c, &n) != nil || n < -(1<<53-1) || n > 1<<53-1 {
			return "", nil, ErrActionSelection
		}
		text = strconv.FormatInt(n, 10)
	default:
		return "", nil, ErrActionSelection
	}
	return text, c, nil
}

func actionText(s string) bool {
	return s != "" && len(s) <= 4096 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func actionToken(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

func actionPath(s string) bool {
	if !actionText(s) || len(s) > 1024 || path.IsAbs(s) || path.Clean(s) != s || s == "." || strings.Contains(s, "\\") || strings.Count(s, "/") >= 32 {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func validActionFile(f actionFile) bool {
	return (f.Root == "provider" || f.Root == "tool" || f.Root == "project") && actionPath(f.Path) && f.Mode == "100644" && validBuildDigest(f.SHA256) && !strings.HasPrefix(f.Path, "actions/") && f.Path != "actions" && !strings.HasPrefix(f.Path, ".tplaiter/") && f.Path != ".tplaiter"
}

func actionProfile(p string) bool {
	return p == "darwin25G83-native-fd/v1" || p == "linux-static-fd-go127/v1" || p == "linux-static-fd-go127-poll/v1"
}

func actionSupportsHostProfile(p string) bool {
	return p == actionHostProfile() || (p == "linux-static-fd-go127-poll/v1" && runtime.GOOS == "linux" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64"))
}

func actionHostProfile() string {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return "darwin25G83-native-fd/v1"
	}
	if runtime.GOOS == "linux" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "amd64") {
		return "linux-static-fd-go127/v1"
	}
	return ""
}

func actionEvidence(e trustverify.EvidenceRefs) SelectionEvidence {
	return SelectionEvidence{Format: e.Format, StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint, CheckpointCAS: e.CheckpointCAS, InclusionProofCAS: e.InclusionProofCAS}
}

func actionSnapshotBlob(s *trustverify.SourceSnapshot, p, mode string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	for _, e := range s.Entries() {
		if e.Path == p && e.Kind == "file" && e.Mode == mode {
			b, ok := s.Blob(p)
			return b, ok && evidencecas.Digest(b) == e.ContentSHA256
		}
	}
	return nil, false
}

func actionSortContent(e []trustverify.ContentEntry, b [][]byte) {
	for i := 1; i < len(e); i++ {
		for j := i; j > 0 && e[j].Root+"\x00"+e[j].Path < e[j-1].Root+"\x00"+e[j-1].Path; j-- {
			e[j], e[j-1] = e[j-1], e[j]
			b[j], b[j-1] = b[j-1], b[j]
		}
	}
}

// This is structural admission only. The executor must enforce the named OS
// profile before entry; selection supplies no proof of behavior confinement.
func actionNativeImage(b []byte, p string) bool { return actionNativeImageFor(b, p, runtime.GOARCH) }

func actionNativeImageFor(b []byte, p, arch string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if !actionProfile(p) {
		return false
	}
	if p == "linux-static-fd-go127/v1" || p == "linux-static-fd-go127-poll/v1" {
		f, e := elf.NewFile(bytes.NewReader(b))
		if e != nil {
			return false
		}
		defer f.Close()
		if arch != "amd64" && arch != "arm64" {
			return false
		}
		machine := elf.EM_X86_64
		if arch == "arm64" {
			machine = elf.EM_AARCH64
		}
		if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Type != elf.ET_EXEC || f.Machine != machine || f.Entry == 0 || f.Version != elf.EV_CURRENT || f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
			return false
		}
		executable := false
		for _, s := range f.Progs {
			if s.Type == elf.PT_INTERP || s.Type == elf.PT_DYNAMIC {
				return false
			}
			if s.Type == elf.PT_LOAD {
				if s.Filesz > s.Memsz || s.Off+s.Filesz < s.Off || s.Off+s.Filesz > uint64(len(b)) || s.Flags&elf.PF_X != 0 && s.Flags&elf.PF_W != 0 {
					return false
				}
				executable = executable || s.Flags&elf.PF_X != 0
			}
		}
		return executable
	}
	if p != "darwin25G83-native-fd/v1" || arch != "arm64" || len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf || binary.LittleEndian.Uint32(b[4:]) != 0x100000c || binary.LittleEndian.Uint32(b[8:]) != 0 || binary.LittleEndian.Uint32(b[12:]) != 2 {
		return false
	}
	n, size := int(binary.LittleEndian.Uint32(b[16:])), int(binary.LittleEndian.Uint32(b[20:]))
	if n < 1 || n > 4096 || size < 8 || size > len(b)-32 {
		return false
	}
	off, end, dyld, lib := 32, 32+size, false, false
	for i := 0; i < n; i++ {
		if off+8 > end {
			return false
		}
		c := binary.LittleEndian.Uint32(b[off:])
		length := int(binary.LittleEndian.Uint32(b[off+4:]))
		if length < 8 || length%8 != 0 || off+length > end {
			return false
		}
		switch c {
		case 0xe, 0xc:
			if length < 12 {
				return false
			}
			at := int(binary.LittleEndian.Uint32(b[off+8:]))
			if at < 12 || at >= length {
				return false
			}
			name, _, found := bytes.Cut(b[off+at:off+length], []byte{0})
			if !found {
				return false
			}
			if c == 0xe {
				if string(name) != "/usr/lib/dyld" || dyld {
					return false
				}
				dyld = true
			} else {
				if string(name) != "/usr/lib/libSystem.B.dylib" || lib {
					return false
				}
				lib = true
			}
		case 0x8000001c, 0x80000018, 0x8000001f, 0x80000023, 0x20:
			return false
		}
		off += length
	}
	return off == end && dyld && lib
}

type (
	actionHeldFile struct {
		path      string
		fd        *os.File
		info      fs.FileInfo
		bytes     []byte
		directory bool
	}
	actionFiles struct {
		root     *os.Root
		rootPath string
		rootInfo fs.FileInfo
		held     []actionHeldFile
	}
)

func openActionFiles(root string) (*actionFiles, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrActionSelection
	}
	// Runtime supplies the locator. Refuse symlinks in its entire parent chain.
	for p := root; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&fs.ModeSymlink != 0 {
			return nil, ErrActionSelection
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	a := &actionFiles{root: r, rootPath: root}
	a.rootInfo, e = r.Stat(".")
	current, ce := os.Lstat(root)
	if e != nil || ce != nil || !os.SameFile(a.rootInfo, current) {
		r.Close()
		return nil, ErrActionSelection
	}
	return a, nil
}

func (a *actionFiles) read(ctx context.Context, p string, limit int) ([]byte, error) {
	if a == nil || a.root == nil || ctx == nil || ctx.Err() != nil || !actionPath(p) || len(a.held) >= 4096 {
		return nil, ErrActionSelection
	}
	for _, h := range a.held {
		if h.path == p {
			if h.directory {
				return nil, ErrActionSelection
			}
			return append([]byte(nil), h.bytes...), nil
		}
	}
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		found := false
		for _, h := range a.held {
			found = found || h.path == dir
		}
		if found {
			continue
		}
		if len(a.held) >= 4096 {
			return nil, ErrActionSelection
		}
		info, e := a.root.Lstat(dir)
		if e != nil || !info.IsDir() || info.Mode()&(fs.ModeSymlink|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
			return nil, ErrActionSelection
		}
		f, e := a.openMember(dir)
		if e != nil {
			return nil, e
		}
		opened, e := f.Stat()
		if e != nil || !sameActionInfo(info, opened) {
			f.Close()
			return nil, ErrActionSelection
		}
		a.held = append(a.held, actionHeldFile{path: dir, fd: f, info: opened, directory: true})
	}
	info, e := a.root.Lstat(p)
	if e != nil || !actionRegular(info) || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, ErrActionSelection
	}
	f, e := a.openMember(p)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	before, e := f.Stat()
	if e != nil || !sameActionInfo(info, before) || !actionRegular(before) {
		return nil, ErrActionSelection
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit || int64(len(b)) != before.Size() {
		return nil, ErrActionSelection
	}
	after, e := f.Stat()
	current, ce := a.root.Lstat(p)
	if e != nil || ce != nil || !sameActionInfo(before, after) || !sameActionInfo(after, current) || !actionRegular(after) || !actionRegular(current) || ctx.Err() != nil {
		return nil, ErrActionSelection
	}
	a.held = append(a.held, actionHeldFile{path: p, fd: f, info: before, bytes: b})
	success = true
	return append([]byte(nil), b...), nil
}

func (a *actionFiles) check(ctx context.Context) error {
	if a == nil || a.root == nil || ctx == nil || ctx.Err() != nil {
		return ErrActionSelection
	}
	current, e := os.Lstat(a.rootPath)
	held, he := a.root.Stat(".")
	if e != nil || he != nil || !sameActionInfo(a.rootInfo, current) || !sameActionInfo(held, current) {
		return ErrActionSelection
	}
	for _, h := range a.held {
		if ctx.Err() != nil {
			return ErrActionSelection
		}
		info, e := h.fd.Stat()
		current, ce := a.root.Lstat(h.path)
		if e != nil || ce != nil || !sameActionInfo(h.info, info) || !sameActionInfo(h.info, current) {
			return ErrActionSelection
		}
		if h.directory {
			if !info.IsDir() {
				return ErrActionSelection
			}
			continue
		}
		if !actionRegular(info) || !actionRegular(current) {
			return ErrActionSelection
		}
		b := make([]byte, len(h.bytes)+1)
		n, e := h.fd.ReadAt(b, 0)
		if e != io.EOF || n != len(h.bytes) || !bytes.Equal(h.bytes, b[:n]) {
			return ErrActionSelection
		}
		after, e := h.fd.Stat()
		pathAfter, pe := a.root.Lstat(h.path)
		if e != nil || pe != nil || !sameActionInfo(h.info, after) || !sameActionInfo(h.info, pathAfter) || !actionRegular(after) || !actionRegular(pathAfter) {
			return ErrActionSelection
		}
	}
	return ctx.Err()
}

// Native flag values are closed to the two admitted OS ABIs. OpenFile keeps
// the descriptor nonblocking and refuses a last-component symlink even when
// a regular file is replaced between Lstat and open; unknown hosts refuse.
func (a *actionFiles) openMember(p string) (*os.File, error) {
	flags := os.O_RDONLY
	switch runtime.GOOS {
	case "darwin":
		flags |= 0x4 | 0x100
	case "linux":
		flags |= 0x800 | 0x20000
	default:
		return nil, ErrActionSelection
	}
	return a.root.OpenFile(p, flags, 0)
}

func (a *actionFiles) close() {
	if a != nil {
		for _, h := range a.held {
			h.fd.Close()
		}
		a.held = nil
		if a.root != nil {
			a.root.Close()
			a.root = nil
		}
	}
}

func sameActionInfo(a, b fs.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && reflect.DeepEqual(actionCTime(a), actionCTime(b))
}

func actionCTime(i fs.FileInfo) any {
	v := reflect.ValueOf(i.Sys())
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return nil
	}
	for _, field := range []string{"Ctim", "Ctimespec"} {
		x := v.Elem().FieldByName(field)
		if x.IsValid() && x.CanInterface() {
			return x.Interface()
		}
	}
	return nil
}

func actionRegular(i fs.FileInfo) bool {
	if i == nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0o644 || i.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return false
	}
	v := reflect.ValueOf(i.Sys())
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	n := v.Elem().FieldByName("Nlink")
	return n.IsValid() && n.CanUint() && n.Uint() == 1
}

// ActionProfileDigest binds the finite OS/resource contract into the capsule.
// No platform grant or installed tool authority can be minted from this value.
func ActionProfileDigest(profile string) (string, error) {
	if !actionProfile(profile) {
		return "", ErrActionSelection
	}
	if profile == "linux-static-fd-go127-poll/v1" {
		return bootstrap.DomainDigest("tplaiter.dev/action-os-profile/v2", struct {
			APIVersion           string `json:"apiVersion"`
			Profile              string `json:"profile"`
			FDProtocol           string `json:"fdProtocol"`
			PollPolicy           string `json:"pollPolicy"`
			CreationFlags        string `json:"creationFlags"`
			RegistrationTargets  string `json:"registrationTargets"`
			StatusExceptionBytes int64  `json:"statusExceptionBytes"`
			WallMS               int64  `json:"wallMS"`
			CPUS                 int64  `json:"cpuS"`
			StackBytes           int64  `json:"stackBytes"`
			AddressBytes         int64  `json:"addressBytes"`
			FDLimit              int64  `json:"fdLimit"`
			StdoutLimit          int64  `json:"stdoutLimit"`
			StderrLimit          int64  `json:"stderrLimit"`
		}{"tplaiter.dev/action-os-profile/v2", profile, "stdin-regular0-poll3-event4-descriptor6-input7/v2", "fixed-poll3-event4/v1", "epoll:CLOEXEC;eventfd:initial0,CLOEXEC,NONBLOCK;io4:8bytes", "0,1,2,4,6..N;ADD,DEL;wait128,nullsigmask", 111, 5000, 5, 8 << 20, 2 << 30, 256, 128 << 10, 16 << 10})
	}
	return bootstrap.DomainDigest("tplaiter.dev/action-os-profile/v1", struct {
		APIVersion   string `json:"apiVersion"`
		Profile      string `json:"profile"`
		FDProtocol   string `json:"fdProtocol"`
		WallMS       int64  `json:"wallMS"`
		CPUS         int64  `json:"cpuS"`
		StackBytes   int64  `json:"stackBytes"`
		AddressBytes int64  `json:"addressBytes"`
		FDLimit      int64  `json:"fdLimit"`
		StdoutLimit  int64  `json:"stdoutLimit"`
		StderrLimit  int64  `json:"stderrLimit"`
	}{"tplaiter.dev/action-os-profile/v1", profile, "stdin-regular0-descriptor6-input7/v1", 5000, 5, 8 << 20, 2 << 30, 256, 128 << 10, 16 << 10})
}

// ValidateBoundNativeCommands admits inert, source-bound command declarations.
// It never verifies an operator grant or creates a runtime execution capability.
func ValidateBoundNativeCommands(snapshot *trustverify.SourceSnapshot, tpl *manifest.Template) error {
	if snapshot == nil || tpl == nil {
		return ErrActionSelection
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return ErrActionSelection
	}
	bound, e := manifest.ParseTemplate(raw)
	if e != nil || !reflect.DeepEqual(bound, tpl) {
		return ErrActionSelection
	}
	metadata, hasMetadata := snapshot.Blob(TemplateActionsPath)
	if !hasMetadata {
		return ValidateBoundProjectBuildContent(snapshot, tpl)
	}
	// Metadata presence is never ignored even when the legacy declaration passes.
	doc, e := decodeActionDocument(metadata)
	if e != nil || len(doc.Actions) != len(tpl.Commands) || len(doc.Actions) == 0 {
		return ErrActionSelection
	}
	for _, a := range doc.Actions {
		c, ok := tpl.Commands[a.ID]
		// build remains the separately closed compiler route. Conditional actions
		// require a future connected condition-selection contract, not silent ignore.
		if !ok || a.ID == "build" || c.Run != "tplaiter-action:"+a.ID || c.When != "" {
			return ErrActionSelection
		}
		inputs := append(append([]actionFile(nil), a.Inputs...), a.Stdin)
		for _, f := range inputs {
			if f.Root == "provider" {
				b, ok := actionSnapshotBlob(snapshot, f.Path, f.Mode)
				if !ok || evidencecas.Digest(b) != f.SHA256 || (f == a.Stdin && len(b) > 1<<20) {
					return ErrActionSelection
				}
			}
		}
	}
	return nil
}

// ValidateNativeCommandSource authenticates inert declarations in the selected
// native source. Enrollment is separate from operator approval and execution.
func ValidateNativeCommandSource(ctx context.Context, runtime *trustverify.Runtime, input []byte, tpl *manifest.Template) error {
	if ctx == nil || runtime == nil {
		return ErrActionSelection
	}
	selected, err := DecodeSourceSelection(input)
	if err != nil {
		return err
	}
	resolution, err := runtime.VerifySubject(ctx, selected.TrustSubject(), selected.EvidenceRefs())
	if err != nil {
		return err
	}
	snapshot, err := runtime.VerifiedSnapshot(resolution)
	if err != nil {
		return err
	}
	raw, ok := snapshot.Blob("template.manifest.yaml")
	if !ok {
		return ErrActionSelection
	}
	if _, err := requireNativeContract(snapshot.ContractBytes(), raw); err != nil {
		return err
	}
	return ValidateBoundNativeCommands(snapshot, tpl)
}

// v2 selects installed-current proof explicitly; v1 never retries via this route.
func actionToolSubject(p trustverify.Provider) trustverify.Subject {
	return trustverify.Subject{Origin: p.Origin, TemplatePath: p.TemplatePath, RequestedRef: p.Commit, Commit: p.Commit, TreeSHA256: p.TreeSHA256, ContractSHA256: p.ContractSHA256}
}

func actionPublisher(e SelectionEvidence) bootstrap.PublisherEvidence {
	return bootstrap.PublisherEvidence{StatementCAS: e.StatementCAS, SignatureCAS: e.SignatureCAS, KeyFingerprint: e.KeyFingerprint}
}

func actionEvidenceMatches(version string, declared SelectionEvidence, actual trustverify.EvidenceRefs) bool {
	if version == "tplaiter.dev/template-actions/v1" {
		return declared == actionEvidence(actual)
	}
	return version == "tplaiter.dev/template-actions/v2" && declared.Format == actual.Format && actionPublisher(declared) == (bootstrap.PublisherEvidence{StatementCAS: actual.StatementCAS, SignatureCAS: actual.SignatureCAS, KeyFingerprint: actual.KeyFingerprint}) && declared.CheckpointCAS == "" && declared.InclusionProofCAS == ""
}

func actionCurrentDocument(raw []byte) ([]byte, bool, error) {
	if len(raw) == 0 || len(raw) > actionMetadataLimit {
		return nil, false, ErrActionSelection
	}
	canonical, e := canonicaljson.Canonicalize(raw)
	if e != nil || !bytes.Equal(raw, canonical) {
		return nil, false, ErrActionSelection
	}
	var doc map[string]json.RawMessage
	if canonicaljson.DecodeStrict(raw, &doc) != nil {
		return nil, false, ErrActionSelection
	}
	var version string
	if json.Unmarshal(doc["apiVersion"], &version) != nil {
		return nil, false, ErrActionSelection
	}
	if version != "tplaiter.dev/template-actions/v2" {
		return raw, false, nil
	}
	var actions []map[string]json.RawMessage
	if json.Unmarshal(doc["actions"], &actions) != nil || actions == nil {
		return nil, false, ErrActionSelection
	}
	for _, a := range actions {
		var tool map[string]json.RawMessage
		if json.Unmarshal(a["tool"], &tool) != nil || len(tool) != 6 {
			return nil, false, ErrActionSelection
		}
		var selection string
		if json.Unmarshal(tool["selection"], &selection) != nil || selection != "installed-current/v1" {
			return nil, false, ErrActionSelection
		}
		delete(tool, "selection")
		var evidence map[string]json.RawMessage
		if json.Unmarshal(tool["evidence"], &evidence) != nil || len(evidence) != 4 {
			return nil, false, ErrActionSelection
		}
		for _, name := range []string{"format", "statementCAS", "signatureCAS", "keyFingerprint"} {
			if v, ok := evidence[name]; !ok || bytes.Equal(v, []byte("null")) {
				return nil, false, ErrActionSelection
			}
		}
		evidence["checkpointCAS"] = json.RawMessage(`""`)
		evidence["inclusionProofCAS"] = json.RawMessage(`""`)
		tool["evidence"], e = canonicaljson.Canonical(evidence)
		if e != nil {
			return nil, false, e
		}
		a["tool"], e = canonicaljson.Canonical(tool)
		if e != nil {
			return nil, false, e
		}
	}
	doc["actions"], e = canonicaljson.Canonical(actions)
	if e != nil {
		return nil, false, e
	}
	normalized, e := canonicaljson.Canonical(doc)
	return normalized, true, e
}

func actionCurrentCapsule(c actionCapsule, metadata []byte, tool *trustverify.VerifiedResolution, binding bootstrap.ProfileBinding) ([]byte, error) {
	raw, e := canonicaljson.Canonical(c)
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, ErrActionSelection
	}
	var doc struct {
		Actions []json.RawMessage `json:"actions"`
	}
	if json.Unmarshal(metadata, &doc) != nil {
		return nil, ErrActionSelection
	}
	var declaration json.RawMessage
	for _, a := range doc.Actions {
		var id struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(a, &id) != nil {
			return nil, ErrActionSelection
		}
		if id.ID == c.Declaration.ID {
			declaration = a
		}
	}
	if declaration == nil {
		return nil, ErrActionSelection
	}
	fields["apiVersion"] = json.RawMessage(`"tplaiter.dev/action-capsule/v2"`)
	fields["declaration"] = declaration
	fields["toolSelectionVersion"] = json.RawMessage(`"installed-current/v1"`)
	fields["verifiedToolSubject"], e = canonicaljson.Canonical(provider(tool.Subject()))
	if e != nil {
		return nil, e
	}
	fields["verifiedToolEvidence"], e = canonicaljson.Canonical(actionEvidence(tool.Evidence()))
	if e != nil {
		return nil, e
	}
	digest, e := bootstrap.DomainDigest(bootstrap.ProfileBindingAPIVersion, binding)
	if e != nil {
		return nil, e
	}
	fields["profileBindingSHA256"], e = canonicaljson.Canonical(digest)
	if e != nil {
		return nil, e
	}
	return canonicaljson.Canonical(fields)
}
