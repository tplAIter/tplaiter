package ossinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/sourcepackage"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

type sourceContractClass uint8

const (
	sourceNative sourceContractClass = iota
	sourceInertContent
)

// Classification is derived solely from verified retained contract bytes. An
// inert index conveys no native root, dependency, resource or action authority.
func validateSourceSnapshot(snapshot *trustverify.SourceSnapshot) (sourceContractClass, error) {
	if snapshot == nil {
		return sourceNative, errors.New("ossinstall: source snapshot missing")
	}
	raw := snapshot.ContractBytes()
	var fields map[string]json.RawMessage
	if len(raw) <= 1<<20 && json.Unmarshal(raw, &fields) == nil {
		var version string
		if json.Unmarshal(fields["apiVersion"], &version) == nil && version == exports.ExportPayloadAPIVersion {
			return sourceInertContent, validateContentSnapshot(snapshot)
		}
	}
	return sourceNative, validateNativeSnapshot(snapshot)
}

func validateContentSnapshot(snapshot *trustverify.SourceSnapshot) error {
	raw := snapshot.ContractBytes()
	payload, err := exports.ParseExportPayload(raw)
	if err != nil {
		return err
	}
	if len(payload.Slots) != 0 || len(payload.Blocks) != 0 {
		return errors.New("ossinstall: inert content cannot declare slots or blocks")
	}
	// ParseExportPayload normalizes ordering for materialization; admission must
	// inspect original order as well, rather than accepting a reordered index.
	var original exports.ExportPayload
	if err := canonicaljson.DecodeStrict(raw, &original); err != nil {
		return err
	}
	entries := snapshot.Entries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	files := []trustverify.SourceEntry{}
	contractFound := false
	for _, entry := range entries {
		if entry.Kind == "directory" {
			continue
		}
		if entry.Kind != "file" || (entry.Mode != "100644" && entry.Mode != "100755") {
			return errors.New("ossinstall: content requires regular files")
		}
		if entry.Path == "template.contract.json" {
			contractFound = true
			continue
		}
		files = append(files, entry)
	}
	if !contractFound || len(files) != len(original.Files) {
		return errors.New("ossinstall: incomplete content index")
	}
	for i, entry := range files {
		f := original.Files[i]
		if f.SourcePath != entry.Path || f.TargetPath != entry.Path || f.Mode != entry.Mode || f.ContentSHA256 != entry.ContentSHA256 {
			return errors.New("ossinstall: content index order, path, mode or digest differs")
		}
	}
	return nil
}

// DecodeLocalSourceBundle accepts existing CaptureInput records, not new caller
// kind/eligibility fields. Source IDs are the canonical origin+templatePath pair.
func DecodeLocalSourceBundle(raw []byte) ([]sourcepackage.CaptureInput, error) {
	if len(raw) == 0 || len(raw) > MaxLocalSourceInputBytes {
		return nil, errors.New("ossinstall: local source input size limit")
	}
	var inputs []sourcepackage.CaptureInput
	if err := canonicaljson.DecodeStrict(raw, &inputs); err != nil {
		return nil, err
	}
	if err := validateBundleInputs(inputs); err != nil {
		return nil, err
	}
	return inputs, nil
}

func validateBundleInputs(inputs []sourcepackage.CaptureInput) error {
	if len(inputs) < 2 || len(inputs) > 16 {
		return errors.New("ossinstall: local bundle requires 2..16 sources")
	}
	ids := map[string]bool{}
	for _, in := range inputs {
		if err := in.Validate(); err != nil {
			return err
		}
		id := in.Origin + "\x00" + in.TemplatePath
		if ids[id] {
			return errors.New("ossinstall: duplicate bundle source identity")
		}
		ids[id] = true
	}
	return nil
}

func generateLocalBundle(ctx context.Context, o Options) (Result, error) {
	if o.LocalSources != nil || o.SourcePackages != nil || o.Publishers != nil || o.Rotate || len(o.ProjectContexts) == 0 {
		return Result{}, errors.New("ossinstall: bundle requires explicit contexts, no other source mode and no rotation")
	}
	if err := validateBundleInputs(o.LocalSourceBundle); err != nil {
		return Result{}, err
	}
	if !filepath.IsAbs(o.Root) || filepath.Clean(o.Root) != o.Root {
		return Result{}, errors.New("ossinstall: canonical absolute install root required")
	}
	if err := canonicalProjectRoot(o.Root); err != nil {
		return Result{}, err
	}
	if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrInstallRootForeign
	}
	for _, p := range o.ProjectContexts {
		if p.SubmitterPrincipalID != operatorPrincipal {
			return Result{}, errors.New("ossinstall: local project submitter must be operator")
		}
	}
	if err := validateProjects(o.Root, o.ProjectContexts, nil); err != nil {
		return Result{}, err
	}
	if len(o.LocalProviders) > 0 {
		if _, err := normalizeLocalProviders(o.LocalProviders, o.ProjectContexts); err != nil {
			return Result{}, err
		}
	}
	inputs := append([]sourcepackage.CaptureInput(nil), o.LocalSourceBundle...)
	sort.Slice(inputs, func(i, j int) bool {
		return inputs[i].Origin+"\x00"+inputs[i].TemplatePath < inputs[j].Origin+"\x00"+inputs[j].TemplatePath
	})
	captures := make([]sourcepackage.CapturedSource, 0, len(inputs))
	nativeCount, contentCount, total := 0, 0, 0
	for _, in := range inputs {
		capture, err := sourcepackage.Capture(ctx, in)
		if err != nil {
			return Result{}, err
		}
		if len(capture.Objects) == 0 || len(capture.Objects) > 8192 {
			return Result{}, errors.New("ossinstall: source object count limit")
		}
		reader := &packageObjects{origin: capture.Subject.Origin, objects: map[string]trustverify.GitObject{}, used: map[string]bool{}}
		for id, raw := range capture.Objects {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			total += len(raw)
			if total > 64<<20 {
				return Result{}, errors.New("ossinstall: aggregate object byte limit")
			}
			object, err := rawObject(id, raw)
			if err != nil {
				return Result{}, err
			}
			reader.objects[id] = object
		}
		snapshot, err := trustverify.VerifySource(ctx, reader, capture.Subject)
		if err != nil {
			return Result{}, err
		}
		if len(reader.used) != len(capture.Objects) {
			return Result{}, errors.New("ossinstall: objects outside selected closure")
		}
		kind, err := validateSourceSnapshot(snapshot)
		if err != nil {
			return Result{}, err
		}
		if kind == sourceNative {
			nativeCount++
		} else {
			contentCount++
		}
		// The exact signed subject/scope must decode before any entropy as well.
		s := capture.Subject
		statement := bootstrap.PublisherStatement{APIVersion: bootstrap.PublisherStatementAPIVersion, PolicyOrigin: localPolicyOrigin, Issuer: "local-operator", Predicate: localPredicate, Usage: "template-source", Subject: bootstrap.SubjectIdentity{Origin: s.Origin, TemplatePath: s.TemplatePath, Commit: s.Commit, TreeSHA256: s.TreeSHA256, ContractSHA256: s.ContractSHA256}}
		raw, err := marshal(statement)
		if err != nil {
			return Result{}, err
		}
		if _, err := bootstrap.DecodePublisherStatement(raw); err != nil {
			return Result{}, err
		}
		captures = append(captures, capture)
	}
	if nativeCount != 1 || contentCount < 1 || contentCount > 15 {
		return Result{}, errors.New("ossinstall: bundle requires one native and 1..15 inert content sources")
	}
	if _, err := os.Lstat(o.Root); !errors.Is(err, os.ErrNotExist) {
		return Result{}, ErrInstallRootForeign
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	records := make([]LocalPublication, 0, len(captures))
	for _, capture := range captures {
		pub, pkg, record, err := signLocalCapture(ctx, o, capture)
		if err != nil {
			return Result{}, err
		}
		o.Publishers = append(o.Publishers, pub)
		o.SourcePackages = append(o.SourcePackages, pkg)
		records = append(records, record)
	}
	var err error
	o.localRecord, err = marshal(records)
	if err != nil {
		return Result{}, err
	}
	return generateEnrollment(ctx, o)
}
