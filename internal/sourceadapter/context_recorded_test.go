package sourceadapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/contextsource"
	"github.com/tplAIter/tplaiter/internal/provenance"
	"github.com/tplAIter/tplaiter/internal/renderref"
	"github.com/tplAIter/tplaiter/internal/resources"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/sourceadapter"
)

func TestRecordedContextSourcesRealAdmissionAndResourceProjection(t *testing.T) {
	started := time.Now()
	t.Log("phase: fixture capture/install/enrollment")
	f := normalNew(t, nil)
	t.Logf("phase: fixture ready elapsed=%s", time.Since(started))
	ctx := context.Background()
	sources, err := contextsource.PrepareContextSources(ctx, f.runtime, f.raw)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	root, deps, err := contextsource.ProjectContextSourceLocks(ctx, f.runtime, sources, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	rootRaw, err := canonicaljson.Canonical(root)
	if err != nil {
		t.Fatal(err)
	}
	depRaw, err := canonicaljson.Canonical(deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("phase: complete recorded closure admission elapsed=%s", time.Since(started))
	actual, err := sourceadapter.PrepareRecordedContextSources(ctx, f.runtime, rootRaw, depRaw)
	if err != nil {
		t.Fatal("recorded closure", err)
	}
	defer actual.Close()
	values := settings.Values{"greeting": "Hello"}
	t.Logf("phase: recorded render elapsed=%s", time.Since(started))
	snapshot, err := contextsource.PrepareRecordedNativeSnapshot(ctx, f.runtime, actual, contextsource.RecordedNativeSnapshotInput{Render: renderref.Input{Values: values}, RecordedValues: values, RendererVersion: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	t.Logf("phase: resource projection elapsed=%s", time.Since(started))
	images, err := resources.PlanContextNativeSnapshotGeneratorImages(ctx, f.runtime, snapshot)
	if err != nil || len(images.Files) == 0 || images.Validate(root) != nil {
		t.Fatal("recorded resource projection", err)
	}
	if _, err := sourceadapter.RecordedContextSourceInput(ctx, f.runtime, rootRaw, depRaw); err != nil {
		t.Fatal("actual recorded transport", err)
	}
	t.Logf("phase: missing/duplicate closure refusals elapsed=%s", time.Since(started))
	missing := deps
	missing.Dependencies = append([]provenance.DependencySubject{}, deps.Dependencies[1:]...)
	missing.LockSHA256, err = provenance.ComputeTemplateLockSHA256(missing)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicaljson.Canonical(missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceadapter.PrepareRecordedContextSources(ctx, f.runtime, rootRaw, raw); err == nil {
		t.Fatal("valid-hash incomplete recorded closure admitted")
	}
	extra := deps
	extra.Dependencies = append(append([]provenance.DependencySubject{}, deps.Dependencies...), deps.Dependencies[0])
	extra.LockSHA256, err = provenance.ComputeTemplateLockSHA256(extra)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = canonicaljson.Canonical(extra)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceadapter.PrepareRecordedContextSources(ctx, f.runtime, rootRaw, raw); err == nil {
		t.Fatal("duplicate recorded source admitted")
	}
	snapshot.Close()
	if _, err := resources.PlanContextNativeSnapshotGeneratorImages(ctx, f.runtime, snapshot); err == nil {
		t.Fatal("closed recorded snapshot supplied resources")
	}
}
