package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/tplAIter/tplaiter/internal/bootstrap"
	"github.com/tplAIter/tplaiter/internal/evidencecas"
	"github.com/tplAIter/tplaiter/internal/operationtrust"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/trustverify"
	"gopkg.in/yaml.v3"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func publicBuildVariantCounterproof(t *testing.T, call func(...string) (string, int), project, base, grant string, workflow bool, policy *trustverify.ExecutionPolicy, key ed25519.PrivateKey, launch trustload.LaunchSelection) {
	t.Helper()
	refuse := func(label string, args ...string) {
		t.Helper()
		out, exit := call(args...)
		if exit == 0 {
			t.Fatalf("%s accepted: %s", label, out)
		}
		var raw []byte
		if i := bytes.IndexByte([]byte(out), '\n'); i >= 0 {
			raw = []byte(out[:i])
		} else {
			raw = []byte(out)
		}
		env, e := resultdto.Decode(raw)
		if e != nil || env.Status != resultdto.StatusBlocked || bytes.Contains(env.Data, []byte("processReceipt")) {
			t.Fatalf("%s not a pre-spawn refusal: %s %v", label, out, e)
		}
		t.Log(label, out)
	}
	mutate := func(name string, b []byte, fn func()) {
		t.Helper()
		name = filepath.Join(project, name)
		saved, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(name, b, 0600); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if e := os.WriteFile(name, saved, 0600); e != nil {
				t.Fatal(e)
			}
		}()
		fn()
	}
	ctx := context.Background()
	owner, e := trustload.OpenRuntime(ctx, trustload.RuntimeOptions{Selection: launch, ProjectKey: "temporal", Clock: bootstrap.ClockFunc(time.Now)})
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	_, values, e := nativeGenCatalog(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	source, e := projectBuildSource(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	wrong := settings.Values{}
	for k, v := range values {
		wrong[k] = v
	}
	wrong["workflow"] = !workflow
	if selected, e := operationtrust.PrepareProjectBuild(ctx, owner, source, "build", wrong); e == nil || selected != nil {
		t.Fatal("caller boolean selected a different variant")
	}
	t.Log("direct API forged caller workflow refused")
	frozen, e := operationtrust.PrepareProjectBuild(ctx, owner, source, "build", values)
	if e != nil {
		t.Fatal(e)
	}
	freshGrant := filepath.Join(base, "cross-variant-fresh-grant.json")
	if e = os.WriteFile(freshGrant, fixtureApproval(t, policy, frozen.Request(), key), 0600); e != nil {
		t.Fatal(e)
	}

	if workflow {
		acquisition := os.Getenv("TPLAITER_PUBLIC_BUILD_ACQUISITION_PACKET")
		raw, e := os.ReadFile(filepath.Join(acquisition, "module-index.json"))
		if e != nil {
			t.Fatal(e)
		}
		var index trustload.GoModuleIndex
		if e = json.Unmarshal(raw, &index); e != nil {
			t.Fatal(e)
		}
		var ref string
		for _, f := range index.Files {
			if strings.HasSuffix(f.Path, "internal/editiondefaults/editions_defaults.binpb") {
				ref = f.Chunks[0]
				break
			}
		}
		if ref == "" {
			t.Fatal("missing declared embedded module asset")
		}
		hash := strings.TrimPrefix(ref, "sha256:")
		cas := filepath.Join(base, "install/evidence/sha256", hash[:2], hash[2:])
		if e = os.Rename(cas, cas+".counterproof"); e != nil {
			t.Fatal(e)
		}
		func() {
			defer func() {
				if e := os.Rename(cas+".counterproof", cas); e != nil {
					t.Fatal(e)
				}
			}()
			refuse("true missing required CAS refused without false fallback", "run", "build", "--prepare", "--json")
		}()
	}

	mod, e := os.ReadFile(filepath.Join(project, "go.mod"))
	if e != nil {
		t.Fatal(e)
	}
	if !workflow {
		mutate("go.mod", append(append([]byte(nil), mod...), []byte("\nrequire example.invalid/undeclared v1.0.0\n")...), func() { refuse("zero-case added require refused", "run", "build", "--prepare", "--json") })
	}
	sum, e := os.ReadFile(filepath.Join(project, "go.sum"))
	if e != nil {
		t.Fatal(e)
	}
	mutate("go.sum", append(append([]byte(nil), sum...), '\n'), func() { refuse("selected raw sum mutation refused", "run", "build", "--prepare", "--json") })
	markerPath := filepath.Join(project, ".tplaiter/project.yaml")
	raw, e := os.ReadFile(markerPath)
	if e != nil {
		t.Fatal(e)
	}
	var marker stateledger.ProjectV2
	if e = yaml.Unmarshal(raw, &marker); e != nil {
		t.Fatal(e)
	}
	delete(marker.Answers, "workflow")
	missing, e := yaml.Marshal(marker)
	if e != nil {
		t.Fatal(e)
	}
	mutate(".tplaiter/project.yaml", missing, func() { refuse("missing explicit workflow answer refused", "run", "build", "--prepare", "--json") })
	marker.Answers["workflow"] = stateledger.Answer{Value: !workflow, Source: "user"}
	flipped, e := yaml.Marshal(marker)
	if e != nil {
		t.Fatal(e)
	}
	mutate(".tplaiter/project.yaml", flipped, func() {
		if material, e := operationtrust.BindProjectBuildMaterial(ctx, owner, frozen); e == nil || material != nil {
			t.Fatal("fresh material accepted changed marker")
		}
		t.Log("opaque selection fresh marker recheck refused")
		refuse("cross-variant marker/input mismatch refused", "run", "build", "--approval-input", freshGrant, "--json")
		acquisition := os.Getenv("TPLAITER_PUBLIC_BUILD_ACQUISITION_PACKET")
		alternateMod, alternateSum := []byte("module example.com/temporal-public-proof\n\ngo 1.26\n"), []byte("\n")
		if !workflow {
			var e error
			alternateMod, e = os.ReadFile(filepath.Join(acquisition, "rendered/go.mod"))
			if e != nil {
				t.Fatal(e)
			}
			alternateSum, e = os.ReadFile(filepath.Join(acquisition, "rendered/go.sum"))
			if e != nil {
				t.Fatal(e)
			}
		}
		mutate("go.mod", alternateMod, func() {
			mutate("go.sum", alternateSum, func() {
				out, exit := call("run", "build", "--prepare", "--json")
				if exit != 0 {
					t.Fatalf("valid alternate variant prepare failed: %s", out)
				}
				env, e := resultdto.Decode([]byte(out))
				if e != nil {
					t.Fatal(e)
				}
				var d resultdto.ProjectRunData
				if e = json.Unmarshal(env.Data, &d); e != nil || d.PreparedRequest == nil {
					t.Fatal("missing alternate request", e)
				}
				if d.PreparedRequest.RequestSHA256 == frozen.Request().RequestSHA256 {
					t.Fatal("variant not request-bound")
				}
				t.Log("valid alternate variant prepared with different request", out)
				refuse("fresh signed grant cannot cross valid variants", "run", "build", "--approval-input", freshGrant, "--json")
			})
		})
	})
}

// These assertions inspect actual committed process envelopes, rather than
// invoking or mirroring the result emitter directly.
func assertNativeGenCommittedSummary(t *testing.T, env resultdto.Result, data resultdto.GenRunData) {
	t.Helper()
	paths := map[string]bool{}
	for _, p := range data.Created {
		paths[p] = true
	}
	for _, p := range data.Edited {
		paths[p] = true
	}
	changes := map[string]bool{}
	for _, c := range env.Changes {
		changes[c.Path] = true
	}
	if env.Summary.FilesChanged != len(paths) || len(changes) != len(paths) {
		t.Fatalf("committed summary %d vs unique paths %d and changes %d", env.Summary.FilesChanged, len(paths), len(changes))
	}
	for p := range paths {
		if !changes[p] {
			t.Fatalf("committed path omitted from changes: %s", p)
		}
	}
}

// A mode of the existing installed proof reuses only this owner's fresh LOCAL
// v3 enrollment. It rebuilds the image after the named summary delta and runs
// only the required actual Gen transports; prior build proofs are not restarted.
func publicBuildCommittedGenSummaryProof(t *testing.T, base string) {
	t.Helper()
	packet := os.Getenv("TPLAITER_PUBLIC_TEMPORAL_PACKET")
	proof := os.Getenv("TPLAITER_PUBLIC_GEN_SUMMARY_PACKET")
	if packet == "" || proof == "" || !strings.HasPrefix(base, filepath.Join(packet, "installed-proof-")) {
		t.Fatal("owned v3 installation and persistent summary packet required")
	}
	home, project := filepath.Join(base, "home"), filepath.Join(base, "project")
	regPath := filepath.Join(base, "install/registration.json")
	raw, e := os.ReadFile(regPath)
	if e != nil {
		t.Fatal(e)
	}
	reg, e := ossinstall.DecodeRegistration(raw)
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := trustload.Load(context.Background(), reg.Selection())
	if e != nil {
		t.Fatal(e)
	}
	policy, e := trustverify.DecodeExecutionPolicy(loaded.PolicyJSON)
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(proof, "tplaiter")
	if os.Getenv("TPLAITER_PUBLIC_BUILD_GEN_SUMMARY_NO_BUILD_ONLY") != "1" {
		build := exec.Command(filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-o", binary, "-ldflags", "-X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath="+regPath+" -X github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256="+evidencecas.Digest(raw), "../..")
		build.Env = testBuildEnv(home)
		if out, e := build.CombinedOutput(); e != nil {
			t.Fatalf("summary image build %v %s", e, out)
		}
	}
	image, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	t.Log("summary delta LOCAL installed image", evidencecas.Digest(image))
	call := func(args ...string) (string, int) {
		t.Helper()
		c := exec.Command(binary, args...)
		c.Dir = base
		c.Env = testProcessEnv(home)
		out, e := c.CombinedOutput()
		exit := 0
		if e != nil {
			if x, ok := e.(*exec.ExitError); ok {
				exit = x.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		return string(out), exit
	}
	if os.Getenv("TPLAITER_PUBLIC_BUILD_GEN_SUMMARY_NO_BUILD_ONLY") == "1" {
		if expected := os.Getenv("TPLAITER_PUBLIC_GEN_SUMMARY_IMAGE_SHA256"); expected == "" || evidencecas.Digest(image) != expected {
			t.Fatal("file-only check requires the exact retained summary image")
		}
		publicBuildSummaryFileOnly(t, call, project)
		return
	}

	key := ed25519.NewKeyFromSeed([]byte("project-build-approver-test-only"))
	prepare := func(args ...string) trustverify.ExecutionRequest {
		t.Helper()
		out, exit := call(append(args, "--prepare", "--json")...)
		if exit != 0 {
			t.Fatalf("summary prepare %d %s", exit, out)
		}
		env, e := resultdto.Decode([]byte(out))
		if e != nil {
			t.Fatal(e)
		}
		if env.Summary.FilesChanged != 0 {
			t.Fatal("prepare counted uncommitted files")
		}
		var data resultdto.GenRunData
		if e = json.Unmarshal(env.Data, &data); e != nil || data.PreparedRequest == nil {
			t.Fatal("missing summary request", e)
		}
		return *data.PreparedRequest
	}
	ops := `[{"kind":"entity","name":"SummaryBatchOne"},{"kind":"entity","name":"SummaryBatchTwo"}]`
	args := []string{"gen", "batch", "--operations", ops, "--dir", project}
	req := prepare(args...)
	grant := filepath.Join(proof, "batch-grant.json")
	if e = os.WriteFile(grant, fixtureApproval(t, policy, req, key), 0600); e != nil {
		t.Fatal(e)
	}
	out, exit := call(append(args, "--approval-input", grant, "--json")...)
	if exit != 0 {
		t.Fatalf("committed batch %d %s", exit, out)
	}
	env, e := resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var data resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &data); e != nil {
		t.Fatal(e)
	}
	if env.Operation != resultdto.OperationGenBatch || env.Status != resultdto.StatusChanges || data.NoBuild || data.ProcessReceipt == nil || data.ProcessReceipt.ExitCode != 0 || data.ProcessReceipt.RequestSHA256 != req.RequestSHA256 || data.ProcessReceipt.BuildVariant != "workflow-false" {
		t.Fatalf("batch flags/receipt changed %s", out)
	}
	assertNativeGenCommittedSummary(t, env, data)
	if env.Summary.FilesChanged != 11 || len(data.Created) != 10 || len(data.Edited) != 1 {
		t.Fatalf("batch shared-anchor count %s", out)
	}
	t.Log("actual committed CLI batch unique summary 11", out)
	mcpReq := prepare("gen", "entity", "SummaryMCP", "--dir", project)
	mcpGrant := filepath.Join(proof, "mcp-grant.json")
	if e = os.WriteFile(mcpGrant, fixtureApproval(t, policy, mcpReq, key), 0600); e != nil {
		t.Fatal(e)
	}
	publicTemporalMCPGen(t, binary, base, home, project, mcpGrant, "SummaryMCP", mcpReq, "")
	before := nativeGenTree(t, project)
	out, exit = call(append(args, "--prepare", "--json")...)
	if exit == 0 {
		t.Fatalf("duplicate batch accepted %s", out)
	}
	// Failure envelopes have a single JSON line followed by the CLI diagnostic.
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	env, e = resultdto.Decode([]byte(out))
	if e != nil || env.Summary.FilesChanged != 0 || len(env.Changes) != 0 {
		t.Fatalf("failed generation counted files %v %s", e, out)
	}
	if !equalStringMap(before, nativeGenTree(t, project)) {
		t.Fatal("failed generation changed files")
	}
	t.Log("failed duplicate batch summary zero and tree unchanged", out)
	publicBuildSummaryFileOnly(t, call, project)
}

func publicBuildSummaryFileOnly(t *testing.T, call func(...string) (string, int), project string) {
	t.Helper()
	out, exit := call("gen", "entity", "SummaryFileOnly", "--dir", project, "--no-build", "--json")
	if exit != 0 {
		t.Fatalf("file-only Gen %d %s", exit, out)
	}
	env, e := resultdto.Decode([]byte(out))
	if e != nil {
		t.Fatal(e)
	}
	var data resultdto.GenRunData
	if e = json.Unmarshal(env.Data, &data); e != nil {
		t.Fatal(e)
	}
	if env.Operation != resultdto.OperationGenRun || env.Status != resultdto.StatusChanges || !data.NoBuild || data.ProcessReceipt != nil {
		t.Fatalf("file-only flags/receipt changed %s", out)
	}
	assertNativeGenCommittedSummary(t, env, data)
	if env.Summary.FilesChanged != 6 || len(data.Created) != 5 || len(data.Edited) != 1 {
		t.Fatalf("file-only count %s", out)
	}
	t.Log("actual file-only Gen committed summary six, no process receipt", out)
}
