package trustload

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/bootstrap"
)

func validInstall() RuntimeInstall {
	d := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	return RuntimeInstall{
		APIVersion: RuntimeInstallAPIVersion, InstallationID: "install.test", Profile: bootstrap.ProfileOSS, MinimumProfile: bootstrap.ProfileOSS,
		Descriptor: FilePin{"/var/tmp/tplaiter-test/descriptor.json", d}, Provisioning: FilePin{"/var/tmp/tplaiter-test/provisioning.json", d2},
		OperatorRecord: FilePin{"/var/tmp/tplaiter-test/operator.json", d}, ExecutionPolicy: FilePin{"/var/tmp/tplaiter-test/policy.json", d2},
		ProjectContexts: []ProjectContext{{Key: "project", ProjectID: "project.test", SubmitterPrincipalID: "principal.test", MinimumProfile: bootstrap.ProfileOSS, RootPath: "/var/tmp/tplaiter-project"}},
		ObjectOrigins:   []ObjectOrigin{{Origin: "https://example.test/source", RootPath: "/var/tmp/tplaiter-objects"}}, EvidenceRoot: "/var/tmp/tplaiter-evidence", ScratchRoot: "/var/tmp/tplaiter-scratch",
		OSS: &OSSInstall{StorePath: "/var/tmp/tplaiter-store", InitialStatePath: "/var/tmp/tplaiter-state", InitialStateSHA256: d, InitialBundlePath: "/var/tmp/tplaiter-bundle", InitialBundleSHA256: d2},
	}
}

func TestDecodeRuntimeInstallClosedAndBounded(t *testing.T) {
	v := validInstall()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRuntimeInstall(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallationID != v.InstallationID {
		t.Fatalf("installation id = %q", got.InstallationID)
	}
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { delete(m, "profile") },
		func(m map[string]any) { m["unexpected"] = true },
		func(m map[string]any) { m["descriptor"] = nil },
		func(m map[string]any) { m["profile"] = "development" },
		func(m map[string]any) {
			m["projectContexts"].([]any)[0].(map[string]any)["minimumProfile"] = "organization"
		},
		func(m map[string]any) {
			m["projectContexts"].([]any)[0].(map[string]any)["rootPath"] = "/var/tmp/tplaiter-store"
		},
		func(m map[string]any) {
			m["projectContexts"].([]any)[0].(map[string]any)["rootPath"] = "/var/tmp/tplaiter-store/sub"
		},
		func(m map[string]any) {
			m["projectContexts"].([]any)[0].(map[string]any)["rootPath"] = "/var/tmp"
		},
		func(m map[string]any) {
			m["descriptor"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("A", 64)
		},
	} {
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mutate(m)
		changed, _ := json.Marshal(m)
		if _, err := DecodeRuntimeInstall(changed); err == nil {
			t.Fatal("accepted invalid runtime install")
		}
	}
}

func TestDecodeOperatorPinRecordClosed(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	good := `{"apiVersion":"tplaiter.dev/operator-pin-record/v1","method":"operator-pinned","descriptorSHA256":"` + d + `"}`
	if got, err := DecodeOperatorPinRecord([]byte(good)); err != nil || got.DescriptorSHA256 != d {
		t.Fatalf("decode good: %v", err)
	}
	for _, raw := range []string{
		`{"apiVersion":"tplaiter.dev/operator-pin-record/v1","method":"release-distribution","descriptorSHA256":"` + d + `"}`,
		`{"apiVersion":"tplaiter.dev/operator-pin-record/v1","method":"operator-pinned","descriptorSHA256":"` + d + `","extra":1}`,
		`{"apiVersion":"tplaiter.dev/operator-pin-record/v1","method":"operator-pinned","descriptorSHA256":null}`,
	} {
		if _, err := DecodeOperatorPinRecord([]byte(raw)); err == nil {
			t.Fatal("accepted invalid operator record")
		}
	}
}

func TestRuntimeDigestIsIndependentOfRawBytes(t *testing.T) {
	v := validInstall()
	d, err := v.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !digest(d) {
		t.Fatalf("bad digest %q", d)
	}
}
