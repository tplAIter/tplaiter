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

func TestRuntimeInstallV2ExplicitLocalRegistration(t *testing.T) {
	v1 := validInstall()
	before, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	v2 := v1
	v2.APIVersion = RuntimeInstallV2APIVersion
	v2.LocalProviders = []FilePin{{Path: "/var/tmp/local-provider-registration.json", SHA256: v1.Descriptor.SHA256}}
	raw, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRuntimeInstall(raw)
	if err != nil || len(got.LocalProviders) != 1 {
		t.Fatal("v2", err)
	}
	h1, _ := v1.Digest()
	h2, _ := v2.Digest()
	if h1 == h2 {
		t.Fatal("digest domain collision")
	}
	empty := v2
	empty.LocalProviders = []FilePin{}
	rawEmpty, _ := json.Marshal(empty)
	if _, err = DecodeRuntimeInstall(rawEmpty); err != nil {
		t.Fatal("explicit empty v2", err)
	}
	for _, mutate := range []func(map[string]any){
		func(m map[string]any) { delete(m, "localProviders") },
		func(m map[string]any) { m["localProviders"] = nil },
		func(m map[string]any) { m["apiVersion"] = RuntimeInstallAPIVersion },
		func(m map[string]any) { m["localProviders"] = []any{m["descriptor"]} },
		func(m map[string]any) {
			m["localProviders"] = []any{map[string]any{"path": v1.ProjectContexts[0].RootPath + "/providers.json", "sha256": v1.Descriptor.SHA256}}
		},
		func(m map[string]any) { m["profile"] = "organization" },
		func(m map[string]any) { m["socketPath"] = "/var/tmp/session.sock" },
	} {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mutate(m)
		bad, _ := json.Marshal(m)
		if _, err = DecodeRuntimeInstall(bad); err == nil {
			t.Fatal("accepted invalid v2")
		}
	}
	var legacy map[string]any
	_ = json.Unmarshal(before, &legacy)
	legacy["localProviders"] = nil
	bad, _ := json.Marshal(legacy)
	if _, err = DecodeRuntimeInstall(bad); err == nil {
		t.Fatal("v1 accepts v2 field")
	}
	after, _ := json.Marshal(v1)
	if string(before) != string(after) {
		t.Fatal("v1 serialization changed")
	}
}
