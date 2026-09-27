package deps

import (
	"context"
	"testing"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

func TestCheck_FoundSatisfies(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("go", "/usr/local/bin/go")
	runner.OnCommand("go", execx.Response{Result: execx.Result{Stdout: "go version go1.26.4 darwin/arm64\n"}})

	tools := []manifest.Tool{{Name: "go", Version: ">=1.26.0"}}
	got := Check(context.Background(), runner, tools)

	if len(got) != 1 {
		t.Fatalf("Check() returned %d statuses, want 1", len(got))
	}
	st := got[0]
	if !st.Found {
		t.Error("Found = false, want true")
	}
	if st.Path != "/usr/local/bin/go" {
		t.Errorf("Path = %q, want /usr/local/bin/go", st.Path)
	}
	if st.Version != "1.26.4" {
		t.Errorf("Version = %q, want 1.26.4", st.Version)
	}
	if !st.Satisfies {
		t.Errorf("Satisfies = false, want true (err=%v)", st.Err)
	}
	if st.Err != nil {
		t.Errorf("Err = %v, want nil", st.Err)
	}
}

func TestCheck_FoundOldVersionDoesNotSatisfy(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("git", "/usr/bin/git")
	runner.OnCommand("git", execx.Response{Result: execx.Result{Stdout: "git version 2.30.0\n"}})

	tools := []manifest.Tool{{Name: "git", Version: ">=2.40.0"}}
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if !st.Found {
		t.Error("Found = false, want true")
	}
	if st.Version != "2.30.0" {
		t.Errorf("Version = %q, want 2.30.0", st.Version)
	}
	if st.Satisfies {
		t.Error("Satisfies = true, want false (2.30.0 does not satisfy >=2.40.0)")
	}
	if st.Err != nil {
		t.Errorf("Err = %v, want nil (constraint mismatch is not an Err, see Satisfies)", st.Err)
	}
}

func TestCheck_NotFound(t *testing.T) {
	runner := execx.NewRecordingRunner()
	// Ни SetLookPath, ни скрипт Run для "docker" не заданы — LookPath
	// вернёт ошибку "не найдено", как реальный exec.LookPath.

	tools := []manifest.Tool{{Name: "docker", Required: false}}
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if st.Found {
		t.Error("Found = true, want false")
	}
	if st.Satisfies {
		t.Error("Satisfies = true, want false")
	}
	if st.Err == nil {
		t.Error("Err = nil, want non-nil (объясняет отсутствие)")
	}
	if len(runner.Calls) != 0 {
		t.Errorf("Calls = %v, want no Run calls when LookPath fails (не пытаемся исполнить версию отсутствующего бинарника)", runner.Calls)
	}
}

func TestCheck_EmptyConstraintSatisfiesAnyVersion(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("jq", "/usr/bin/jq")
	runner.OnCommand("jq", execx.Response{Result: execx.Result{Stdout: "jq-1.7.1\n"}})

	tools := []manifest.Tool{{Name: "jq"}} // без Version-constraint
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if !st.Found || !st.Satisfies {
		t.Errorf("Found/Satisfies = %v/%v, want true/true (constraint пуст)", st.Found, st.Satisfies)
	}
	if st.Version != "1.7.1" {
		t.Errorf("Version = %q, want 1.7.1", st.Version)
	}
}

func TestCheck_DockerFallsBackToPlainVersionFlag(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("docker", "/usr/local/bin/docker")
	// Первая попытка (--format, требует живой демон) — ошибка.
	runner.On("docker", []string{"version", "--format", "{{.Client.Version}}"}, execx.Response{
		Result: execx.Result{ExitCode: 1, Stderr: "Cannot connect to the Docker daemon"},
		Err:    &execx.ExitError{Name: "docker", ExitCode: 1},
	})
	// Фоллбек — обычный --version, работает без демона.
	runner.OnCommand("docker", execx.Response{Result: execx.Result{Stdout: "Docker version 27.3.1, build 8a028fdc9f4c\n"}})

	tools := []manifest.Tool{{Name: "docker"}}
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if !st.Found {
		t.Fatalf("Found = false, want true (err=%v)", st.Err)
	}
	if st.Version != "27.3.1" {
		t.Errorf("Version = %q, want 27.3.1 (fallback --version)", st.Version)
	}
}

func TestCheck_AnsibleFirstLineOnly(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible", "/usr/bin/ansible")
	runner.OnCommand("ansible", execx.Response{Result: execx.Result{
		Stdout: "ansible [core 2.16.3]\n  config file = /etc/ansible/ansible.cfg\n  python version = 3.11.6\n",
	}})

	tools := []manifest.Tool{{Name: "ansible", Version: ">=2.10.0"}}
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if st.Version != "2.16.3" {
		t.Errorf("Version = %q, want 2.16.3 (from first line only)", st.Version)
	}
	if !st.Satisfies {
		t.Error("Satisfies = false, want true")
	}
}

func TestCheck_AnsibleLegacyFormat(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("ansible", "/usr/bin/ansible")
	runner.OnCommand("ansible", execx.Response{Result: execx.Result{Stdout: "ansible 2.9.27\n  config file = None\n"}})

	tools := []manifest.Tool{{Name: "ansible"}}
	got := Check(context.Background(), runner, tools)

	if got[0].Version != "2.9.27" {
		t.Errorf("Version = %q, want 2.9.27", got[0].Version)
	}
}

func TestCheck_UnparseableVersionOutput(t *testing.T) {
	runner := execx.NewRecordingRunner()
	runner.SetLookPath("mystery", "/usr/bin/mystery")
	runner.OnCommand("mystery", execx.Response{Result: execx.Result{Stdout: "no numbers here\n"}})

	tools := []manifest.Tool{{Name: "mystery"}}
	got := Check(context.Background(), runner, tools)

	st := got[0]
	if !st.Found {
		t.Error("Found = false, want true (бинарник же есть в PATH)")
	}
	if st.Satisfies {
		t.Error("Satisfies = true, want false")
	}
	if st.Err == nil {
		t.Error("Err = nil, want non-nil")
	}
}

func TestExtractGoVersion(t *testing.T) {
	cases := []struct {
		output string
		want   string
		ok     bool
	}{
		{"go version go1.26.4 darwin/arm64", "1.26.4", true},
		{"go version go1.21 linux/amd64", "1.21", true},
		{"garbage", "", false},
	}
	for _, tc := range cases {
		got, ok := extractGoVersion(tc.output)
		if got != tc.want || ok != tc.ok {
			t.Errorf("extractGoVersion(%q) = (%q, %v), want (%q, %v)", tc.output, got, ok, tc.want, tc.ok)
		}
	}
}

func TestExtractGenericVersion(t *testing.T) {
	cases := []struct {
		output string
		want   string
		ok     bool
	}{
		{"git version 2.43.0", "2.43.0", true},
		{"jq-1.7.1", "1.7.1", true},
		{"Docker version 27.3.1, build 8a028fdc9f4c", "27.3.1", true},
		{"v1.2.3", "1.2.3", true},
		{"no version token", "", false},
	}
	for _, tc := range cases {
		got, ok := extractGenericVersion(tc.output)
		if got != tc.want || ok != tc.ok {
			t.Errorf("extractGenericVersion(%q) = (%q, %v), want (%q, %v)", tc.output, got, ok, tc.want, tc.ok)
		}
	}
}

func TestExtractAnsibleVersion(t *testing.T) {
	cases := []struct {
		output string
		want   string
		ok     bool
	}{
		{"ansible [core 2.16.3]\npython version = 3.11.6 (main)", "2.16.3", true},
		{"ansible 2.9.27\n  config file = None", "2.9.27", true},
	}
	for _, tc := range cases {
		got, ok := extractAnsibleVersion(tc.output)
		if got != tc.want || ok != tc.ok {
			t.Errorf("extractAnsibleVersion(%q) = (%q, %v), want (%q, %v)", tc.output, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"1.26", "1.26.0", true},
		{"1.26.4", "1.26.4", true},
		{"2", "2.0.0", true},
		{"not-a-version", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeVersion(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("normalizeVersion(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSatisfiesConstraint(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"1.26.4", "", true},
		{"1.26.4", ">=1.26.0", true},
		{"1.26.4", ">=1.27.0", false},
		{"2.30.0", ">=2.40.0", false},
	}
	for _, tc := range cases {
		got, err := satisfiesConstraint(tc.version, tc.constraint)
		if err != nil {
			t.Fatalf("satisfiesConstraint(%q, %q) error = %v", tc.version, tc.constraint, err)
		}
		if got != tc.want {
			t.Errorf("satisfiesConstraint(%q, %q) = %v, want %v", tc.version, tc.constraint, got, tc.want)
		}
	}
}

func TestSatisfiesConstraint_InvalidConstraintErrors(t *testing.T) {
	if _, err := satisfiesConstraint("1.0.0", "not a constraint"); err == nil {
		t.Error("satisfiesConstraint() error = nil, want non-nil for invalid constraint")
	}
}
