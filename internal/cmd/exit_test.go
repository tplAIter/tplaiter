package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/trustload"
	"github.com/tplAIter/tplaiter/internal/update"
)

func TestExitCodeRegistry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want resultdto.ExitCode
	}{
		{"nil", nil, resultdto.ExitSuccess},
		{"untyped", errors.New("template not found"), resultdto.ExitOperational},
		{"usage", &usageError{err: errors.New("unknown flag")}, resultdto.ExitUsage},
		{"finding", &ExitError{Code: 1, Err: errors.New("lint")}, resultdto.ExitFinding},
		{"child passthrough", &ExitError{Code: 127, Err: errors.New("sh")}, resultdto.ExitCode(127)},
		{"update markers", &update.ExitCodeError{Code: 1, Err: errors.New("m")}, resultdto.ExitFinding},
		{"update conflicts", &update.ExitCodeError{Code: 2, Err: errors.New("c")}, resultdto.ExitConflict},
		{"settings conflicts", mapExit(&update.ExitCodeError{Code: 2, Err: errors.New("c")}), resultdto.ExitConflict},
		{"wrapped update", fmt.Errorf("ctx: %w", &update.ExitCodeError{Code: 2, Err: errors.New("c")}), resultdto.ExitConflict},
		{"action unavailable", actionUnavailable(), resultdto.ExitUnavailable},
		{"anchor missing", trustload.ErrAnchorMissing, resultdto.ExitTrust},
		{"ad-hoc unsupported", errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED"), resultdto.ExitUnavailable},
		{"wrapped trust", fmt.Errorf("new: %w", trustload.ErrAnchorMissing), resultdto.ExitTrust},
		{"code inside free text is not parsed", errors.New("path TRUST_ANCHOR_MISSING/x"), resultdto.ExitOperational},
		{"typed wins", errors.Join(trustload.ErrAnchorMissing, resultdto.NewError("TPL-E-TX", resultdto.ExitTransaction, nil)), resultdto.ExitTransaction},
		{"result exit", &resultExitError{code: resultdto.ExitChild, err: errors.New("child")}, resultdto.ExitChild},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeFor(tc.err); got != tc.want {
				t.Fatalf("exitCodeFor(%v)=%d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrorCodesOnlyMatchWholeLeafTokens(t *testing.T) {
	got := errorCodes(errors.Join(actionUnavailable(), errors.New("see TRUST_EXPIRED docs"), fmt.Errorf("x: %w", errors.New("bootstrap: TRUST_EXPIRED"))))
	want := []string{"TRUST_ACTION_UNAVAILABLE", "TRUST_EXPIRED", "TRUST_PROVENANCE_UNAVAILABLE"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("codes=%v, want %v", got, want)
	}
}

// mainHarness runs runMain against a fresh command tree with an isolated
// home and returns the exit status, stdout and stderr.
func mainHarness(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv(state.HomeEnv, home)
	t.Setenv("HOME", home)
	t.Setenv("NO_COLOR", "1")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("version: 1\nrepos: []\ndefaults: {}\nupdates:\n  check: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	root := newTrustRootCommand(invocation{})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	code := runMain(root, args, &stderr)
	return code, stdout.String(), stderr.String()
}

func decodeOne(t *testing.T, stdout string) resultdto.Result {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout must hold exactly one envelope line, got %d:\n%s", len(lines), stdout)
	}
	env, err := resultdto.Decode([]byte(lines[0]))
	if err != nil {
		t.Fatalf("stdout is not result/v1: %v\n%s", err, stdout)
	}
	return env
}

func TestMainJSONSuccessAndFailureEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		exit   resultdto.ExitCode
		op     resultdto.Operation
		status resultdto.Status
		code   string
	}{
		{"repo list", []string{"repo", "list", "--json"}, resultdto.ExitSuccess, resultdto.OperationRepoList, resultdto.StatusOK, ""},
		{"projects list", []string{"projects", "list", "--json"}, resultdto.ExitSuccess, resultdto.OperationProjectsList, resultdto.StatusOK, ""},
		{"doctor", []string{"doctor", "--json"}, resultdto.ExitSuccess, resultdto.OperationDoctorCheck, resultdto.StatusOK, ""},
		{"update check clean", []string{"update", "--check", "--json"}, resultdto.ExitSuccess, resultdto.OperationUpdateCheck, resultdto.StatusOK, ""},
		{"usage", []string{"repo", "list", "--bogus", "--json"}, resultdto.ExitUsage, resultdto.OperationRepoList, resultdto.StatusFailed, "CLI_USAGE"},
		{"native default build unavailable", []string{"gen", "crud", "Ride", "--json"}, resultdto.ExitUnavailable, resultdto.OperationGenRun, resultdto.StatusBlocked, "TRUST_GENERATION_EXECUTION_UNAVAILABLE"},
		{"native file-only anchor missing", []string{"gen", "crud", "Ride", "--no-build", "--json"}, resultdto.ExitTrust, resultdto.OperationGenRun, resultdto.StatusBlocked, "TRUST_ANCHOR_MISSING"},
		{"trust anchor", []string{"new", "ref", "name", "--json"}, resultdto.ExitTrust, resultdto.OperationProjectNew, resultdto.StatusBlocked, "TRUST_ANCHOR_MISSING"},
		{"not in project", []string{"settings", "list", "--json"}, resultdto.ExitOperational, resultdto.OperationSettingsShow, resultdto.StatusFailed, "TPL-E-PROJECT-NOT-FOUND"},
		{"update dry-run names update.plan", []string{"update", "--dry-run", "--json"}, resultdto.ExitTrust, resultdto.OperationUpdatePlan, resultdto.StatusBlocked, "TRUST_ANCHOR_MISSING"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := mainHarness(t, tc.args...)
			if resultdto.ExitCode(code) != tc.exit {
				t.Fatalf("exit=%d, want %d\nstdout=%s\nstderr=%s", code, tc.exit, stdout, stderr)
			}
			env := decodeOne(t, stdout)
			if env.Operation != tc.op || env.Status != tc.status {
				t.Fatalf("envelope %s/%s, want %s/%s", env.Operation, env.Status, tc.op, tc.status)
			}
			if err := env.ValidateExit(resultdto.ExitCode(code)); err != nil {
				t.Fatalf("status does not agree with exit: %v", err)
			}
			if tc.code != "" {
				found := false
				for _, d := range env.Diagnostics {
					found = found || d.Code == tc.code
				}
				if !found {
					t.Fatalf("diagnostics %+v lack %s", env.Diagnostics, tc.code)
				}
			}
		})
	}
}

func TestMainTextModeKeepsStdoutFreeOfEnvelopes(t *testing.T) {
	code, stdout, stderr := mainHarness(t, "gen", "crud", "Ride")
	if resultdto.ExitCode(code) != resultdto.ExitUnavailable || stdout != "" || !strings.Contains(stderr, "TRUST_GENERATION_EXECUTION_UNAVAILABLE") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = mainHarness(t, "gen", "crud", "Ride", "--no-build")
	if resultdto.ExitCode(code) != resultdto.ExitTrust || stdout != "" || !strings.Contains(stderr, "TRUST_ANCHOR_MISSING") {
		t.Fatalf("unauthenticated file-only gen: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, _, _ = mainHarness(t, "no-such-command")
	if resultdto.ExitCode(code) != resultdto.ExitUsage {
		t.Fatalf("unknown command exit=%d, want 2", code)
	}
	code, _, _ = mainHarness(t, "repo", "add", "only-alias")
	if resultdto.ExitCode(code) != resultdto.ExitUsage {
		t.Fatalf("wrong arity exit=%d, want 2", code)
	}
}

// mcpBackedCommands are the CLI commands behind the MCP tools; each must
// support --json with the operation the tool expects.
var mcpBackedCommands = map[string]resultdto.Operation{
	"repo add":              resultdto.OperationRepoAdd,
	"repo list":             resultdto.OperationRepoList,
	"repo update":           resultdto.OperationRepoUpdate,
	"repo remove":           resultdto.OperationRepoRemove,
	"template list":         resultdto.OperationTemplateList,
	"template show":         resultdto.OperationTemplateShow,
	"new":                   resultdto.OperationProjectNew,
	"run":                   resultdto.OperationProjectRun,
	"update":                resultdto.OperationUpdateApply,
	"stats":                 resultdto.OperationProjectStats,
	"doctor":                resultdto.OperationDoctorCheck,
	"ai gen":                resultdto.OperationAIGen,
	"settings list":         resultdto.OperationSettingsShow,
	"settings set":          resultdto.OperationSettingsSet,
	"gen":                   resultdto.OperationGenRun,
	"gen batch":             resultdto.OperationGenBatch,
	"gen list":              resultdto.OperationGenList,
	"workspace add-service": resultdto.OperationWorkspaceAddService,
	"lint-template":         resultdto.OperationTemplateLint,
	"init-template":         resultdto.OperationTemplateInit,
	"projects list":         resultdto.OperationProjectsList,
	"env setup":             resultdto.OperationEnvSetup,
}

func TestEveryMCPBackedCommandSupportsJSON(t *testing.T) {
	root := newTrustRootCommand(invocation{})
	seen := map[string]resultdto.Operation{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if op := resultOperation(c); op != "" {
			path := strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
			seen[path] = op
			if c.Flags().Lookup("json") == nil {
				t.Errorf("%s declares %s but has no --json flag", path, op)
			}
			if _, err := resultdto.KindForOperation(op); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	var missing []string
	for path, op := range mcpBackedCommands {
		if seen[path] != op {
			missing = append(missing, fmt.Sprintf("%s (want %s, got %q)", path, op, seen[path]))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("commands without the expected --json operation:\n%s", strings.Join(missing, "\n"))
	}
}
