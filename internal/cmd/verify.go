package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/projectverify"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/stateledger"
	"github.com/tplAIter/tplaiter/internal/stateledger/ledgerpath"
	"github.com/tplAIter/tplaiter/internal/trustload"
)

func init() { registerCommand(newVerifyCmd) }

func newVerifyCmd() *cobra.Command {
	return newReadonlyProjectCommand("verify", "Verify sealed project state using installed offline evidence", resultdto.OperationProjectVerify, runVerify)
}

type readonlyProjectAction func(*cobra.Command, *trustload.Runtime, string) error

func newReadonlyProjectCommand(name, description string, op resultdto.Operation, action readonlyProjectAction) *cobra.Command {
	var key, dir string
	var offline bool
	c := &cobra.Command{Use: name, Short: description, Args: cobra.NoArgs, Annotations: prerunAnnotations(prerunTrustOwned)}
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := readonlyContext(cmd.Context()); err != nil {
			return err
		}
		if !offline {
			return resultdto.NewError("TPL-E-ONLINE-UNSUPPORTED-001", resultdto.ExitUnavailable, nil)
		}
		runtime, err := composeRuntimeForProject(cmd.Context(), key)
		if err != nil {
			if cancelled := readonlyContext(cmd.Context()); cancelled != nil {
				return cancelled
			}
			return err
		}
		defer runtime.Close()
		root := runtime.ProjectContext().RootPath
		if dir != "" {
			abs, err := filepath.Abs(dir)
			if err != nil || filepath.Clean(abs) != root {
				return resultdto.NewError("TRUST_PROJECT_CONTEXT_MISMATCH", resultdto.ExitTrust, nil)
			}
		}
		return action(cmd, runtime, root)
	}
	c.Flags().StringVar(&key, "project-context", "", "key of an authenticated installed project context")
	c.Flags().StringVar(&dir, "dir", "", "project locator; must equal the installed context root")
	c.Flags().BoolVar(&offline, "offline", true, "use only installed evidence; online verification is unavailable")
	return withResult(c, op)
}

func readonlyContext(ctx context.Context) error {
	if ctx == nil {
		return resultdto.NewError(projectverify.StateCode, resultdto.ExitOperational, nil)
	}
	if err := ctx.Err(); err != nil {
		return resultdto.NewError(projectverify.CancelledCode, projectverify.ExitCancelled, err)
	}
	return nil
}

func runVerify(cmd *cobra.Command, runtime *trustload.Runtime, root string) error {
	home, err := readonlyHome()
	if err != nil {
		return err
	}
	report, err := projectverify.Verify(cmd.Context(), root, runtime.TrustRuntime(), projectverify.Options{HomeRoot: home, CAS: runtime, SecretProvider: readonlyHomeClassifier{}})
	if err != nil {
		return err
	}
	return readonlyResult(cmd, resultdto.OperationProjectVerify, runtime, verifyData(report), resultdto.ExitSuccess)
}

func verifyData(r projectverify.Report) resultdto.ProjectVerifyData {
	return resultdto.ProjectVerifyData{Offline: r.Offline, EntryCount: r.EntryCount, LedgerCount: r.LedgerCount, DependencyCount: r.DependencyCount, DependencyState: r.DependencyState}
}

func readonlyResult(cmd *cobra.Command, op resultdto.Operation, runtime *trustload.Runtime, data any, exit resultdto.ExitCode) error {
	if err := readonlyContext(cmd.Context()); err != nil {
		return err
	}
	p := runtime.ProjectContext()
	if jsonMode(cmd) {
		env := newResult(op)
		env.Project = &resultdto.Project{ID: p.ProjectID, Root: p.RootPath}
		env.Status = resultdto.StatusForExit(exit)
		if err := env.SetData(data); err != nil {
			return err
		}
		return emitResult(cmd, env, exit, nil)
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (offline)\n", op, resultdto.StatusForExit(exit))
	if err != nil {
		return err
	}
	if exit != resultdto.ExitSuccess {
		return &resultExitError{code: exit, err: errResultReported}
	}
	return nil
}

// Home selection is a locator only. A missing home is not initialized.
func readonlyHome() (string, error) {
	home, err := state.Home()
	if err != nil {
		return "", resultdto.NewError(projectverify.StateCode, resultdto.ExitOperational, nil)
	}
	// Private credential roots are never inventory inputs, including when
	// a caller redirects HOME or TPLAITER_HOME at them.
	for _, part := range strings.Split(filepath.Clean(home), string(filepath.Separator)) {
		if part == ".globals" {
			return "", resultdto.NewError("TPL-E-SECRET-PROVIDER-001", resultdto.ExitUnavailable, nil)
		}
	}
	info, err := os.Lstat(home)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", resultdto.NewError(projectverify.StateCode, resultdto.ExitOperational, nil)
	}
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", resultdto.NewError(projectverify.StateCode, resultdto.ExitOperational, nil)
	}
	for _, part := range strings.Split(resolved, string(filepath.Separator)) {
		if part == ".globals" {
			return "", resultdto.NewError("TPL-E-SECRET-PROVIDER-001", resultdto.ExitUnavailable, nil)
		}
	}
	return home, nil
}

// No secret digest provider is installed by the OSS launcher. Permit only
// canonical non-secret state owned by named subsystems; unknown home files
// fail before opening them. Never invent a digest or read credential bytes.
type readonlyHomeClassifier struct{}

func (readonlyHomeClassifier) DigestSecret(ctx context.Context, loc stateledger.SecretLocator) (stateledger.SecretDigestResult, error) {
	if err := readonlyContext(ctx); err != nil {
		return stateledger.SecretDigestResult{}, err
	}
	class := ledgerpath.Home(loc.RelativePath)
	if loc.RootID != "home" || class.Classification == "opaque" || class.Classification == "new-transaction-opaque" {
		return stateledger.SecretDigestResult{}, resultdto.NewError("TPL-E-SECRET-PROVIDER-001", resultdto.ExitUnavailable, nil)
	}
	return stateledger.SecretDigestResult{}, nil
}
