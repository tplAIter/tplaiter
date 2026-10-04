package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/stateledger"
)

func TestReadonlyCommandsRefuseBeforeLegacyHooks(t *testing.T) {
	for _, command := range [][]string{{"verify"}, {"check"}, {"deps", "verify"}} {
		for _, variant := range []struct {
			name, flag, code string
			exit             resultdto.ExitCode
			cancel           bool
		}{
			{name: "anchor", code: "TRUST_ANCHOR_MISSING", exit: resultdto.ExitTrust},
			{name: "online", flag: "--offline=false", code: "TPL-E-ONLINE-UNSUPPORTED-001", exit: resultdto.ExitUnavailable},
			{name: "cancel", code: "TPL-E-CANCELLED-001", exit: resultdto.ExitOperational, cancel: true},
		} {
			t.Run(command[0]+variant.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("TPLAITER_HOME", filepath.Join(home, "absent"))
				root := newTrustRootCommand(invocation{})
				ctx := context.Background()
				if variant.cancel {
					c, cancel := context.WithCancel(ctx)
					cancel()
					ctx = c
				}
				root.SetContext(ctx)
				var out, stderr bytes.Buffer
				root.SetOut(&out)
				args := append([]string(nil), command...)
				if variant.flag != "" {
					args = append(args, variant.flag)
				}
				args = append(args, "--json")
				got := runMain(root, args, &stderr)
				env, err := resultdto.Decode(bytes.TrimSpace(out.Bytes()))
				if err != nil {
					t.Fatalf("exit=%d decode=%v output=%s", got, err, out.Bytes())
				}
				if got != variant.exit.Int() || len(env.Diagnostics) != 1 || env.Diagnostics[0].Code != variant.code || env.Project != nil || len(env.Data) != 0 {
					t.Fatalf("exit=%d result=%+v", got, env)
				}
				if err := env.ValidateExit(variant.exit); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(home)
				if err != nil || len(entries) != 0 {
					t.Fatalf("legacy hook wrote home: %v %v", entries, err)
				}
			})
		}
	}
}

func TestReadonlyHomeAbsentAndSecretRefusal(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "absent")
	t.Setenv("HOME", root)
	t.Setenv("TPLAITER_HOME", home)
	if got, err := readonlyHome(); err != nil || got != "" {
		t.Fatalf("missing home: %q %v", got, err)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("home initialized: %v", err)
	}
	for _, rel := range []string{"auth.json", "credentials.json", "unknown", "credentials/token"} {
		_, err := (readonlyHomeClassifier{}).DigestSecret(context.Background(), stateledger.SecretLocator{RootID: "home", RelativePath: rel})
		diagnostics := resultdto.ProjectDiagnostics(err)
		if resultdto.Classify(err) != resultdto.ExitUnavailable || len(diagnostics) != 1 || diagnostics[0].Code != "TPL-E-SECRET-PROVIDER-001" {
			t.Fatalf("secret read capability: %s %v", rel, err)
		}
	}
	// A hostile credential symlink must be refused before its target can open.
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/unavailable/credential", filepath.Join(home, "auth.json")); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	_, err := stateledger.InventoryContext(context.Background(), project, stateledger.Options{HomeRoot: home, SecretProvider: readonlyHomeClassifier{}})
	if resultdto.Classify(err) != resultdto.ExitUnavailable {
		t.Fatalf("credential target opened: %v", err)
	}
	entries, _ := os.ReadDir(home)
	if len(entries) != 1 {
		t.Fatal("home inventory wrote state")
	}
}

func TestReadonlyPrerunAndScope(t *testing.T) {
	root := newTrustRootCommand(invocation{})
	for _, args := range [][]string{{"verify"}, {"check"}, {"deps", "verify"}} {
		c, _, err := root.Find(args)
		if err != nil {
			t.Fatal(err)
		}
		if classifyPrerun(c, nil) != prerunTrustOwned {
			t.Fatalf("legacy hooks enabled: %v", args)
		}
		scope, err := resultdto.ScopeForOperation(resultOperation(c))
		if err != nil || scope != resultdto.ScopeProject {
			t.Fatalf("scope: %v %v", scope, err)
		}
	}
}

func TestReadonlyHomeRejectsPrivateCredentialRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("TPLAITER_HOME", filepath.Join(root, ".globals"))
	_, err := readonlyHome()
	if resultdto.Classify(err) != resultdto.ExitUnavailable {
		t.Fatalf("private credential inventory allowed: %v", err)
	}
}
