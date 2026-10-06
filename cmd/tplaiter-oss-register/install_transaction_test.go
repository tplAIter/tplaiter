package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tplAIter/tplaiter/internal/ossinstall"
)

func TestTransactionSubprocessWholeBarrier(t *testing.T) {
	if os.Getenv("TPLAITER_TRANSACTION_CHILD") == "1" {
		t.Skip("child handled by TestTransactionSubprocessChild")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	explicitRegistration, err := ossinstall.GenerateWithContext(context.Background(), ossinstall.Options{Root: filepath.Join(base, "explicit-registration", "trust")})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		root1        string
		root2        string
		destination1 string
		destination2 string
		explicit     bool
	}{
		{"same-root-different-destination", root, root, filepath.Join(base, "a", "tplaiter"), filepath.Join(base, "b", "tplaiter"), false},
		{"different-root-same-destination", root, filepath.Join(base, "other-root"), filepath.Join(base, "c", "tplaiter"), filepath.Join(base, "c", "tplaiter"), false},
		{"same-root-same-destination", root, root, filepath.Join(base, "d", "tplaiter"), filepath.Join(base, "d", "tplaiter"), false},
		{"explicit-pins-destination-only", filepath.Join(base, "unused-explicit-root"), filepath.Join(base, "unused-explicit-root-2"), filepath.Join(base, "e", "tplaiter"), filepath.Join(base, "e", "tplaiter"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			barrier1 := t.TempDir()
			barrier2 := t.TempDir()
			registrationPath, registrationSHA := "", ""
			if tc.explicit {
				registrationPath, registrationSHA = explicitRegistration.RegistrationPath, explicitRegistration.RegistrationSHA256
			}
			first := startTransactionChild(t, tc.root1, tc.destination1, barrier1, tc.explicit, true, registrationPath, registrationSHA)
			waitForPhase(t, barrier1, string(transactionBeforePublication))
			second := startTransactionChild(t, tc.root2, tc.destination2, barrier2, tc.explicit, false, registrationPath, registrationSHA)
			time.Sleep(150 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(barrier2, string(transactionLocked))); err == nil {
				t.Fatal("second transaction crossed lock barrier before first publication")
			}
			if err := os.WriteFile(filepath.Join(barrier1, "release"), []byte("release\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			waitChild(t, first)
			waitChild(t, second)
			for _, barrier := range []string{barrier1, barrier2} {
				proof := readTransactionProof(t, filepath.Join(barrier, "proof.json"))
				t.Logf("writer proof: %+v", proof)
				if proof.BuiltSHA256 == "" || proof.BuiltSHA256 != proof.FinalSHA256 || !proof.BuildInfoPathPresent || !proof.CGO0 || !proof.Trimpath || proof.RegistrationPath == "" || proof.RegistrationSHA256 == "" {
					t.Fatalf("invalid final-writer proof: %+v", proof)
				}
				if tc.explicit && (proof.RegistrationPath != registrationPath || proof.RegistrationSHA256 != registrationSHA) {
					t.Fatalf("explicit registration pair changed: %+v", proof)
				}
			}
			for _, destination := range []string{tc.destination1, tc.destination2} {
				info, err := os.Stat(destination)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("publication missing exact regular destination %s: %v", destination, err)
				}
			}
			if tc.explicit {
				if _, err := os.Stat(tc.root1); !os.IsNotExist(err) {
					t.Fatalf("explicit pins created root coordinator input: %v", err)
				}
			}
		})
	}
}

type transactionProof struct {
	BuiltSHA256          string
	FinalSHA256          string
	RegistrationPath     string
	RegistrationSHA256   string
	BuildInfoPathPresent bool
	CGO0                 bool
	Trimpath             bool
}

func TestTransactionSubprocessChild(t *testing.T) {
	if os.Getenv("TPLAITER_TRANSACTION_CHILD") != "1" {
		return
	}
	args := os.Args
	separator := 0
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == 0 || len(args) < separator+8 {
		os.Exit(2)
	}
	root, destination, barrier, mode, wait := args[separator+1], args[separator+2], args[separator+3], args[separator+4], args[separator+5]
	registrationPath, registrationSHA := args[separator+6], args[separator+7]
	transactionPhaseHook = func(event transactionPhaseEvent) error {
		if err := os.WriteFile(filepath.Join(barrier, string(event.Phase)), []byte("ready\n"), 0o600); err != nil {
			return err
		}
		if event.Phase == transactionBuilt {
			raw, err := os.ReadFile(event.BuildOutput)
			if err != nil {
				return err
			}
			info, err := buildinfo.ReadFile(event.BuildOutput)
			if err != nil {
				return err
			}
			if !bytes.Contains(raw, []byte(event.RegistrationPath)) || !bytes.Contains(raw, []byte(event.RegistrationSHA256)) {
				return errors.New("built binary is missing linker registration pins")
			}
			settings := map[string]string{}
			for _, setting := range info.Settings {
				settings[setting.Key] = setting.Value
			}
			proof := transactionProof{
				BuiltSHA256:          digestBytes(raw),
				RegistrationPath:     event.RegistrationPath,
				RegistrationSHA256:   event.RegistrationSHA256,
				BuildInfoPathPresent: info.Path != "",
				CGO0:                 settings["CGO_ENABLED"] == "0",
				Trimpath:             settings["-trimpath"] == "true",
			}
			return writeTransactionProof(filepath.Join(barrier, "proof.json"), proof)
		}
		if event.Phase == transactionPublished {
			proof, err := readProofFile(filepath.Join(barrier, "proof.json"))
			if err != nil {
				return err
			}
			final, err := os.ReadFile(event.Destination)
			if err != nil {
				return err
			}
			proof.FinalSHA256 = digestBytes(final)
			return writeTransactionProof(filepath.Join(barrier, "proof.json"), proof)
		}
		if event.Phase == transactionBeforePublication && wait == "wait" {
			for {
				if _, err := os.Stat(filepath.Join(barrier, "release")); err == nil {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		return nil
	}
	argv := []string{"--transaction", "--root", root, "--destination", destination}
	if mode == "explicit" {
		argv = append(argv, "--registration-path", registrationPath, "--registration-sha256", registrationSHA)
	}
	if err := runWithContext(context.Background(), argv, io.Discard); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	os.Exit(0)
}

func readTransactionProof(t *testing.T, path string) transactionProof {
	t.Helper()
	proof, err := readProofFile(path)
	if err != nil {
		t.Fatalf("read proof %s: %v", path, err)
	}
	return proof
}

func readProofFile(path string) (transactionProof, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return transactionProof{}, err
	}
	var proof transactionProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		return transactionProof{}, err
	}
	return proof, nil
}

func writeTransactionProof(path string, proof transactionProof) error {
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestTransactionPublicationClassification(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(filepath.Dir(root), "classified", "tplaiter")
	failure := errors.New("fixed test build failure")
	transactionPhaseHook = func(event transactionPhaseEvent) error {
		if event.Phase == transactionBuilt {
			return failure
		}
		return nil
	}
	defer func() { transactionPhaseHook = nil }()
	err = runTransaction(context.Background(), ossinstall.Options{Root: root}, destination, "dev", "", "", io.Discard)
	if !errors.Is(err, ossinstall.ErrPublicationCommitted) {
		t.Fatalf("generated post-publication failure lost classification: %v", err)
	}
	if !errors.Is(err, failure) {
		t.Fatalf("generated cause lost: %v", err)
	}

	reusedDestination := filepath.Join(filepath.Dir(root), "reused", "tplaiter")
	transactionPhaseHook = nil
	if err := runTransaction(context.Background(), ossinstall.Options{Root: root}, reusedDestination, "dev", "", "", io.Discard); err != nil {
		t.Fatal(err)
	}
	transactionPhaseHook = func(event transactionPhaseEvent) error {
		if event.Phase == transactionBuilt {
			return failure
		}
		return nil
	}
	err = runTransaction(context.Background(), ossinstall.Options{Root: root}, destination, "dev", "", "", io.Discard)
	if errors.Is(err, ossinstall.ErrPublicationCommitted) {
		t.Fatalf("reused-root failure incorrectly classified as committed: %v", err)
	}

	explicitRoot := filepath.Join(filepath.Dir(root), "explicit-input-must-stay-absent")
	err = runTransaction(context.Background(), ossinstall.Options{Root: explicitRoot}, filepath.Join(filepath.Dir(root), "explicit", "tplaiter"), "dev", filepath.Join(filepath.Dir(root), "pins.json"), "sha256:"+strings.Repeat("1", 64), io.Discard)
	if errors.Is(err, ossinstall.ErrPublicationCommitted) {
		t.Fatalf("explicit-pin failure incorrectly classified as committed: %v", err)
	}
	if _, statErr := os.Stat(explicitRoot); !os.IsNotExist(statErr) {
		t.Fatalf("explicit pins touched root input: %v", statErr)
	}

	lateFailure := errors.New("fixed late output failure")
	transactionPhaseHook = func(event transactionPhaseEvent) error {
		if event.Phase == transactionPublished {
			return lateFailure
		}
		return nil
	}
	lateDestination := filepath.Join(filepath.Dir(root), "late", "tplaiter")
	err = runTransaction(context.Background(), ossinstall.Options{Root: root}, lateDestination, "dev", "", "", io.Discard)
	if !errors.Is(err, ossinstall.ErrPublicationCommitted) || !errors.Is(err, lateFailure) {
		t.Fatalf("late output failure lost committed classification: %v", err)
	}
}

func startTransactionChild(t *testing.T, root, destination, barrier string, explicit, wait bool, registrationPath, registrationSHA string) *exec.Cmd {
	t.Helper()
	mode := "generated"
	if explicit {
		mode = "explicit"
	}
	role := "continue"
	if wait {
		role = "wait"
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestTransactionSubprocessChild$", "--", root, destination, barrier, mode, role, registrationPath, registrationSHA)
	cmd.Env = append(os.Environ(), "TPLAITER_TRANSACTION_CHILD=1")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func waitForPhase(t *testing.T, barrier, phase string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(barrier, phase)); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("phase %s did not arrive", phase)
}

func waitChild(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestInstallLockSubprocessConflictsAndCancellation(t *testing.T) {
	tests := []struct {
		name       string
		parentRoot int
		parentDest int
		childRoot  int
		childDest  int
		conflicts  bool
	}{
		{name: "same root different destination", parentRoot: 0, parentDest: 1, childRoot: 0, childDest: 2, conflicts: true},
		{name: "different root same destination", parentRoot: 0, parentDest: 1, childRoot: 2, childDest: 1, conflicts: true},
		{name: "same root same destination", parentRoot: 0, parentDest: 1, childRoot: 0, childDest: 1, conflicts: true},
		{name: "different root different destination", parentRoot: 0, parentDest: 1, childRoot: 2, childDest: 3, conflicts: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roots, destinations := lockFixtures(t)
			parent, err := ossinstall.AcquireInstallLocks(context.Background(), roots[tc.parentRoot], destinations[tc.parentDest])
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()

			cmd, output, input, err := startLockChild(roots[tc.childRoot], destinations[tc.childDest], "")
			if err != nil {
				t.Fatal(err)
			}
			line := make(chan string, 1)
			go func() {
				scanner := bufio.NewScanner(output)
				if scanner.Scan() {
					line <- scanner.Text()
				}
			}()
			if tc.conflicts {
				select {
				case got := <-line:
					t.Fatalf("child acquired conflicting locks early: %s", got)
				case <-time.After(150 * time.Millisecond):
				}
				if err := parent.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-line:
					if got != "acquired" {
						t.Fatalf("child status: %s", got)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("child did not acquire locks after release")
				}
			} else {
				select {
				case got := <-line:
					if got != "acquired" {
						t.Fatalf("child status: %s", got)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("child did not acquire independent locks")
				}
			}
			_, _ = io.WriteString(input, "release\n")
			_ = input.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}

	roots, destinations := lockFixtures(t)
	parent, err := ossinstall.AcquireInstallLocks(context.Background(), roots[0], destinations[0])
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	cmd, output, _, err := startLockChild(roots[0], destinations[0], "cancel")
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "canceled" {
		t.Fatalf("cancellation child output: %q", scanner.Text())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionRejectsForeignRootWithoutChangingIt(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("keep me"), 0o640); err != nil {
		t.Fatal(err)
	}
	destinationParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(destinationParent, "bin", "tplaiter")
	err = runWithContext(context.Background(), []string{"--transaction", "--root", root, "--destination", destination}, io.Discard)
	if !errors.Is(err, ossinstall.ErrInstallRootForeign) {
		t.Fatalf("foreign root error: %v", err)
	}
	raw, err := os.ReadFile(foreign)
	if err != nil || string(raw) != "keep me" {
		t.Fatalf("foreign file changed: %v %q", err, raw)
	}
}

func lockFixtures(t *testing.T) ([]string, []string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := make([]string, 4)
	destinations := make([]string, 4)
	for i := range roots {
		roots[i] = filepath.Join(base, fmt.Sprintf("root-%d", i), "trust")
		destinations[i] = filepath.Join(base, fmt.Sprintf("destination-%d", i), "bin", "tplaiter")
	}
	return roots, destinations
}

func startLockChild(root, destination, mode string) (*exec.Cmd, io.ReadCloser, io.WriteCloser, error) {
	args := []string{"-test.run", "^TestInstallLockChild$", "--", root, destination, mode}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "TPLAITER_LOCK_CHILD=1")
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd.Stderr = os.Stderr
	return cmd, output, input, cmd.Start()
}

func TestInstallLockChild(t *testing.T) {
	if os.Getenv("TPLAITER_LOCK_CHILD") != "1" {
		return
	}
	args := os.Args
	separator := 0
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator == 0 || len(args) < separator+4 {
		os.Exit(2)
	}
	root, destination, mode := args[separator+1], args[separator+2], args[separator+3]
	ctx := context.Background()
	var cancel context.CancelFunc
	if mode == "cancel" {
		ctx, cancel = context.WithTimeout(ctx, 120*time.Millisecond)
		defer cancel()
	}
	locks, err := ossinstall.AcquireInstallLocks(ctx, root, destination)
	if mode == "cancel" {
		if !errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintln(os.Stdout, "unexpected", err)
			os.Exit(3)
		}
		fmt.Fprintln(os.Stdout, "canceled")
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stdout, "error", err)
		os.Exit(4)
	}
	fmt.Fprintln(os.Stdout, "acquired")
	var release string
	_, _ = fmt.Fscan(os.Stdin, &release)
	_ = locks.Close()
	os.Exit(0)
}
