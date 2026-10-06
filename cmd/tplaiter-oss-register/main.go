// Command tplaiter-oss-register generates the operator-pinned OSS trust
// installation for a source build. `make install` runs it before linking the
// tplaiter binary; its output is the pair of linker pins
// (REGISTRATION_PATH, REGISTRATION_SHA256) the build compiles in.
//
// It is a build-time tool, not part of the installed CLI: it never runs the
// binary, never touches HOME or XDG directories, and never keeps a private
// key. See docs/adr/ADR-005-oss-install-registration.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
)

type transactionPhase string

const (
	transactionLocked            transactionPhase = "locked"
	transactionGenerated         transactionPhase = "generated"
	transactionBuilt             transactionPhase = "built"
	transactionBeforePublication transactionPhase = "before-publication"
	transactionPublished         transactionPhase = "published"
)

type transactionPhaseEvent struct {
	Phase              transactionPhase
	BuildOutput        string
	Destination        string
	RegistrationPath   string
	RegistrationSHA256 string
}

// transactionPhaseHook is a typed test-only observation seam. Production has
// no command, executable, or environment input that can install a hook.
var transactionPhaseHook func(transactionPhaseEvent) error

func observeTransactionPhase(event transactionPhaseEvent) error {
	if transactionPhaseHook == nil {
		return nil
	}
	return transactionPhaseHook(event)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tplaiter-oss-register:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, args, stdout)
}

func runWithContext(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("tplaiter-oss-register", flag.ContinueOnError)
	root := flags.String("root", "", "absolute install root for the trust material (required)")
	localProviders := flags.String("local-providers", "", "bounded operator-selected local preview host specs (requires explicit project contexts)")
	publishers := flags.String("publishers", "", "optional JSON file with a list of trusted template publishers")
	sources := flags.String("source-packages", "", "public initial signed-source package JSON (fresh source-built installation only)")
	local := flags.String("local-sources", "", "explicit public local source JSON; one offline operator-attested source, fresh absent root only")
	bundle := flags.String("local-source-bundle", "", "closed operator source bundle: one native and 1..15 inert content sources, fresh absent root only")
	projects := flags.String("project-contexts", "", "finite operator-approved project context JSON")
	approvers := flags.String("approvers", "", "public explicit approver JSON, fresh signed-source registration only")
	executionEvidence := flags.String("execution-evidence", "", "public digest/base64 chunk JSON, fresh registration only")
	rotate := flags.Bool("rotate", false, "discard an existing installation (and its trust store) and generate a new one")
	output := flags.String("output", "", "write the linker pins to this file instead of stdout")
	transaction := flags.Bool("transaction", false, "run the complete serialized source install")
	destination := flags.String("destination", "", "final executable destination for --transaction")
	version := flags.String("version", "dev", "version linker value for --transaction")
	registrationPath := flags.String("registration-path", "", "existing registration path for an explicit-pin --transaction")
	registrationSHA256 := flags.String("registration-sha256", "", "existing registration digest for an explicit-pin --transaction")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *root == "" {
		return errors.New("--root is required")
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	if strings.ContainsAny(absRoot, linkerUnsafe) {
		return fmt.Errorf("install root %q contains characters that cannot be passed to the linker", absRoot)
	}
	if *transaction && *destination == "" {
		return errors.New("--transaction requires --destination")
	}
	if *transaction && *output != "" {
		return errors.New("--transaction does not accept --output; pins use a private transaction path")
	}
	explicitPins := *registrationPath != "" || *registrationSHA256 != ""
	if explicitPins && (*registrationPath == "" || *registrationSHA256 == "") {
		return errors.New("set both --registration-path and --registration-sha256, or neither")
	}
	if *transaction && explicitPins && (*local != "" || *bundle != "" || *publishers != "" || *sources != "" || *projects != "" || *localProviders != "" || *approvers != "" || *executionEvidence != "" || *rotate) {
		return errors.New("explicit transaction pins conflict with trust enrollment inputs or rotation")
	}
	if *local != "" && (*sources != "" || *publishers != "" || *rotate || *projects == "") {
		return errors.New("--local-sources requires --project-contexts and forbids --publishers, --source-packages and --rotate")
	}
	if *bundle != "" && (*local != "" || *sources != "" || *publishers != "" || *rotate || *projects == "") {
		return errors.New("--local-source-bundle requires --project-contexts and forbids --local-sources, --publishers, --source-packages and --rotate")
	}
	options := ossinstall.Options{Root: absRoot, Rotate: *rotate}
	if *bundle != "" {
		raw, err := readPublicInput(*bundle, ossinstall.MaxLocalSourceInputBytes)
		if err != nil {
			return err
		}
		options.LocalSourceBundle, err = ossinstall.DecodeLocalSourceBundle(raw)
		if err != nil {
			return err
		}
	}
	if *local != "" {
		raw, err := readPublicInput(*local, ossinstall.MaxLocalSourceInputBytes)
		if err != nil {
			return err
		}
		options.LocalSources, err = ossinstall.DecodeLocalSources(raw)
		if err != nil {
			return err
		}
	}
	if *publishers != "" {
		raw, err := readPublicInput(*publishers, 1<<20)
		if err != nil {
			return fmt.Errorf("read publishers: %w", err)
		}
		if err := canonicaljson.DecodeStrict(raw, &options.Publishers); err != nil {
			return fmt.Errorf("decode publishers: %w", err)
		}
	}
	if *sources != "" {
		raw, err := readPublicInput(*sources, ossinstall.MaxSourcePackageInputBytes)
		if err != nil {
			return err
		}
		options.SourcePackages, err = ossinstall.DecodeSourcePackages(raw)
		if err != nil {
			return err
		}
	}
	if *projects != "" {
		raw, err := readPublicInput(*projects, ossinstall.MaxProjectContextInputBytes)
		if err != nil {
			return err
		}
		options.ProjectContexts, err = ossinstall.DecodeProjectContexts(raw)
		if err != nil {
			return err
		}
	}
	if *localProviders != "" {
		if *projects == "" || *rotate {
			return errors.New("--local-providers requires --project-contexts and forbids rotation")
		}
		raw, e := readPublicInput(*localProviders, 131072)
		if e != nil {
			return e
		}
		options.LocalProviders, e = ossinstall.DecodeLocalProviders(raw)
		if e != nil {
			return e
		}
	}
	for _, item := range []struct {
		path   string
		target any
		limit  int64
	}{{*approvers, &options.Approvers, 1 << 20}, {*executionEvidence, &options.ExecutionEvidence, 768 << 20}} {
		if item.path != "" {
			raw, e := readPublicInput(item.path, item.limit)
			if e != nil {
				return e
			}
			if e = canonicaljson.DecodeStrict(raw, item.target); e != nil {
				return e
			}
		}
	}
	if *transaction {
		return runTransaction(ctx, options, *destination, *version, *registrationPath, *registrationSHA256, stdout)
	}
	result, err := ossinstall.GenerateWithContext(ctx, options)
	if err != nil {
		return err
	}
	// The pins travel through make and -X linker flags, which split on
	// whitespace; reject such paths instead of producing a broken binary.
	if strings.ContainsAny(result.RegistrationPath, linkerUnsafe) {
		return fmt.Errorf("install root %q contains characters that cannot be passed to the linker", result.Root)
	}
	pins := fmt.Sprintf("REGISTRATION_PATH=%s\nREGISTRATION_SHA256=%s\n", result.RegistrationPath, result.RegistrationSHA256)
	state := "generated"
	if result.Reused {
		state = "reused"
	}
	fmt.Fprintf(os.Stderr, "tplaiter-oss-register: %s OSS installation %s at %s\n", state, result.InstallationID, result.Root)
	if *output == "" {
		_, err = io.WriteString(stdout, pins)
		if err != nil {
			return &ossinstall.PublicationCommittedError{Cause: err}
		}
		return nil
	}
	if err := os.WriteFile(*output, []byte(pins), 0o600); err != nil {
		return &ossinstall.PublicationCommittedError{Cause: err}
	}
	return nil
}

func runTransaction(ctx context.Context, options ossinstall.Options, destination, version, registrationPath, registrationSHA256 string, stdout io.Writer) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	if filepath.Clean(destination) != destination {
		return errors.New("destination must be a clean absolute path")
	}
	root := options.Root
	if registrationPath != "" {
		// Explicit pins have no generated trust-root transaction. They still
		// coordinate the final destination, but do not create or inspect a root.
		root = ""
	}
	locks, err := ossinstall.AcquireInstallLocks(ctx, root, destination)
	if err != nil {
		return err
	}
	state := transactionPrePublication
	defer func() {
		if closeErr := locks.Close(); err == nil && closeErr != nil {
			err = classifyTransactionError(closeErr, state)
		}
	}()
	if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionLocked, Destination: destination}); err != nil {
		return err
	}

	transactionDir, err := os.MkdirTemp("", "tplaiter-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(transactionDir)

	if registrationPath == "" {
		result, generateErr := ossinstall.GenerateWithContext(ctx, options)
		if generateErr != nil {
			return generateErr
		}
		registrationPath = result.RegistrationPath
		registrationSHA256 = result.RegistrationSHA256
		installState := "generated"
		if result.Reused {
			installState = "reused"
		}
		fmt.Fprintf(os.Stderr, "tplaiter-oss-register: %s OSS installation %s at %s\n", installState, result.InstallationID, result.Root)
		if !result.Reused {
			state = transactionGeneratedPublicationCommitted
		} else {
			state = transactionReusedRoot
		}
		if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionGenerated, Destination: destination, RegistrationPath: registrationPath, RegistrationSHA256: registrationSHA256}); err != nil {
			return classifyTransactionError(err, state)
		}
	} else {
		state = transactionExplicitPins
		if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionGenerated, Destination: destination, RegistrationPath: registrationPath, RegistrationSHA256: registrationSHA256}); err != nil {
			return err
		}
	}
	if strings.ContainsAny(registrationPath, linkerUnsafe) || strings.ContainsAny(registrationSHA256, linkerUnsafe) {
		return classifyTransactionError(errors.New("transaction linker pins contain unsafe characters"), state)
	}
	pinsPath := filepath.Join(transactionDir, "registration.pins")
	pins := fmt.Sprintf("REGISTRATION_PATH=%s\nREGISTRATION_SHA256=%s\n", registrationPath, registrationSHA256)
	if err := os.WriteFile(pinsPath, []byte(pins), 0o600); err != nil {
		return classifyTransactionError(err, state)
	}

	buildOutput := filepath.Join(transactionDir, "tplaiter")
	ldflags := strings.Join([]string{
		"-s", "-w",
		"-X", "github.com/tplAIter/tplaiter/internal/cmd.version=" + version,
		"-X", "github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationPath=" + registrationPath,
		"-X", "github.com/tplAIter/tplaiter/internal/cmd.installedRegistrationSHA256=" + registrationSHA256,
	}, " ")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", ldflags, "-o", buildOutput, ".")
	build.Dir, err = os.Getwd()
	if err != nil {
		return classifyTransactionError(err, state)
	}
	build.Env = replaceEnv(os.Environ(), "CGO_ENABLED", "0")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return classifyTransactionError(fmt.Errorf("build transaction binary: %w", err), state)
	}
	if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionBuilt, BuildOutput: buildOutput, Destination: destination, RegistrationPath: registrationPath, RegistrationSHA256: registrationSHA256}); err != nil {
		return classifyTransactionError(err, state)
	}
	if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionBeforePublication, BuildOutput: buildOutput, Destination: destination, RegistrationPath: registrationPath, RegistrationSHA256: registrationSHA256}); err != nil {
		return classifyTransactionError(err, state)
	}
	if err := ossinstall.ValidateInstallDestination(destination); err != nil {
		return classifyTransactionError(err, state)
	}
	publication, publishErr := ossinstall.PublishExecutable(buildOutput, destination)
	if publication.Committed {
		state = transactionBinaryPublished
	}
	if publishErr != nil {
		return classifyTransactionError(fmt.Errorf("publish transaction binary: %w", publishErr), state)
	}
	if err := observeTransactionPhase(transactionPhaseEvent{Phase: transactionPublished, BuildOutput: buildOutput, Destination: destination, RegistrationPath: registrationPath, RegistrationSHA256: registrationSHA256}); err != nil {
		return classifyTransactionError(err, state)
	}
	if _, err = io.WriteString(stdout, pins); err != nil {
		return classifyTransactionError(err, state)
	}
	return nil
}

type transactionState uint8

const (
	transactionPrePublication transactionState = iota
	transactionReusedRoot
	transactionExplicitPins
	transactionGeneratedPublicationCommitted
	transactionBinaryPublished
)

func classifyTransactionError(err error, state transactionState) error {
	if err == nil {
		return nil
	}
	if state == transactionGeneratedPublicationCommitted || state == transactionBinaryPublished {
		if errors.Is(err, ossinstall.ErrPublicationCommitted) {
			return err
		}
		return &ossinstall.PublicationCommittedError{Cause: err}
	}
	return err
}

func replaceEnv(env []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
}

// linkerUnsafe lists characters that cannot travel through make variables and
// -X linker flags intact (they split on whitespace and are shell-quoted).
const linkerUnsafe = " \t\r\n'\"$`\\"

// Inputs are public JSON documents; no credential/profile file is consumed.
func readPublicInput(path string, limit int64) ([]byte, error) {
	f, err := openPublicInput(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("public input is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("public input size limit")
	}
	return raw, nil
}
