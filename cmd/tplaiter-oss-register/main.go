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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tplAIter/tplaiter/internal/canonicaljson"
	"github.com/tplAIter/tplaiter/internal/ossinstall"
)

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
	projects := flags.String("project-contexts", "", "finite operator-approved project context JSON")
	approvers := flags.String("approvers", "", "public explicit approver JSON, fresh signed-source registration only")
	executionEvidence := flags.String("execution-evidence", "", "public digest/base64 chunk JSON, fresh registration only")
	rotate := flags.Bool("rotate", false, "discard an existing installation (and its trust store) and generate a new one")
	output := flags.String("output", "", "write the linker pins to this file instead of stdout")
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
	if *local != "" && (*sources != "" || *publishers != "" || *rotate || *projects == "") {
		return errors.New("--local-sources requires --project-contexts and forbids --publishers, --source-packages and --rotate")
	}
	options := ossinstall.Options{Root: absRoot, Rotate: *rotate}
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
