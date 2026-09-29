package cmd

import "github.com/spf13/cobra"

// Pre-run classification.
//
// The root PersistentPreRunE ([rootPreRun]) decides, before any command body
// runs, whether the legacy process hooks (first-run initialization of the
// process home, the update suggestion check and project registry sync) may
// run. That decision is declared by each command through a cobra annotation
// instead of a name-based switch in root.go, so a work package that adds a
// command only annotates the command in its own file.
//
// A command without an annotation inherits the class of its nearest annotated
// ancestor (the root itself is never annotated); a command with no annotated
// ancestor is [prerunStateful].
const (
	// prerunClassAnnotation holds the command's [prerunClass].
	prerunClassAnnotation = "tplaiter.dev/prerun-class"
	// prerunNoArgsClassAnnotation optionally overrides the class when the
	// command is invoked without positional arguments (for example, bare
	// `run` lists commands while `run <name>` executes one).
	prerunNoArgsClassAnnotation = "tplaiter.dev/prerun-class-no-args"
)

// prerunClass is the pre-run class of a command.
type prerunClass string

const (
	// prerunStateful commands run the legacy hooks: they may create the
	// process home, check for updates and synchronize the project registry.
	prerunStateful prerunClass = "stateful"
	// prerunReadonly commands only describe state. No hook runs, so the
	// command writes nothing on its own behalf (zero-write proofs rely on it).
	prerunReadonly prerunClass = "readonly"
	// prerunTrustOwned commands own their complete per-invocation composition
	// (trust runtime selection, sealed migration plans). No hook runs before
	// the command has selected its fixed material.
	prerunTrustOwned prerunClass = "trust-owned"
	// prerunLegacyAction commands could execute manifest-derived input for
	// which this binary has no fixed, launcher-selected execution material.
	// They are refused with TRUST_ACTION_UNAVAILABLE before any hook runs.
	prerunLegacyAction prerunClass = "legacy-action"
)

// prerunAnnotations returns the cobra Annotations that declare class. An
// optional second class applies when the command runs without positional
// arguments. Constructors use it as `Annotations: prerunAnnotations(...)`.
func prerunAnnotations(class prerunClass, noArgs ...prerunClass) map[string]string {
	annotations := map[string]string{prerunClassAnnotation: string(class)}
	if len(noArgs) > 0 {
		annotations[prerunNoArgsClassAnnotation] = string(noArgs[0])
	}
	return annotations
}

// classifyPrerun returns the pre-run class of cmd invoked with args.
func classifyPrerun(cmd *cobra.Command, args []string) prerunClass {
	if cmd == nil {
		return prerunStateful
	}
	if len(args) == 0 {
		if class, ok := cmd.Annotations[prerunNoArgsClassAnnotation]; ok {
			return prerunClass(class)
		}
	}
	for c := cmd; c != nil && c.HasParent(); c = c.Parent() {
		if class, ok := c.Annotations[prerunClassAnnotation]; ok {
			return prerunClass(class)
		}
	}
	return prerunStateful
}
