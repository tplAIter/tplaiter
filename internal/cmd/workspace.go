package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
	"golang.org/x/term"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/newcmd"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/survey"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// forcedWorkflowGroup — settings group name that `workspace add-service`
// best-effort forces to true when present in the service template manifest
// (see allSets/serviceTemplateHasGroup below and isUnknownForcedGroupError).
const forcedWorkflowGroup = "workflow"

func init() {
	registerCommand(newWorkspaceCmd)
}

// newWorkspaceCmd — `tplater workspace`, grouping CLI functions tied to
// kind=workspace projects (see docs/workspace-temporal.md in the go-template
// repository; the spec lives there, not in tplater; §2.3): this is tplater
// logic, not a manifest command.
func newWorkspaceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "workspace",
		Short: "Operations on a monorepo project (kind=workspace)",
		Long:  "CLI functions tied to monorepo structure (go.work + Temporal), not a specific template manifest.",
	}
	c.AddCommand(newWorkspaceAddServiceCmd())
	return c
}

// newWorkspaceAddServiceCmd creates `tplater workspace add-service <name>`
// (see docs/workspace-temporal.md in the go-template repository): it renders a
// service action using a `service` template from the same repository as the
// current workspace into services/<slug>, best-effort forces workflow=true
// (a service is a Temporal activity; missing group means a warning), and adds
// the directory to go.work.
func newWorkspaceAddServiceCmd() *cobra.Command {
	var (
		module      string
		sets        []string
		answers     string
		defaults    bool
		noHooks     bool
		noDepsCheck bool
		envSetup    bool
		noEnvSetup  bool
		yes         bool
		port        int
	)

	c := &cobra.Command{
		Use:   "add-service <name>",
		Short: "Add a service action to the current workspace project",
		Long: "Deploys a service template (type=service from the same repository as the current " +
			"workspace) into services/<slug>, best-effort forces workflow=true setting (a service is a " +
			"set of Temporal activities, see docs/workspace-temporal.md in the go-template repository), and " +
			"adds the directory to go.work. Runs from the workspace root (or any nested subdirectory, including " +
			"existing services/<slug>).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			home, _, err := state.EnsureHome()
			if err != nil {
				return err
			}

			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			root, proj, tpl, err := findWorkspaceRoot(home, cwd)
			if err != nil {
				if errors.Is(err, project.ErrNotInProject) {
					return fmt.Errorf("workspace add-service: current directory is not a tplater project (workspace root needed, %s): %w", project.MarkerRelPath, err)
				}
				return fmt.Errorf("workspace add-service: reading current project manifest: %w", err)
			}
			if !slices.Contains(tpl.Metadata.Labels["type"], "workspace") {
				return fmt.Errorf("workspace add-service: project %s (template %s) is not a workspace (labels.type=%v) — command applies only to kind=workspace projects; if you are inside a nested service (services/<slug>), go up to the workspace root", proj.Project.Slug, tpl.Metadata.Name, tpl.Metadata.Labels["type"])
			}

			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			svcName, err := resolveServiceTemplateName(mgr, proj.Template.Repo)
			if err != nil {
				return err
			}

			slug, err := newcmd.Slugify(args[0])
			if err != nil {
				return fmt.Errorf("workspace add-service: %w", err)
			}
			targetDir := filepath.Join(root, "services", slug)

			mod := module
			if mod == "" {
				mod = proj.Project.Module + "/services/" + slug
			}

			svcRef := proj.Template.Repo + "/" + svcName
			pal := ui.Default()

			// workflow=true is forced best-effort (docs/workspace-temporal.md in the
			// go-template repository): a workspace service action must be a Temporal
			// worker. Service templates need not declare workflow; when absent there is
			// nothing to force, so warn and continue without the forced value. When the
			// group exists, a user --set cannot disable the force: append the forced
			// value last, overriding earlier --set entries (survey.AskFlow uses the
			// last group occurrence).
			allSets := slices.Clone(sets)
			hasWorkflow, err := serviceTemplateHasGroup(cmd, mgr, svcRef, forcedWorkflowGroup)
			if err != nil {
				return fmt.Errorf("workspace add-service: checking service template settings %s: %w", svcRef, err)
			}
			if hasWorkflow {
				allSets = append(allSets, forcedWorkflowGroup+"=true")
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), ui.WarnLine(pal, fmt.Sprintf(
					"service template %s does not contain setting %q — service is created WITHOUT forced "+
						"%s=true (a service in workspace must normally be a Temporal worker, "+
						"docs/workspace-temporal.md in go-template repository; add a toggle group "+
						"%s to template.manifest.yaml of the service template if applicable)",
					svcRef, forcedWorkflowGroup, forcedWorkflowGroup, forcedWorkflowGroup,
				)))
			}

			interactive := term.IsTerminal(int(os.Stdin.Fd()))

			opts := newcmd.Options{
				Ref:         svcRef,
				ProjectName: args[0],
				Dir:         targetDir,
				Module:      mod,
				System:      proj.Project.System,
				Domain:      proj.Project.Domain,
				Sets:        allSets,
				AnswersFile: answers,
				Defaults:    defaults,
				NoHooks:     noHooks,
				NoDepsCheck: noDepsCheck,
				EnvSetup:    envSetupTriState(cmd, envSetup, noEnvSetup),
				Yes:         yes,
				Port:        port,
				Interactive: interactive,
				CLIVersion:  resolveVersion(),
			}
			d := newcmd.Deps{
				Manager:  mgr,
				Runner:   newRunner,
				Home:     home,
				Prompter: survey.HuhPrompter{In: cmd.InOrStdin(), Out: cmd.OutOrStdout()},
				Confirm:  confirmFunc(cmd, interactive),
				Out:      cmd.OutOrStdout(),
				Err:      cmd.ErrOrStderr(),
				Palette:  pal,
			}
			if err := newcmd.Run(cmd.Context(), opts, d); err != nil {
				// Defensive fallback: serviceTemplateHasGroup already checked for
				// forcedWorkflowGroup above, so this should be unreachable. However,
				// newcmd.Run checks out the manifest independently; if it diverges due to
				// a race or resolver error, return the same clear explanation instead of
				// the raw settings.ParseSet error.
				if isUnknownForcedGroupError(err, forcedWorkflowGroup) {
					return fmt.Errorf(
						"workspace add-service: service template %s/%s does not contain setting %q "+
							"(this command tries to force %s=true — a service in workspace must normally "+
							"be a Temporal worker, see docs/workspace-temporal.md in go-template repository; "+
							"the value is provided by tplater, not the user — "+
							"add a toggle group %s to template.manifest.yaml of the service template): %w",
						proj.Template.Repo, svcName, forcedWorkflowGroup, forcedWorkflowGroup, forcedWorkflowGroup, err,
					)
				}
				return err
			}

			if err := addWorkspaceUse(root, "./services/"+slug); err != nil {
				return fmt.Errorf("workspace add-service: service created in %s, but registration in go.work failed (add manually: use ./services/%s): %w", targetDir, slug, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\nService action %s registered in go.work (./services/%s). Run `tplater run sync` at the workspace root.\n", slug, slug)
			return nil
		},
	}

	f := c.Flags()
	f.StringVar(&module, "module", "", "service go-module (default <workspace module>/services/<slug>)")
	f.StringArrayVar(&sets, "set", nil, "setting value group=value (repeatable flag); workflow=true is forced separately")
	f.StringVar(&answers, "answers", "", "YAML answers file (group: value)")
	f.BoolVar(&defaults, "defaults", false, "do not prompt — use defaults (+ --set/--answers)")
	f.BoolVar(&noHooks, "no-hooks", false, "skip hooks.postCreate")
	f.BoolVar(&noDepsCheck, "no-deps-check", false, "skip environment tools check")
	f.BoolVar(&envSetup, "env-setup", false, "run env setup after creation without prompting")
	f.BoolVar(&noEnvSetup, "no-env-setup", false, "do not offer env setup after creation")
	f.BoolVar(&yes, "yes", false, "auto-confirm (tool installation and env setup)")
	f.IntVar(&port, "port", 0, "service port (.Runtime.Port)")
	return c
}

// findWorkspaceRoot finds the nearest tplater project while walking upward from
// startDir. If it is not kind=workspace, it continues from the parent: a nested
// project such as services/<slug> (registered by this command with its own
// .tplaiter/project.yaml) may otherwise hide the workspace root from
// project.FindRoot, which prefers the nearest marker. If no real workspace is
// found above, it returns the original non-workspace project unchanged, keeping
// the previous behavior and error for invocation outside any workspace.
func findWorkspaceRoot(home, startDir string) (root string, proj *manifest.Project, tpl *manifest.Template, err error) {
	root, proj, err = project.FindRoot(startDir)
	if err != nil {
		return "", nil, nil, err
	}
	tpl, _, err = project.LoadManifestForProject(root, proj, home)
	if err != nil {
		return "", nil, nil, err
	}
	if slices.Contains(tpl.Metadata.Labels["type"], "workspace") {
		return root, proj, tpl, nil
	}

	if parent := filepath.Dir(root); parent != root {
		if wsRoot, wsProj, wsErr := project.FindRoot(parent); wsErr == nil {
			if wsTpl, _, lerr := project.LoadManifestForProject(wsRoot, wsProj, home); lerr == nil &&
				slices.Contains(wsTpl.Metadata.Labels["type"], "workspace") {
				return wsRoot, wsProj, wsTpl, nil
			}
		}
	}
	return root, proj, tpl, nil
}

// isUnknownForcedGroupError reports whether an error (settings.ParseSet directly
// in [serviceTemplateHasGroup] or a failed newcmd.Run) is caused by group being
// absent from the service template manifest. It matches the typed
// [settings.UnknownSetGroupError] so that other "unknown group" messages (condition
// evaluation, settings edit, conditional paths) do not trigger the fallback.
// This distinguishes a failed forced --set (added by tplaiter) from an error in
// the user's --set/--answers for the same command.
func isUnknownForcedGroupError(err error, group string) bool {
	var ug *settings.UnknownSetGroupError
	return errors.As(err, &ug) && ug.Group == group
}

// serviceTemplateHasGroup reports whether the service template manifest at ref
// (repoAlias/templateName, the same format passed to newcmd.Options.Ref)
// declares the settings group named by group. The caller (RunE in
// newWorkspaceAddServiceCmd) uses this to decide whether to force
// --set workflow=true: service templates need not declare the group, and its
// absence must not fail the command.
//
// Manifest checkout and parsing follow runTemplateShow (template.go):
// ResolveRef → Checkout → read and parse template.manifest.yaml. Check group
// presence through settings.ParseSet rather than manually walking tpl.Settings,
// so nested groups (Option.Settings) use the same logic as real settings
// installation in newcmd.Run; otherwise the check could diverge from actual
// behavior, such as a group visible only under a selected option.
func serviceTemplateHasGroup(cmd *cobra.Command, mgr *repo.Manager, ref, group string) (bool, error) {
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		return false, fmt.Errorf("resolving template %s: %w", ref, err)
	}
	fsys, cleanup, err := mgr.Checkout(cmd.Context(), resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return false, fmt.Errorf("checking out template %s: %w", ref, err)
	}
	defer func() { _ = cleanup() }()

	data, err := fs.ReadFile(fsys, templateManifestFileName)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return false, fmt.Errorf("parsing manifest: %w", err)
	}

	if _, _, err := settings.ParseSet(tpl, group+"=true"); err != nil {
		if isUnknownForcedGroupError(err, group) {
			return false, nil
		}
		// The group exists but is incompatible with value "true" (for example,
		// select/int rather than toggle). This is a real conflict with the
		// manifest, not a missing group, and best-effort logic must not hide it.
		return false, fmt.Errorf("group %q declared in template manifest but incompatible with forced value true: %w", group, err)
	}
	return true, nil
}

// resolveServiceTemplateName finds exactly one template with label type=service
// in repository repoAlias (the index entry), the service-action template for
// `workspace add-service`. Zero or multiple matches are errors listing the
// findings; a future command version may resolve ambiguity with explicit --ref.
func resolveServiceTemplateName(mgr interface {
	Templates() (map[string][]state.TemplateEntry, error)
}, repoAlias string,
) (string, error) {
	idx, err := mgr.Templates()
	if err != nil {
		return "", fmt.Errorf("resolving service template: %w", err)
	}
	entries := idx[repoAlias]
	var matches []string
	for _, e := range entries {
		if slices.Contains(e.LabelsFlat["type"], "service") {
			matches = append(matches, e.Name)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("repository %s has no template with labels.type=service (run: tplater template list -l type=service)", repoAlias)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("repository %s has multiple templates with labels.type=service: %v — flag-based disambiguation not yet implemented", repoAlias, matches)
	}
}

// addWorkspaceUse adds a use directive for diskPath to root's go.work when it
// is not already present (idempotent: repeating add-service does not duplicate
// an existing path).
func addWorkspaceUse(root, diskPath string) error {
	workPath := filepath.Join(root, "go.work")
	data, err := os.ReadFile(workPath)
	if err != nil {
		return fmt.Errorf("reading go.work: %w", err)
	}
	wf, err := modfile.ParseWork(workPath, data, nil)
	if err != nil {
		return fmt.Errorf("parsing go.work: %w", err)
	}
	// filepath.Clean normalizes "./services/<slug>" (what we pass) and equivalent
	// manual directives such as "use services/<slug>" (valid go.work syntax) to
	// one form; otherwise AddUse would duplicate a path manually written without
	// "./".
	cleanDiskPath := filepath.Clean(diskPath)
	for _, u := range wf.Use {
		if filepath.Clean(u.Path) == cleanDiskPath {
			return nil // already registered
		}
	}
	if err := wf.AddUse(diskPath, ""); err != nil {
		return fmt.Errorf("adding use %s: %w", diskPath, err)
	}
	wf.Cleanup()
	out := modfile.Format(wf.Syntax)
	// Leave the neighboring go.work.sum alone; `go work sync`/`tplater run sync`
	// will regenerate it normally after the new module is registered.
	if err := os.WriteFile(workPath, out, 0o644); err != nil { //nolint:gosec // G306: go.work is not secret; 0644 is intentional (as in manifest.SaveSnapshot).
		return fmt.Errorf("writing go.work: %w", err)
	}
	return nil
}
