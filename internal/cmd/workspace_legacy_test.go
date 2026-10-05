package cmd

// Historical unsigned fixture helpers are test-only and grant no production path.
import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/mod/modfile"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/project"
	"github.com/tplAIter/tplaiter/internal/settings"
	"github.com/tplAIter/tplaiter/internal/state"
)

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
	if err := os.WriteFile(workPath, out, 0o644); err != nil {
		return fmt.Errorf("writing go.work: %w", err)
	}
	return nil
}
