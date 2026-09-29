package mcpsrv

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Package mcpsrv builds tplater subcommand argv values from MCP tool arguments.
// The essential security rule is that arguments always pass to a child process
// as separate slice elements: there is no string concatenation or shell
// interpolation (see exec.go). The functions below are pure: they neither touch
// the filesystem nor execute processes, so table-driven unit tests cover them
// easily (argv_test.go).

// sortedSetPairs serializes a group-to-value map into a deterministic sequence
// of ascending-key "--set", "group=value" pairs. Determinism matters both for
// tests and reproducible agent calls.
func sortedSetPairs(set map[string]string) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		out = append(out, "--set", k+"="+set[k])
	}
	return out
}

// sortedPositionalPairs serializes a group-to-value map into a deterministic
// sequence of positional "group=value" arguments. `settings set` accepts pairs
// positionally rather than through --set.
func sortedPositionalPairs(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+values[k])
	}
	return out
}

// sortedDynamicFlags serializes generator parameters into dynamic Cobra flags
// such as "--fields", "name:string". Unlike project settings, `tplater gen`
// registers a particular generator's parameters directly as flags (see cmd/gen.go),
// so the generic `--set key=value` is not applicable here.
func sortedDynamicFlags(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		out = append(out, "--"+k, values[k])
	}
	return out
}

func argvRepoAdd(alias, url, branch string) []string {
	argv := []string{"repo", "add", alias, url}
	if branch != "" {
		argv = append(argv, "--branch", branch)
	}
	return argv
}

func argvRepoList() []string { return []string{"repo", "list"} }

func argvTrustInspect() []string { return []string{"trust", "inspect", "--json"} }

func argvRepoUpdate(alias string) []string {
	argv := []string{"repo", "update"}
	if alias != "" {
		argv = append(argv, alias)
	}
	return argv
}

func argvRepoRemove(alias string) []string { return []string{"repo", "remove", alias} }

func argvTemplateList(repo, name string, labels []string) []string {
	argv := []string{"template", "list"}
	if repo != "" {
		argv = append(argv, "--repo", repo)
	}
	if name != "" {
		argv = append(argv, "--name", name)
	}
	for _, l := range labels {
		argv = append(argv, "--label", l)
	}
	return argv
}

func argvTemplateShow(ref string) []string { return []string{"template", "show", ref} }

// argvProjectNew builds argv for `tplater new`. Interaction is always excluded:
// the child process has no stdin (see exec.go), and `new` reports missing required
// groups when --set is incomplete. --defaults forces defaults. dir is NOT used
// here: it becomes the child process working directory (cwd), and the project is
// created as <dir>/<slug> (the uniform dir=cwd rule for all tools; see tools.go).
func argvProjectNew(ref, name string, set map[string]string, defaults, noHooks, noDepsCheck, noEnvSetup, yes bool, port int, extra ...string) []string {
	argv := []string{"new", ref, name}
	argv = append(argv, sortedSetPairs(set)...)
	if defaults {
		argv = append(argv, "--defaults")
	}
	if noHooks {
		argv = append(argv, "--no-hooks")
	}
	if noDepsCheck {
		argv = append(argv, "--no-deps-check")
	}
	if port > 0 {
		argv = append(argv, "--port", strconv.Itoa(port))
	}
	if noEnvSetup {
		argv = append(argv, "--no-env-setup")
	}
	if yes {
		argv = append(argv, "--yes")
	}
	if len(extra) > 0 && extra[0] == "true" {
		argv = append(argv, "--dry-run")
	}
	if len(extra) > 1 && extra[1] != "" {
		argv = append(argv, "--source-input", extra[1])
	}
	return argv
}

func argvRun(command string, args []string) []string {
	argv := []string{"run", command}
	if len(args) > 0 {
		argv = append(argv, "--")
		argv = append(argv, args...)
	}
	return argv
}

func argvSettingsList() []string { return []string{"settings", "list"} }

// argvSettingsSet builds argv for `settings set`. --yes is required: interaction
// is excluded, and without it the command would await confirmation when noninteractive.
func argvSettingsSet(values map[string]string) []string {
	pairs := sortedPositionalPairs(values)
	argv := make([]string, 0, len(pairs)+3)
	argv = append(argv, "settings", "set")
	argv = append(argv, pairs...)
	argv = append(argv, "--yes")
	return argv
}

func argvUpdate(to string, dryRun, check bool, extra ...string) []string {
	argv := []string{"update"}
	if to != "" {
		argv = append(argv, "--to", to)
	}
	if dryRun {
		argv = append(argv, "--dry-run")
	}
	if check {
		argv = append(argv, "--check")
	}
	if len(extra) > 0 && extra[0] != "" {
		argv = append(argv, "--source-input", extra[0])
	}
	return argv
}

// argvStats builds argv for `stats`; the structured-call path adds --json.
func argvStats() []string { return []string{"stats"} }

// argvGen builds argv for `tplater gen <kind> <name>`. params serialize as dynamic
// generator flags: {"fields":"name:string"} becomes `--fields name:string`.
// Cobra registers these flags from manifest params before argv parsing; gen has no
// generic --set flag. noBuild skips the final build gate, retaining created files
// when the toolchain is unavailable.
func argvGen(kind, name string, params map[string]string, noBuild bool) []string {
	pairs := sortedDynamicFlags(params)
	argv := make([]string, 0, len(pairs)+3)
	argv = append(argv, "gen", kind, name)
	argv = append(argv, pairs...)
	if noBuild {
		argv = append(argv, "--no-build")
	}
	return argv
}

// genBatchOperation is the MCP gen_batch input contract. JSON is serialized only
// at the CLI boundary; params values remain strings until `tplater gen batch`
// types them according to the specific generator's manifest.Param.
type genBatchOperation struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params,omitempty"`
}

func argvGenBatch(operations []genBatchOperation, noBuild bool) []string {
	// genBatchOperation contains only strings and map[string]string, so json.Marshal
	// cannot fail for this closed set of types.
	payload, _ := json.Marshal(operations)
	argv := []string{"gen", "batch", "--operations", string(payload)}
	if noBuild {
		argv = append(argv, "--no-build")
	}
	return argv
}

func argvGenList() []string { return []string{"gen", "list"} }

func argvWorkspaceAddService(name, module string, set map[string]string, defaults, noHooks, noDepsCheck bool, port int) []string {
	argv := []string{"workspace", "add-service", name}
	if module != "" {
		argv = append(argv, "--module", module)
	}
	argv = append(argv, sortedSetPairs(set)...)
	if defaults {
		argv = append(argv, "--defaults")
	}
	if noHooks {
		argv = append(argv, "--no-hooks")
	}
	if noDepsCheck {
		argv = append(argv, "--no-deps-check")
	}
	if port > 0 {
		argv = append(argv, "--port", strconv.Itoa(port))
	}
	// MCP does not connect stdin: suppress the env setup prompt and make all
	// confirmations noninteractive.
	return append(argv, "--no-env-setup", "--yes")
}

// argvLintTemplate passes path with --path (the command's native mechanism); the
// caller makes it absolute.
func argvLintTemplate(path, combo string) []string {
	argv := []string{"lint-template"}
	if path != "" {
		argv = append(argv, "--path", path)
	}
	if combo != "" {
		argv = append(argv, "--combo", combo)
	}
	return argv
}

// argvInitTemplate passes dir, if supplied, with --dir (the command's native
// mechanism; it creates the target directory); the caller makes it absolute.
func argvInitTemplate(name, dir string, multi bool) []string {
	argv := []string{"init-template", name}
	if dir != "" {
		argv = append(argv, "--dir", dir)
	}
	if multi {
		argv = append(argv, "--multi")
	}
	return argv
}

func argvProjectsList() []string { return []string{"projects", "list"} }

func argvDoctor() []string { return []string{"doctor"} }

func argvAIGen() []string { return []string{"ai", "gen"} }

// argvEnvSetup always forces yes (interaction is excluded); name is optional
// (the command itself defaults it to "setup").
func argvEnvSetup(name string) []string {
	argv := []string{"env", "setup"}
	if name != "" {
		argv = append(argv, name)
	}
	argv = append(argv, "--yes")
	return argv
}
