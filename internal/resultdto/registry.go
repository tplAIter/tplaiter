package resultdto

import (
	"fmt"
	"sort"
)

// Operation is the stable identity of what produced a result. Every
// operation has exactly one kind and one project scope in the registry.
type Operation string

// Lifecycle operations. Their CLI/MCP backends land with the lifecycle work
// packages; the identities are fixed now so every producer shares them.
const (
	OperationProjectNew Operation = "project.new"
	// New recovery is a first-class lifecycle surface. Status describes the
	// global journal while continue/abort act on one durable transaction.
	OperationNewStatus   Operation = "new.status"
	OperationNewContinue Operation = "new.continue"
	OperationNewAbort    Operation = "new.abort"
	OperationUpdatePlan  Operation = "update.plan"
	OperationUpdateApply Operation = "update.apply"
	// OperationUpdateCheck is `update --check`: a local conflict-marker scan.
	OperationUpdateCheck       Operation = "update.check"
	OperationUpdateStatus      Operation = "update.status"
	OperationUpdateContinue    Operation = "update.continue"
	OperationUpdateAbort       Operation = "update.abort"
	OperationSettingsShow      Operation = "settings.show"
	OperationSettingsSet       Operation = "settings.set"
	OperationSettingsReanswer  Operation = "settings.reanswer"
	OperationProjectCheck      Operation = "project.check"
	OperationProjectVerify     Operation = "project.verify"
	OperationProjectDiff       Operation = "project.diff"
	OperationProjectLink       Operation = "project.link"
	OperationProjectAdopt      Operation = "project.adopt"
	OperationProjectRecopy     Operation = "project.recopy"
	OperationProjectRebaseline Operation = "project.rebaseline"
	OperationDepsVerify        Operation = "deps.verify"
)

// Catalog, repository, project and authoring operations behind the existing
// CLI commands and MCP tools.
const (
	OperationRepoAdd             Operation = "repo.add"
	OperationRepoList            Operation = "repo.list"
	OperationRepoUpdate          Operation = "repo.update"
	OperationRepoRemove          Operation = "repo.remove"
	OperationTemplateList        Operation = "template.list"
	OperationTemplateDiscover    Operation = "template.discover"
	OperationTemplateShow        Operation = "template.show"
	OperationTemplateLint        Operation = "template.lint"
	OperationTemplateInit        Operation = "template.init"
	OperationTrustInspect        Operation = "trust.inspect"
	OperationProjectsList        Operation = "projects.list"
	OperationProjectStats        Operation = "project.stats"
	OperationProjectRun          Operation = "project.run"
	OperationDoctorCheck         Operation = "doctor.check"
	OperationAIGen               Operation = "ai.gen"
	OperationGenRun              Operation = "gen.run"
	OperationGenBatch            Operation = "gen.batch"
	OperationGenList             Operation = "gen.list"
	OperationWorkspaceAddService Operation = "workspace.add-service"
	OperationEnvSetup            Operation = "env.setup"
)

// Scope states whether an operation acts on a project.
type Scope string

const (
	// ScopeProject operations act on one project: a successful result
	// (ok/changes/conflicted) carries a non-null project.
	ScopeProject Scope = "project"
	// ScopeGlobal operations never carry a project (project is null).
	ScopeGlobal Scope = "global"
	// ScopeOptional operations may or may not identify a project (for
	// example a dry run that has not created one yet, or doctor outside a
	// project).
	ScopeOptional Scope = "optional"
)

type operationSpec struct {
	kind  string
	scope Scope
}

// operationRegistry is the protocol registry. Keeping it explicit prevents
// a producer from publishing a plausible but semantically wrong kind.
var operationRegistry = map[Operation]operationSpec{
	OperationProjectNew:        {"ProjectNew", ScopeOptional},
	OperationNewStatus:         {"NewStatus", ScopeGlobal},
	OperationNewContinue:       {"NewContinue", ScopeOptional},
	OperationNewAbort:          {"NewAbort", ScopeOptional},
	OperationUpdatePlan:        {"UpdatePlan", ScopeProject},
	OperationUpdateApply:       {"UpdateApply", ScopeProject},
	OperationUpdateCheck:       {"UpdateCheck", ScopeOptional},
	OperationUpdateStatus:      {"UpdateStatus", ScopeProject},
	OperationUpdateContinue:    {"UpdateContinue", ScopeProject},
	OperationUpdateAbort:       {"UpdateAbort", ScopeProject},
	OperationSettingsShow:      {"SettingsShow", ScopeProject},
	OperationSettingsSet:       {"SettingsSet", ScopeProject},
	OperationSettingsReanswer:  {"SettingsReanswer", ScopeProject},
	OperationProjectCheck:      {"ProjectCheck", ScopeProject},
	OperationProjectVerify:     {"ProjectVerify", ScopeProject},
	OperationProjectDiff:       {"ProjectDiff", ScopeProject},
	OperationProjectLink:       {"ProjectLink", ScopeProject},
	OperationProjectAdopt:      {"ProjectAdopt", ScopeProject},
	OperationProjectRecopy:     {"ProjectRecopy", ScopeProject},
	OperationProjectRebaseline: {"ProjectRebaseline", ScopeProject},
	OperationDepsVerify:        {"DepsVerify", ScopeProject},

	OperationRepoAdd:             {"RepoAdd", ScopeGlobal},
	OperationRepoList:            {"RepoList", ScopeGlobal},
	OperationRepoUpdate:          {"RepoUpdate", ScopeGlobal},
	OperationRepoRemove:          {"RepoRemove", ScopeGlobal},
	OperationTemplateList:        {"TemplateList", ScopeGlobal},
	OperationTemplateDiscover:    {"TemplateDiscover", ScopeGlobal},
	OperationTemplateShow:        {"TemplateShow", ScopeGlobal},
	OperationTemplateLint:        {"TemplateLint", ScopeGlobal},
	OperationTemplateInit:        {"TemplateInit", ScopeGlobal},
	OperationTrustInspect:        {"TrustInspect", ScopeGlobal},
	OperationProjectsList:        {"ProjectsList", ScopeGlobal},
	OperationProjectStats:        {"ProjectStats", ScopeProject},
	OperationProjectRun:          {"ProjectRun", ScopeProject},
	OperationDoctorCheck:         {"DoctorCheck", ScopeOptional},
	OperationAIGen:               {"AIGen", ScopeProject},
	OperationGenRun:              {"GenRun", ScopeProject},
	OperationGenBatch:            {"GenBatch", ScopeProject},
	OperationGenList:             {"GenList", ScopeProject},
	OperationWorkspaceAddService: {"WorkspaceAddService", ScopeProject},
	OperationEnvSetup:            {"EnvSetup", ScopeProject},
}

// KindForOperation returns the registered kind of operation.
func KindForOperation(operation Operation) (string, error) {
	spec, ok := operationRegistry[operation]
	if !ok {
		return "", fmt.Errorf("unsupported result operation %q", operation)
	}
	return spec.kind, nil
}

// ScopeForOperation returns the registered project scope of operation.
func ScopeForOperation(operation Operation) (Scope, error) {
	spec, ok := operationRegistry[operation]
	if !ok {
		return "", fmt.Errorf("unsupported result operation %q", operation)
	}
	return spec.scope, nil
}

// ValidateOperationKind checks that kind is the registered kind of operation.
func ValidateOperationKind(operation Operation, kind string) error {
	want, err := KindForOperation(operation)
	if err != nil {
		return err
	}
	if kind != want {
		return fmt.Errorf("result kind %q does not match operation %q (want %q)", kind, operation, want)
	}
	return nil
}

// Operations returns every registered operation in sorted order.
func Operations() []Operation {
	out := make([]Operation, 0, len(operationRegistry))
	for op := range operationRegistry {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func validOperation(operation Operation) bool {
	_, ok := operationRegistry[operation]
	return ok
}
