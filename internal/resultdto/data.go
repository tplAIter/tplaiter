package resultdto

import (
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// Operation-specific data payloads carried in Result.Data. Each type is the
// source of the `data` schema that the matching MCP tool declares in its
// outputSchema. Fields are additive: a new optional field is a compatible
// change, while removing or retyping one needs a new schema version.

// RepoInfo describes one added template repository.
type RepoInfo struct {
	Alias     string `json:"alias"`
	URL       string `json:"url"`
	Type      string `json:"type"`
	Templates int    `json:"templates"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// RepoListData is the data of repo.list, repo.add and repo.update: the
// repositories the operation reports on.
type RepoListData struct {
	Repositories []RepoInfo `json:"repositories"`
}

// RepoRemoveData is the data of repo.remove.
type RepoRemoveData struct {
	Alias string `json:"alias"`
}

// TemplateSummary is one catalog entry.
type TemplateSummary struct {
	Name        string              `json:"name"`
	Repo        string              `json:"repo"`
	Version     string              `json:"version"`
	Description string              `json:"description,omitempty"`
	Labels      map[string][]string `json:"labels"`
}

// TemplateListData is the data of template.list.
type TemplateListData struct {
	Templates []TemplateSummary `json:"templates"`
}

// TemplateCommand is one manifest command of a template.
type TemplateCommand struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	When        string `json:"when,omitempty"`
}

// TemplateShowData is the data of template.show.
type TemplateShowData struct {
	Repo        string            `json:"repo"`
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName,omitempty"`
	Version     string            `json:"version"`
	Versions    []string          `json:"versions"`
	Description string            `json:"description,omitempty"`
	Maintainers []string          `json:"maintainers"`
	Labels      map[string]any    `json:"labels"`
	Settings    []string          `json:"settings"`
	Commands    []TemplateCommand `json:"commands"`
	Docs        string            `json:"docs,omitempty"`
}

// TemplateLintRow is one template × combination lint outcome.
type TemplateLintRow struct {
	Template string `json:"template"`
	Combo    string `json:"combo"`
	OK       bool   `json:"ok"`
}

// TemplateLintData is the data of template.lint.
type TemplateLintData struct {
	Failed bool              `json:"failed"`
	Rows   []TemplateLintRow `json:"rows"`
}

// TemplateInitData is the data of template.init.
type TemplateInitData struct {
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Multi bool   `json:"multi"`
}

// TrustInspectData is the data of trust.inspect: the verified trust-profile
// binding exactly as `trust inspect --json` reports it.
type TrustInspectData struct {
	Binding map[string]any `json:"binding"`
}

// ProjectEntry is one project registry entry.
type ProjectEntry struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Template   string `json:"template"`
	LastSeenAt string `json:"lastSeenAt,omitempty"`
	Status     string `json:"status"`
}

// ProjectsListData is the data of projects.list.
type ProjectsListData struct {
	Projects []ProjectEntry `json:"projects"`
}

// ProjectStatsData is the data of project.stats: the drift report of
// `stats` (see internal/stats for its fields).
type ProjectStatsData struct {
	Report map[string]any `json:"report"`
}

// DoctorRow is one doctor check.
type DoctorRow struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

// DoctorSection is one group of doctor checks.
type DoctorSection struct {
	Title string      `json:"title"`
	Rows  []DoctorRow `json:"rows"`
}

// DoctorData is the data of doctor.check.
type DoctorData struct {
	Critical bool            `json:"critical"`
	Sections []DoctorSection `json:"sections"`
}

// TemplateRef identifies a template version.
type TemplateRef struct {
	Repo    string `json:"repo"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SettingsShowData is the data of settings.show.
type SettingsShowData struct {
	Template TemplateRef    `json:"template"`
	Settings map[string]any `json:"settings"`
}

// SettingsSetData is the data of settings.set.
type SettingsSetData struct {
	DryRun bool `json:"dryRun"`
}

// GeneratorInfo is one generator of the project template.
type GeneratorInfo struct {
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
	Available   bool   `json:"available"`
	Reason      string `json:"reason,omitempty"`
}

// GenListData is the data of gen.list.
type GenListData struct {
	Generators []GeneratorInfo `json:"generators"`
}

// GenRunData is the data of gen.run and gen.batch.
type GenRunData struct {
	PreparedRequest *trustverify.ExecutionRequest `json:"preparedRequest,omitempty"`
	ProcessReceipt  *execx.ProjectProcessResult   `json:"processReceipt,omitempty"`
	Created         []string                      `json:"created"`
	Edited          []string                      `json:"edited"`
	NoBuild         bool                          `json:"noBuild"`
}

// AIGenData is the data of ai.gen.
type AIGenData struct {
	Written          []string `json:"written"`
	SkippedProtected []string `json:"skippedProtected"`
}

// ProjectRunData is the data of project.run. With a command it reports the
// child's exit status; without one (`run --json`) it lists the manifest
// commands instead.
type ProjectRunData struct {
	PreparedRequest *trustverify.ExecutionRequest `json:"preparedRequest,omitempty"`
	ProcessReceipt  *execx.ProjectProcessResult   `json:"processReceipt,omitempty"`
	Command         string                        `json:"command,omitempty"`
	ChildExitCode   int                           `json:"childExitCode"`
	Commands        []TemplateCommand             `json:"commands,omitempty"`
}

// EnvSetupData is the data of env.setup.
type EnvSetupData struct {
	Playbook      string `json:"playbook"`
	ChildExitCode int    `json:"childExitCode"`
}

// WorkspaceAddServiceData is the data of workspace.add-service.
type WorkspaceAddServiceData struct {
	Service string `json:"service"`
	Module  string `json:"module,omitempty"`
	Dir     string `json:"dir,omitempty"`
}

// ProjectNewData is the data of project.new.
type ProjectNewData struct {
	DryRun bool   `json:"dryRun"`
	Ref    string `json:"ref"`
	Name   string `json:"name"`
}

// UpdateData is the data of update.plan, update.apply and update.check.
type UpdateData struct {
	DryRun          bool     `json:"dryRun"`
	To              string   `json:"to,omitempty"`
	ConflictMarkers []string `json:"conflictMarkers"`
}
