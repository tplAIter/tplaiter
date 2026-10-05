package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/resultdto"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// rowStatus — semantic status of one doctor report row.
type rowStatus int

const (
	rowOK rowStatus = iota
	rowWarn
	rowFail
)

// doctorRow — one checked report item (environment tool, template tool, or
// ~/.tplaiter state item).
type doctorRow struct {
	Name   string
	Status rowStatus
	Detail string
	Hint   string
}

// doctorSection — named group of rows ("Environment", "Template tools",
// "State", SPEC-03 §4).
type doctorSection struct {
	Title string
	Rows  []doctorRow
}

// doctorCriticalTools — tools whose absence/mismatch makes `tplaiter doctor`
// fail (non-zero exit code). Other problems are only warnings in the report
// (SPEC-03 §4: "exit 1 on critical ✗
// (go, git)").
var doctorCriticalTools = map[string]bool{
	"go":  true,
	"git": true,
}

// newDoctorCmd creates `tplaiter doctor`.
func newDoctorCmd() *cobra.Command {
	return withResult(&cobra.Command{
		Annotations: prerunAnnotations(prerunReadonly),

		Use:   "doctor",
		Short: "Check environment and tools of active template",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sections, critical := buildDoctorReport(cmd.Context(), nil, "", "")
			criticalErr := errors.New("cmd: doctor: critical environment tools are not available — see report above")
			if jsonMode(cmd) {
				return emitDoctorResult(cmd, sections, critical, criticalErr)
			}
			renderDoctorReport(cmd.OutOrStdout(), ui.Default(), sections)

			if critical {
				// Exit 1: the check found problems (a finding, not a failure to run).
				return &ExitError{Code: 1, Err: criticalErr}
			}
			return nil
		},
	}, resultdto.OperationDoctorCheck)
}

// emitDoctorResult prints the doctor report as doctor.check data. A critical
// finding is status changes with exit 1, as in text mode.
func emitDoctorResult(cmd *cobra.Command, sections []doctorSection, critical bool, criticalErr error) error {
	data := resultdto.DoctorData{Critical: critical, Sections: []resultdto.DoctorSection{}}
	for _, section := range sections {
		out := resultdto.DoctorSection{Title: section.Title, Rows: []resultdto.DoctorRow{}}
		for _, row := range section.Rows {
			status := "ok"
			switch row.Status {
			case rowWarn:
				status = "warn"
			case rowFail:
				status = "fail"
			case rowOK:
			}
			out.Rows = append(out.Rows, resultdto.DoctorRow{Name: row.Name, Status: status, Detail: row.Detail, Hint: row.Hint})
		}
		data.Sections = append(data.Sections, out)
	}
	env := newResult(resultdto.OperationDoctorCheck)
	env.Project = currentProject()
	if err := env.SetData(data); err != nil {
		return err
	}
	if !critical {
		return emitResult(cmd, env, resultdto.ExitSuccess, nil)
	}
	env.Status = resultdto.StatusChanges
	env.Diagnostics = []resultdto.Diagnostic{{Code: "DOCTOR_CRITICAL_TOOL", Severity: "error", Message: "critical environment tools are not available", Details: map[string]any{}}}
	return emitResult(cmd, env, resultdto.ExitFinding, criticalErr)
}

// buildDoctorReport assembles all report sections. critical is true if at least
// one [doctorCriticalTools] row failed (Found and Satisfies are not both true).
func buildDoctorReport(ctx context.Context, runner execx.Runner, cwd, home string) (sections []doctorSection, critical bool) {
	// A doctor report is useful without becoming an authority or running a
	// manifest-selected executable.  The old probe path remains unavailable
	// until a separately approved bound action exists.
	_ = ctx
	_ = runner
	_ = cwd
	_ = home
	return []doctorSection{{Title: "Environment", Rows: []doctorRow{{Name: "tools", Status: rowWarn, Detail: "not checked: confirmed action required"}}}}, false
	/*
		envSection, envCritical := environmentSection(ctx, runner)
		sections = append(sections, envSection)
		critical = critical || envCritical

		if templSection, ok := templateToolsSection(ctx, runner, cwd); ok {
			sections = append(sections, templSection)
		}

		sections = append(sections, stateSection(home))

		return sections, critical
	*/
}

// environmentSection — base set of tools, independent of whether doctor runs
// inside a template project (SPEC-03 §4).
func environmentSection(ctx context.Context, runner execx.Runner) (doctorSection, bool) {
	tools := []manifest.Tool{
		{
			Name:     "go",
			Version:  ">=1.26.0",
			Required: true,
			Install:  manifest.ToolInstall{URL: "https://go.dev/dl/"},
		},
		{
			Name:     "git",
			Required: true,
			Install:  manifest.ToolInstall{Brew: "git", Apt: "git"},
		},
		{
			Name:     "docker",
			Required: false,
			Install:  manifest.ToolInstall{URL: "https://docs.docker.com/get-docker/"},
		},
		{
			Name:     "brew",
			Required: false,
			Install:  manifest.ToolInstall{URL: "https://brew.sh"},
		},
	}

	statuses := deps.Check(ctx, runner, tools)
	section := doctorSection{Title: "Environment"}
	critical := false
	for _, st := range statuses {
		row := toolRow(st)
		if row.Status == rowFail && doctorCriticalTools[st.Tool.Name] {
			critical = true
		}
		section.Rows = append(section.Rows, row)
	}
	return section, critical
}

// templateToolsSection checks requires.tools in the current project's manifest
// snapshot. ok=false when cwd is not a tplaiter project (no snapshot); the
// caller skips the entire section.
func templateToolsSection(ctx context.Context, runner execx.Runner, cwd string) (doctorSection, bool) {
	snapshotPath := filepath.Join(cwd, manifest.SnapshotRelPath)
	if _, err := os.Stat(snapshotPath); err != nil {
		return doctorSection{}, false
	}

	section := doctorSection{Title: "Template tools"}

	tmpl, err := manifest.LoadSnapshot(snapshotPath)
	if err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   manifest.SnapshotRelPath,
			Status: rowFail,
			Detail: "failed to parse manifest snapshot",
			Hint:   err.Error(),
		})
		return section, true
	}

	if len(tmpl.Requires.Tools) == 0 {
		section.Rows = append(section.Rows, doctorRow{
			Name:   manifest.SnapshotRelPath,
			Status: rowOK,
			Detail: "template does not declare requires.tools",
		})
		return section, true
	}

	for _, st := range deps.Check(ctx, runner, tmpl.Requires.Tools) {
		section.Rows = append(section.Rows, toolRow(st))
	}
	return section, true
}

// stateSection checks the tplaiter home directory (~/.tplaiter) and whether its
// config.yaml can be read.
func stateSection(home string) doctorSection {
	section := doctorSection{Title: "State"}

	if _, err := os.Stat(home); err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   home,
			Status: rowWarn,
			Detail: "directory not created",
			Hint:   "created automatically on first run of any command",
		})
		return section
	}
	section.Rows = append(section.Rows, doctorRow{
		Name:   home,
		Status: rowOK,
		Detail: "directory exists",
	})

	cfg, err := state.LoadConfig(home)
	if err != nil {
		section.Rows = append(section.Rows, doctorRow{
			Name:   "config.yaml",
			Status: rowFail,
			Detail: "not readable",
			Hint:   err.Error(),
		})
		return section
	}
	section.Rows = append(section.Rows, doctorRow{
		Name:   "config.yaml",
		Status: rowOK,
		Detail: fmt.Sprintf("version %d, repositories: %d", cfg.Version, len(cfg.Repos)),
	})
	return section
}

// toolRow turns [deps.ToolStatus] into a report row: a required tool that is
// not OK becomes rowFail, an optional one becomes rowWarn, otherwise rowOK.
func toolRow(st deps.ToolStatus) doctorRow {
	row := doctorRow{Name: st.Tool.Name}

	if st.Found && st.Satisfies {
		row.Status = rowOK
		row.Detail = st.Version
		if row.Detail == "" {
			row.Detail = st.Path
		} else {
			row.Detail = fmt.Sprintf("%s (%s)", st.Version, st.Path)
		}
		return row
	}

	if st.Tool.Required {
		row.Status = rowFail
	} else {
		row.Status = rowWarn
	}
	row.Detail = toolIssueDetail(st)
	row.Hint = installHint(st.Tool)
	return row
}

// toolIssueDetail describes what exactly is wrong with a tool.
func toolIssueDetail(st deps.ToolStatus) string {
	switch {
	case !st.Found:
		return "not found in PATH"
	case st.Version != "" && !st.Satisfies:
		return fmt.Sprintf("version %s does not satisfy %q", st.Version, st.Tool.Version)
	case st.Err != nil:
		return st.Err.Error()
	default:
		return "does not satisfy requirements"
	}
}

// installHint builds an installation recipe for the report: a platform plan
// through [deps.InstallPlan], falling back to the manifest's brew/apt/url when
// the plan applies to no branch (for example, doctor runs on a platform with
// no suitable recipe but the manifest declares something).
func installHint(tool manifest.Tool) string {
	action := deps.InstallPlan(tool, deps.DetectPlatform(execx.Exec{}))
	if action.Kind != deps.ActionNone {
		return action.Command
	}
	switch {
	case tool.Install.Brew != "":
		return "brew install " + tool.Install.Brew
	case tool.Install.Apt != "":
		return "sudo apt install " + tool.Install.Apt
	case tool.Install.URL != "":
		return tool.Install.URL
	default:
		return ""
	}
}

// renderDoctorReport prints report sections as ui.Table to out, with ✓/✗/!
// symbols and installation recipes for rows that are not OK.
func renderDoctorReport(out io.Writer, pal ui.Palette, sections []doctorSection) {
	for _, section := range sections {
		ui.Section(out, pal, section.Title)

		table := ui.NewTable("Component", "Details", "Status")
		for _, row := range section.Rows {
			table.AddRow(row.Name, row.Detail, statusCell(pal, row))
		}
		fmt.Fprintln(out, table.RenderStyled(pal))
		fmt.Fprintln(out)
	}
}

// statusCell builds the last (not padded for alignment) table column: a
// palette-colored status symbol plus an installation recipe for non-OK rows.
// The column is intentionally last: palette ANSI codes add "invisible" runes
// that would break alignment of ANY other column ([ui.Table] does not pad it).
func statusCell(pal ui.Palette, row doctorRow) string {
	var symbol string
	switch row.Status {
	case rowOK:
		symbol = ui.StatusIcon(pal, ui.StatusOK)
	case rowWarn:
		symbol = ui.StatusIcon(pal, ui.StatusWarn)
	case rowFail:
		symbol = ui.StatusIcon(pal, ui.StatusFail)
	}
	if row.Hint == "" {
		return symbol
	}
	return symbol + " — " + row.Hint
}
