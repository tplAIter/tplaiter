package cmd

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/templateview"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// templateManifestFileName — template manifest name at the checkout root
// (see internal/repo/scan.go: templateManifestName, the same package-private
// constant; this copy is needed to read the fs.FS returned by
// [repo.Manager.Checkout]).
const templateManifestFileName = "template.manifest.yaml"

func init() {
	rootCmd.AddCommand(newTemplateCmd())
}

// newTemplateCmd creates `tplater template`: the catalog of templates from
// added repositories, with listing, inspection, and tree export.
func newTemplateCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "template",
		Short: "Каталог шаблонов: list/show/pull",
		Long: "Список, просмотр метаданных с деревом настроек и документацией, а также " +
			"выгрузка дерева шаблонов из добавленных репозиториев. См. документацию.",
	}
	c.AddCommand(
		newTemplateListCmd(),
		newTemplateShowCmd(),
		newTemplatePullCmd(),
	)
	return c
}

// labelFilter — one parsed `-l group=value`.
type labelFilter struct {
	group string
	value string
}

// templateRow — one `template list` row: an index entry and the repository alias
// where it was found.
type templateRow struct {
	alias string
	entry state.TemplateEntry
}

func newTemplateListCmd() *cobra.Command {
	var (
		repoAlias string
		nameSub   string
		labels    []string
	)
	c := &cobra.Command{
		Use:   "list",
		Short: "Список шаблонов каталога (NAME/REPO/VERSION/DESCRIPTION/LABELS)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return runTemplateList(cmd, mgr, repoAlias, nameSub, labels)
		},
	}
	f := c.Flags()
	f.StringVar(&repoAlias, "repo", "", "фильтр по алиасу репозитория (точное совпадение)")
	f.StringVar(&nameSub, "name", "", "фильтр по подстроке имени шаблона (без учёта регистра)")
	f.StringArrayVarP(&labels, "label", "l", nil,
		"фильтр по лейблу group=value (повторяемый флаг, семантика AND)")
	return c
}

func runTemplateList(cmd *cobra.Command, mgr *repo.Manager, repoAlias, nameSub string, rawLabels []string) error {
	filters, err := parseLabelFilters(rawLabels)
	if err != nil {
		return err
	}

	all, err := mgr.Templates()
	if err != nil {
		return err
	}
	rows := filterTemplateRows(all, repoAlias, nameSub, filters)

	out := cmd.OutOrStdout()
	if len(rows) == 0 {
		return reportEmptyTemplateList(out, mgr)
	}

	t := ui.NewTable("NAME", "REPO", "VERSION", "DESCRIPTION", "LABELS")
	for _, r := range rows {
		t.AddRow(r.entry.Name, r.alias, r.entry.Version, r.entry.Description, templateview.FormatLabels(r.entry.LabelsFlat))
	}
	fmt.Fprintln(out, t.RenderStyled(ui.Default()))
	return nil
}

// parseLabelFilters parses repeated `-l group=value` flags into filters. An
// empty group or value is a format error.
func parseLabelFilters(raw []string) ([]labelFilter, error) {
	out := make([]labelFilter, 0, len(raw))
	for _, r := range raw {
		i := strings.Index(r, "=")
		if i <= 0 || i == len(r)-1 {
			return nil, fmt.Errorf("cmd: template list: некорректный формат -l %q (ожидается group=value)", r)
		}
		out = append(out, labelFilter{group: r[:i], value: r[i+1:]})
	}
	return out, nil
}

// filterTemplateRows filters the aggregate index all by repository alias
// (exact match when set), name substring (case-insensitive when set), and
// labels (AND across filters: labels[group] must equal value for each filter).
// The result is deterministic: repository alias, then template name (already
// sorted in index.yaml).
func filterTemplateRows(all map[string][]state.TemplateEntry, repoAlias, nameSub string, filters []labelFilter) []templateRow {
	aliases := make([]string, 0, len(all))
	for a := range all {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	nameSubLower := strings.ToLower(nameSub)

	var out []templateRow
	for _, alias := range aliases {
		if repoAlias != "" && alias != repoAlias {
			continue
		}
		for _, entry := range all[alias] {
			if nameSub != "" && !strings.Contains(strings.ToLower(entry.Name), nameSubLower) {
				continue
			}
			if !matchesLabelFilters(entry.LabelsFlat, filters) {
				continue
			}
			out = append(out, templateRow{alias: alias, entry: entry})
		}
	}
	return out
}

func matchesLabelFilters(labels map[string][]string, filters []labelFilter) bool {
	for _, f := range filters {
		values, ok := labels[f.group]
		if !ok {
			return false
		}
		found := false
		for _, v := range values {
			if v == f.value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// reportEmptyTemplateList prints a friendly message for an empty `template
// list` result: if no repositories are added, it suggests `repo add`; otherwise
// it explains that the filters matched nothing.
func reportEmptyTemplateList(out io.Writer, mgr *repo.Manager) error {
	infos, err := mgr.List()
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		fmt.Fprintln(out, "Шаблоны не найдены: нет ни одного добавленного репозитория. "+
			"Добавьте репозиторий: `tplater repo add <alias> <url>`.")
		return nil
	}
	fmt.Fprintln(out, "Шаблоны не найдены: ни один шаблон не подходит по заданным фильтрам.")
	return nil
}

func newTemplateShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <ref>",
		Short: "Метаданные, дерево настроек и документация шаблона",
		Long: "Разрешает ссылку <ref> (полная `repo/name@version` либо короткая `name`), " +
			"делает checkout на выбранной версии и печатает: шапку метаданных, дерево групп настроек " +
			"(), список команд (`commands`) и рендер docs-файла (glamour при цветном выводе, " +
			"иначе — как есть).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return runTemplateShow(cmd, mgr, args[0])
		},
	}
}

func runTemplateShow(cmd *cobra.Command, mgr *repo.Manager, ref string) error {
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		return err
	}

	fsys, cleanup, err := mgr.Checkout(cmd.Context(), resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "предупреждение: очистка checkout: %v\n", cerr)
		}
	}()

	data, err := fs.ReadFile(fsys, templateManifestFileName)
	if err != nil {
		return fmt.Errorf("cmd: template show: чтение %s: %w", templateManifestFileName, err)
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return fmt.Errorf("cmd: template show: %w", err)
	}

	out := cmd.OutOrStdout()
	pal := ui.Default()

	templateview.RenderHeader(out, pal, templateview.HeaderInfo{
		Repo:        resolved.RepoAlias,
		Name:        tpl.Metadata.Name,
		DisplayName: tpl.Metadata.DisplayName,
		Version:     resolved.Version,
		Versions:    versionSuffixes(resolved.Entry),
		Description: tpl.Metadata.Description,
		Maintainers: tpl.Metadata.Maintainers,
		Labels:      tpl.Metadata.Labels,
	})
	fmt.Fprintln(out)

	ui.Section(out, pal, "настройки:")
	templateview.RenderSettings(out, pal, tpl.Settings, 1)
	fmt.Fprintln(out)

	templateview.RenderCommands(out, pal, tpl.Commands)
	fmt.Fprintln(out)

	return renderTemplateDocs(out, pal, fsys, tpl.Metadata.Docs)
}

// versionSuffixes converts full template git tags (`v1.2.0` for single,
// `<name>/v1.2.0` for multi; see [state.TemplateEntry.Tags]) into version
// suffixes shown to the user in the `template show` header.
func versionSuffixes(entry state.TemplateEntry) []string {
	out := make([]string, 0, len(entry.Tags))
	for _, t := range entry.Tags {
		out = append(out, strings.TrimPrefix(t, entry.Name+"/"))
	}
	return out
}

// renderTemplateDocs prints the `template show` docs section: the file named by
// metadata.docs in checkout fsys, rendered through [templateview.RenderDocs]
// according to pal.Enabled(). Missing metadata.docs or the file itself is not
// a command error (the manifest may omit this optional field); a dimmed
// explanatory line is printed.
func renderTemplateDocs(out io.Writer, pal ui.Palette, fsys fs.FS, docsPath string) error {
	ui.Section(out, pal, "docs:")
	if docsPath == "" {
		fmt.Fprintln(out, pal.Muted("  манифест не указывает metadata.docs"))
		return nil
	}

	clean := path.Clean(strings.TrimPrefix(docsPath, "/"))
	data, err := fs.ReadFile(fsys, clean)
	if err != nil {
		fmt.Fprintln(out, pal.Muted(fmt.Sprintf("  не удалось прочитать docs (%s): %v", docsPath, err)))
		return nil
	}
	return templateview.RenderDocs(out, data, pal.Enabled())
}

func newTemplatePullCmd() *cobra.Command {
	var dest string
	c := &cobra.Command{
		Use:   "pull <ref>",
		Short: "Выгрузить дерево шаблона на диск (checkout ref) для изучения/форка",
		Long: "Разрешает ссылку <ref>, делает checkout на выбранной версии и копирует " +
			"всё дерево шаблона (манифест, files/, docs) в dest (по умолчанию ./<name>). dest должен " +
			"не существовать либо быть пустым каталогом.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, st, err := newManager(cmd)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			return runTemplatePull(cmd, mgr, args[0], dest)
		},
	}
	c.Flags().StringVar(&dest, "dest", "", "каталог выгрузки (по умолчанию ./<name>)")
	return c
}

func runTemplatePull(cmd *cobra.Command, mgr *repo.Manager, ref, dest string) error {
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		return err
	}
	if dest == "" {
		dest = "./" + resolved.Entry.Name
	}
	if err := ensureEmptyDest(dest); err != nil {
		return err
	}

	fsys, cleanup, err := mgr.Checkout(cmd.Context(), resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "предупреждение: очистка checkout: %v\n", cerr)
		}
	}()

	if err := copyFSTree(fsys, dest); err != nil {
		return fmt.Errorf("cmd: template pull: копирование в %s: %w", dest, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "шаблон %s@%s выгружен в %s\n", resolved.Entry.Name, resolved.Version, dest)
	return nil
}

// ensureEmptyDest checks that dest is suitable for export: it either does not
// exist (and will be created while copying) or is an empty directory. A file at
// dest or a non-empty directory is an error.
func ensureEmptyDest(dest string) error {
	info, err := os.Stat(dest)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cmd: template pull: проверка %s: %w", dest, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cmd: template pull: %s существует и не является каталогом", dest)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return fmt.Errorf("cmd: template pull: чтение %s: %w", dest, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("cmd: template pull: каталог %s не пуст", dest)
	}
	return nil
}

// copyFSTree copies the entire fsys tree (template checkout) to dest, preserving
// relative paths and source file permissions. The `.git` directory/file (see
// [repo.Manager.Checkout]: a worktree is not an independent clone, so its root
// contains a `.git` file pointing to the main clone in ~/.tplaiter/repos/) is a
// checkout artifact rather than part of the template tree and is not exported.
func copyFSTree(fsys fs.FS, dest string) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		target := filepath.Join(dest, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("чтение %s: %w", p, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		mode := os.FileMode(0o644)
		if info, ierr := d.Info(); ierr == nil {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			return fmt.Errorf("запись %s: %w", target, err)
		}
		return nil
	})
}
