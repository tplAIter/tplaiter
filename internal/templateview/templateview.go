// Package templateview рендерит "каталожное" представление шаблона
// (`tplater template show`, будущий `tplater new --help-template`,
// §4): шапка метаданных, дерево групп настроек и документация шаблона.
// Пакет — чистый рендер в io.Writer без доступа к репозиториям/файловой
// системе шаблона: вызывающий код (internal/cmd) сам разрешает ссылку,
// делает checkout и передаёт сюда уже разобранный [manifest.Template] и байты
// docs-файла.
package templateview

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// HeaderInfo — данные шапки `template show`: displayName/name, репозиторий,
// выбранная версия (+ доступные стабильные версии), описание, maintainers,
// лейблы.
type HeaderInfo struct {
	Repo        string
	Name        string
	DisplayName string
	// Version — человекочитаемая выбранная версия (см. [repo.Resolved.Version]).
	Version string
	// Versions — все доступные стабильные версии шаблона (версия-суффикс без
	// репо/имени-префикса), в порядке убывания; пусто, если у шаблона нет
	// стабильных тегов.
	Versions    []string
	Description string
	Maintainers []manifest.Maintainer
	Labels      map[string][]string
}

// RenderHeader печатает шапку метаданных шаблона в w: заголовок (жирным при
// цвете, см. [ui.Palette.Header]) и блок "ключ: значение" ([ui.KeyValue]) —
// репозиторий/версия/описание/maintainers/labels, только для непустых полей.
func RenderHeader(w io.Writer, pal ui.Palette, h HeaderInfo) {
	title := h.Name
	if h.DisplayName != "" && h.DisplayName != h.Name {
		title = fmt.Sprintf("%s (%s)", h.DisplayName, h.Name)
	}
	fmt.Fprintln(w, pal.Header(title))

	kv := ui.NewKeyValue().Add("репозиторий", h.Repo)
	if len(h.Versions) > 0 {
		kv.Add("версия", h.Version+"  (доступны: "+strings.Join(h.Versions, ", ")+")")
	} else {
		kv.Add("версия", h.Version)
	}
	if h.Description != "" {
		kv.Add("описание", h.Description)
	}
	if m := formatMaintainers(h.Maintainers); m != "" {
		kv.Add("maintainers", m)
	}
	if l := FormatLabels(h.Labels); l != "" {
		kv.Add("labels", l)
	}
	kv.Render(w)
}

// FormatLabels плоско форматирует лейблы шаблона: группы отсортированы по
// имени, значения внутри группы — через запятую, группы между собой — через
// "; " (`lang=go; infra=kafka,postgres`).
func FormatLabels(labels map[string][]string) string {
	if len(labels) == 0 {
		return ""
	}
	groups := make([]string, 0, len(labels))
	for g := range labels {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		values := append([]string(nil), labels[g]...)
		sort.Strings(values)
		parts = append(parts, g+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, "; ")
}

func formatMaintainers(ms []manifest.Maintainer) string {
	if len(ms) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		s := m.Name
		if m.Email != "" {
			s += " <" + m.Email + ">"
		}
		if s == "" {
			s = m.Telegram
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// RenderCommands печатает список команд манифеста (`commands`)
// как таблицу COMMAND/DESCRIPTION, отсортированную по имени. Пустой список
// команд — не ошибка, печатается поясняющая строка.
func RenderCommands(w io.Writer, pal ui.Palette, commands map[string]manifest.Command) {
	fmt.Fprintln(w, pal.Header("команды:"))
	if len(commands) == 0 {
		fmt.Fprintln(w, "  манифест не объявляет commands")
		return
	}

	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	t := ui.NewTable("COMMAND", "DESCRIPTION")
	for _, name := range names {
		t.AddRow(name, commands[name].Description)
	}
	fmt.Fprintln(w, indentLines(t.RenderStyled(pal), "  "))
}

// indentLines добавляет префикс pad перед каждой строкой s.
func indentLines(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}
