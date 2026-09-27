package contribute

import (
	"bytes"
	"path"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/manifest"
)

// minSubstLen — минимальная длина значения проекта, ниже которой обратная
// замена не выполняется ( уточнение реализации ): короткие slug'и вроде
// "app"/"api" слишком часто встречаются в коде случайно, и их замена на
// плейсхолдер испортила бы содержимое. Module (go-путь) всегда длиннее и
// заменяется всегда.
const minSubstLen = 4

// reviewMarker — текст пометки, которую upgrade вставляет в шапку файла,
// принадлежащего условной вертикали (files-глоб опции). Полная обратная
// трансформация условных блоков алгоритмически ненадёжна — честно
// оставляем ревьюеру шаблона.
const reviewMarker = "TPLATER-REVIEW: файл принадлежит условной вертикали"

// substitution — одна обратная замена: литеральное значение проекта value →
// плейсхолдер go-template placeholder.
type substitution struct {
	value       string
	placeholder string
}

// buildSubstitutions собирает упорядоченный список обратных замен из координат
// проекта. Порядок применения — по убыванию длины value, так
// что более специфичные/длинные вхождения (прежде всего Module — go-путь,
// содержащий Slug как подстроку) заменяются раньше и не портятся более короткими
// заменами. Значения с одинаковым содержимым дедуплицируются: при совпадении
// Slug==Name==Snake (частый случай) остаётся одна замена с самым каноничным
// плейсхолдером (приоритет Slug над Snake/Name).
func buildSubstitutions(p manifest.ProjectInfo) []substitution {
	slug := p.Slug
	// Кандидаты в порядке приоритета плейсхолдера при дедупликации по value.
	// Module первым: это самое длинное и специфичное значение (go-путь).
	candidates := []substitution{
		{p.Module, "{{ .Project.Module }}"},
		{slug, "{{ .Project.Slug }}"},
		{engine.Pascal(slug), "{{ .Project.Pascal }}"},
		{engine.Camel(slug), "{{ .Project.Camel }}"},
		{engine.Kebab(slug), "{{ .Project.Kebab }}"},
		{engine.Snake(slug), "{{ .Project.Snake }}"},
		{p.Name, "{{ .Project.Name }}"},
		{p.System, "{{ .Project.System }}"},
		{p.Domain, "{{ .Project.Domain }}"},
	}

	seen := make(map[string]struct{}, len(candidates))
	subs := make([]substitution, 0, len(candidates))
	for _, c := range candidates {
		if len(c.value) < minSubstLen {
			continue // слишком короткое/пустое значение — не заменяем (шум).
		}
		if _, dup := seen[c.value]; dup {
			continue // дедуп: значение уже покрыто более приоритетным плейсхолдером.
		}
		seen[c.value] = struct{}{}
		subs = append(subs, c)
	}

	// Применять в порядке убывания длины value: длинные (Module) раньше коротких,
	// иначе замена короткого Slug разорвала бы вхождение Module.
	sort.SliceStable(subs, func(i, j int) bool {
		return len(subs[i].value) > len(subs[j].value)
	})
	return subs
}

// derender применяет обратные замены к содержимому work-файла (де-рендер): для
// каждой подстановки заменяет все литеральные вхождения value на placeholder.
// Возвращает результат и признак того, была ли выполнена хотя бы одна замена
// (нужно для эвристики «extra-файл → .tmpl, только если появились плейсхолдеры»).
func derender(content []byte, subs []substitution) (out []byte, changed bool) {
	out = content
	for _, s := range subs {
		vb := []byte(s.value)
		if !bytes.Contains(out, vb) {
			continue
		}
		out = bytes.ReplaceAll(out, vb, []byte(s.placeholder))
		changed = true
	}
	return out, changed
}

// commentStyle возвращает открывающий/закрывающий фрагменты строкового
// комментария для файла logicalPath (по расширению; .tmpl-суффикс снимается).
// ok=false для форматов без известного стиля комментария (бинарные/JSON и т.п.)
// — для таких файлов пометка ревью уходит в описание MR, а не в тело файла.
func commentStyle(logicalPath string) (open, closeTag string, ok bool) {
	name := strings.TrimSuffix(logicalPath, ".tmpl")
	base := path.Base(name)
	ext := strings.ToLower(path.Ext(name))

	switch ext {
	case ".go", ".java", ".kt", ".ts", ".tsx", ".js", ".jsx", ".c", ".h",
		".cc", ".cpp", ".hpp", ".rs", ".scala", ".swift", ".proto", ".groovy":
		return "// ", "", true
	case ".yaml", ".yml", ".sh", ".bash", ".zsh", ".py", ".rb", ".toml",
		".ini", ".conf", ".cfg", ".env", ".mk", ".tf", ".hcl", ".pl":
		return "# ", "", true
	case ".md", ".markdown", ".html", ".htm", ".xml", ".vue", ".svg":
		return "<!-- ", " -->", true
	case ".sql":
		return "-- ", "", true
	case ".lua":
		return "-- ", "", true
	}

	// Файлы без расширения, узнаваемые по имени.
	switch base {
	case "Dockerfile", "Makefile", "Makefile.mk", ".gitignore", ".dockerignore",
		".editorconfig", ".gitattributes":
		return "# ", "", true
	}
	return "", "", false
}

// markReview вставляет строку-пометку reviewMarker в шапку содержимого файла
// logicalPath, если формат допускает комментарий. condition — условие вертикали
// (When/AnyOf files-правила), включается в текст пометки. Для shebang-скриптов
// пометка ставится ПОСЛЕ строки `#!...`, чтобы не сломать интерпретатор.
// Возвращает (контент, true) при успехе; (контент, false), если стиль
// комментария неизвестен (тогда вызывающий добавит пометку в описание MR).
func markReview(content []byte, logicalPath, condition string) ([]byte, bool) {
	open, closeTag, ok := commentStyle(logicalPath)
	if !ok {
		return content, false
	}
	text := reviewMarker
	if condition != "" {
		text += " " + condition
	}
	text += "; проверьте условные блоки"
	line := open + text + closeTag + "\n"

	// Уже помечен — не дублируем.
	if bytes.Contains(content, []byte(reviewMarker)) {
		return content, true
	}

	// Shebang: пометка после первой строки.
	if bytes.HasPrefix(content, []byte("#!")) {
		if nl := bytes.IndexByte(content, '\n'); nl >= 0 {
			var b bytes.Buffer
			b.Write(content[:nl+1])
			b.WriteString(line)
			b.Write(content[nl+1:])
			return b.Bytes(), true
		}
	}

	return append([]byte(line), content...), true
}

// conditionForPath возвращает условие files-правила (When или AnyOf через " | "),
// чьи Paths-глобы покрывают logicalPath, и признак принадлежности условной
// вертикали. Правила без условия (no-op) игнорируются. Учитываются только Paths
// (включение вертикали); Remove-правила описывают удаление и к «принадлежности
// вертикали» не относятся.
func conditionForPath(rules []manifest.FileRule, logicalPath string) (string, bool) {
	for i := range rules {
		r := &rules[i]
		if len(r.Paths) == 0 {
			continue
		}
		cond := ruleCondition(r)
		if cond == "" {
			continue // безусловное правило — не «вертикаль».
		}
		if newGlobMatcher(r.Paths).match(logicalPath) {
			return cond, true
		}
	}
	return "", false
}

// ruleCondition форматирует условие files-правила в человекочитаемую строку.
func ruleCondition(r *manifest.FileRule) string {
	if r.When != "" {
		return r.When
	}
	if len(r.AnyOf) > 0 {
		return strings.Join(r.AnyOf, " | ")
	}
	return ""
}
