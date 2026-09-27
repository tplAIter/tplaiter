// Package engine реализует движок рендера шаблонов на манифест-модели
// ( §3.1, §4). Перенос с заменой источника метаданных:
// вместо gotmpl-специфичного template.json + gotmpl.json — *manifest.Template
// (engine-секция манифеста) и разрешённые настройки ([settings.Resolved]).
//
// Источник дерева файлов — произвольная fs.FS (в проде — репозиторий шаблона на
// диске/из git worktree, в тестах — os.DirFS фикстуры). Layout внутри источника:
// <Template.Engine.Root>/** (по умолчанию "files/"). Содержимое *.tmpl рендерится
// через text/template с собственным FuncMap (без sprig — архитектурное решение
// go-template §2.4, тот же принцип здесь); имена файлов шаблонизируются
// строковой заменой плейсхолдеров (__slug__, __module__) и поддерживают условные
// сегменты __if_<group>__ / __if_<group>=<value>__. Результат
// детерминирован: Baseline (sha256 каждого файла + хэш контекста) стабилен при
// одинаковом входе.
package engine

import (
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/tplAIter/tplaiter/internal/settings"
)

// tmplSuffix — суффикс файлов, содержимое которых рендерится через
// text/template.
const tmplSuffix = ".tmpl"

// StaticFuncMap возвращает набор строково-преобразующих функций, не зависящих
// от разрешённых настроек конкретного рендера (перенос go-template без
// изменений — архитектурное решение: собственная реализация, без sprig).
func StaticFuncMap() template.FuncMap {
	return template.FuncMap{
		"slug":   Slugify,
		"snake":  Snake,
		"camel":  Camel,
		"pascal": Pascal,
		"kebab":  Kebab,
		"upper":  strings.ToUpper,
		"lower":  strings.ToLower,
		"quote":  strconv.Quote,
		"split":  splitOn,
	}
}

// splitOn разбивает s по разделителю sep в []string (обёртка strings.Split с
// порядком аргументов «строка, разделитель» — удобным для пайпа
// `{{ .Name.Raw | split "." }}`). Нужна сниппетам генераторов, декомпозирующим
// составные идентификаторы (напр. "payments.DebitAccount" → сервис + activity):
// text/template не имеет встроенного split.
func splitOn(sep, s string) []string { return strings.Split(s, sep) }

// FuncMap возвращает полный набор функций рендера для заданного представления
// настроек: [StaticFuncMap] плюс новые хелперы `is`/`has`,
// обёртки над [settings.View.Is]/[settings.View.Has] — {{ if is "database"
// "postgres" }}, {{ if has "brokers" "kafka" }}.
func FuncMap(view settings.View) template.FuncMap {
	fm := StaticFuncMap()
	fm["is"] = view.Is
	fm["has"] = view.Has
	return fm
}

// splitWords разбивает произвольную строку на слова (в нижнем регистре) по
// разделителям (_-. /), границам camelCase (aB) и границам аббревиатур
// (HTTPServer → http, server). Основа для всех case-преобразований (перенос
// go-template без изменений).
func splitWords(s string) []string {
	runes := []rune(s)
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, string(cur))
			cur = cur[:0:0]
		}
	}
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == ' ' || r == '.' || r == '/':
			flush()
		case unicode.IsUpper(r):
			if i > 0 {
				prev := runes[i-1]
				var next rune
				if i+1 < len(runes) {
					next = runes[i+1]
				}
				switch {
				case unicode.IsLower(prev) || unicode.IsDigit(prev):
					flush()
				case unicode.IsUpper(prev) && unicode.IsLower(next):
					flush()
				}
			}
			cur = append(cur, unicode.ToLower(r))
		default:
			cur = append(cur, unicode.ToLower(r))
		}
	}
	flush()
	return words
}

func upperFirst(w string) string {
	if w == "" {
		return w
	}
	r := []rune(w)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// Snake преобразует строку в snake_case.
func Snake(s string) string { return strings.Join(splitWords(s), "_") }

// Kebab преобразует строку в kebab-case.
func Kebab(s string) string { return strings.Join(splitWords(s), "-") }

// Pascal преобразует строку в PascalCase.
func Pascal(s string) string {
	words := splitWords(s)
	for i, w := range words {
		words[i] = upperFirst(w)
	}
	return strings.Join(words, "")
}

// Camel преобразует строку в camelCase.
func Camel(s string) string {
	words := splitWords(s)
	for i, w := range words {
		if i == 0 {
			continue
		}
		words[i] = upperFirst(w)
	}
	return strings.Join(words, "")
}

// Slugify приводит имя к slug'у в формате ^[a-z][a-z0-9_]*$ (snake_case).
// Итоговую валидность (например, что slug не начинается с цифры) проверяет
// вызывающий код команды создания проекта.
func Slugify(s string) string { return Snake(s) }
