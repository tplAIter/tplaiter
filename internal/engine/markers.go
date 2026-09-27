package engine

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// markerPrefix — общий префикс всех внутрифайловых маркеров.
// Маркер ищется как ПОДСТРОКА строки — независимо от стиля комментария
// (//, #, <!-- -->, /* */, ;) вокруг него.
const markerPrefix = "tplater:"

// Ключевые слова маркеров, идущие сразу после [markerPrefix].
const (
	markerKwIfInverse = "if!"
	markerKwIf        = "if"
	markerKwBegin     = "begin"
	markerKwEnd       = "end"
)

// commentPrefixes — известные "открывающие" последовательности комментариев.
// Для хвостового tplater:if "начало комментария" — последнее вхождение любой
// из них перед маркером; при отсутствии — generic-фоллбек
// (см. [commentStartBefore]).
var commentPrefixes = []string{"//", "#", "<!--", "/*", ";"}

// commentSuffixes — закрывающие последовательности стилей комментариев,
// которые не входят в текст условия хвостового/begin-маркера, если ими
// заканчивается остаток строки (`<!-- tplater:if x=y -->`, `/* tplater:end */`).
var commentSuffixes = []string{"-->", "*/"}

// markerKind — распознанный вид маркера на строке файла.
type markerKind int

const (
	markerKindIf markerKind = iota
	markerKindIfInverse
	markerKindBegin
	markerKindEnd
	markerKindUnknown
)

// markerMatch — результат разбора одной строки на маркер: idx — индекс начала
// "tplater:" в строке, argIdx — индекс начала текста ПОСЛЕ ключевого слова
// (аргумент/условие для if и begin; для end и unknown не используется).
type markerMatch struct {
	kind   markerKind
	idx    int
	argIdx int
}

// findMarker ищет первое вхождение [markerPrefix] в строке и классифицирует
// его по ключевому слову. Ключевое слово должно заканчиваться границей
// не-идентификаторного символа (или концом строки) — иначе "tplater:iff" или
// "tplater:endpoint" не спутать с известными маркерами, а сообщить как
// [markerKindUnknown] (защита от опечаток).
func findMarker(line string) (markerMatch, bool) {
	idx := strings.Index(line, markerPrefix)
	if idx < 0 {
		return markerMatch{}, false
	}
	after := line[idx+len(markerPrefix):]

	// if! проверяется раньше if — иначе "if" совпал бы как префикс "if!" по
	// ошибке (см. matchesKeyword: "!" — граничный символ, значит "if" тоже
	// матчился бы на "if!...", если бы шёл первым).
	switch {
	case matchesKeyword(after, markerKwIfInverse):
		return markerMatch{kind: markerKindIfInverse, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwIfInverse)}, true
	case matchesKeyword(after, markerKwIf):
		return markerMatch{kind: markerKindIf, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwIf)}, true
	case matchesKeyword(after, markerKwBegin):
		return markerMatch{kind: markerKindBegin, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwBegin)}, true
	case matchesKeyword(after, markerKwEnd):
		return markerMatch{kind: markerKindEnd, idx: idx, argIdx: idx + len(markerPrefix) + len(markerKwEnd)}, true
	default:
		return markerMatch{kind: markerKindUnknown, idx: idx}, true
	}
}

// matchesKeyword сообщает, начинается ли after ключевым словом keyword с
// последующей границей (конец строки или не-идентификаторный символ).
func matchesKeyword(after, keyword string) bool {
	if !strings.HasPrefix(after, keyword) {
		return false
	}
	if len(after) == len(keyword) {
		return true
	}
	return isIdentBoundary(after[len(keyword)])
}

// isIdentBoundary сообщает, что байт b не может быть частью идентификатора
// (буква/цифра/подчёркивание) — используется для отделения ключевого слова
// маркера от случайного продолжения (typo-защита).
func isIdentBoundary(b byte) bool {
	switch {
	case b == '_':
		return false
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return false
	default:
		return true
	}
}

// commentStartBefore определяет индекс "начала комментария-последовательности"
// перед маркером на позиции markerIdx: последнее вхождение
// любого из [commentPrefixes] в line[:markerIdx]. Если ни один префикс не
// найден — generic-фоллбек: индекс самого маркера (после TrimRight пробелов
// перед ним это равносильно "вырезать с последнего пробельного разрыва").
func commentStartBefore(line string, markerIdx int) int {
	head := line[:markerIdx]
	best := -1
	for _, p := range commentPrefixes {
		if i := strings.LastIndex(head, p); i > best {
			best = i
		}
	}
	if best >= 0 {
		return best
	}
	return markerIdx
}

// extractMarkerArg вытаскивает аргумент маркера (условие if/begin) из остатка
// строки после ключевого слова: обрезает пробелы и, если строка заканчивается
// закрывающей последовательностью стиля комментария ([commentSuffixes]), тоже
// её отрезает (иначе она попала бы в текст условия — `<!-- tplater:if x=y -->`).
func extractMarkerArg(rest string) string {
	s := strings.TrimSpace(rest)
	for _, suf := range commentSuffixes {
		if strings.HasSuffix(s, suf) {
			s = strings.TrimSpace(strings.TrimSuffix(s, suf))
			break
		}
	}
	return s
}

// evalConditionExpr разбирает и вычисляет условие §3.2 маркера на values.
func evalConditionExpr(expr string, values settings.Values) (bool, error) {
	cond, err := manifest.ParseCondition(expr)
	if err != nil {
		return false, err
	}
	ok, err := settings.Eval(cond, values)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// markerFrame — открытый tplater:begin в стеке (для вложенности).
type markerFrame struct {
	line       int    // номер строки begin в исходном файле (для ошибки о непарности)
	expr       string // исходный текст условия (для сообщения об ошибке)
	prevActive bool   // active, действовавший ДО этого begin — восстанавливается на end
}

// processMarkers обрабатывает внутрифайловые маркеры tplater:if / tplater:if! /
// tplater:begin / tplater:end над содержимым файла ПОСЛЕ его
// текстового рендера или байт-копирования — см. интеграцию в engine.go
// (renderFile) и описание поведения  о выборе точки интеграции и исключении
// copyWithoutRender-совпадений.
//
// path — логический путь файла в дереве проекта, используется только в
// сообщениях об ошибках. values — [settings.Resolved.ActiveValues] шаблона.
//
// Ошибки (все — fatal, с path:строка): непарный tplater:begin, tplater:end без
// tplater:begin, синтаксически некорректное или ссылающееся на неизвестную
// группу условие, неизвестный tplater-маркер (защита от опечаток, например
// tplater:iff). Вложенные блоки поддержаны через стек [markerFrame].
func processMarkers(path string, data []byte, values settings.Values) ([]byte, error) {
	if !bytes.Contains(data, []byte(markerPrefix)) {
		return data, nil // fast path: в файле нет маркеров вовсе
	}

	lines := strings.Split(string(data), "\n")
	out := make([]string, 0, len(lines))

	var stack []markerFrame
	active := true

	for i, line := range lines {
		lineNo := i + 1
		m, found := findMarker(line)
		if !found {
			if active {
				out = append(out, line)
			}
			continue
		}

		switch m.kind {
		case markerKindUnknown:
			return nil, fmt.Errorf("engine: %s:%d: неизвестный tplater-маркер в строке %q", path, lineNo, line)

		case markerKindBegin:
			expr := extractMarkerArg(line[m.argIdx:])
			ok, err := evalConditionExpr(expr, values)
			if err != nil {
				return nil, fmt.Errorf("engine: %s:%d: tplater:begin %s: %w", path, lineNo, expr, err)
			}
			stack = append(stack, markerFrame{line: lineNo, expr: expr, prevActive: active})
			active = active && ok
			// строка самого begin всегда удаляется из вывода.

		case markerKindEnd:
			if len(stack) == 0 {
				return nil, fmt.Errorf("engine: %s:%d: tplater:end без соответствующего tplater:begin", path, lineNo)
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			active = top.prevActive
			// строка самого end всегда удаляется из вывода.

		case markerKindIf, markerKindIfInverse:
			expr := extractMarkerArg(line[m.argIdx:])
			ok, err := evalConditionExpr(expr, values)
			if err != nil {
				return nil, fmt.Errorf("engine: %s:%d: tplater:if %s: %w", path, lineNo, expr, err)
			}
			if m.kind == markerKindIfInverse {
				ok = !ok
			}
			// active главнее хвостового маркера: строка внутри выключенного
			// tplater:begin-блока вырезается целиком независимо от исхода
			// собственного условия (но условие всё равно проверено выше —
			// синтаксис/группа валидны и в мёртвом коде, как требует lint).
			if !active || !ok {
				continue
			}
			cut := commentStartBefore(line, m.idx)
			out = append(out, strings.TrimRight(line[:cut], " \t"))
		}
	}

	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return nil, fmt.Errorf("engine: %s:%d: непарный tplater:begin %s (нет соответствующего tplater:end)", path, top.line, top.expr)
	}

	result := []byte(strings.Join(out, "\n"))
	if bytes.Contains(result, []byte(markerPrefix)) {
		// Защитная сеть: по построению сюда попадать не должно
		// — каждый маркер выше либо обработан, либо уже вернул ошибку. Если
		// "tplater:" всё же остался в выводе, это баг обработки маркеров, а
		// не опечатка автора шаблона (та уже отловлена как markerKindUnknown).
		return nil, fmt.Errorf("engine: %s: маркер tplater: остался в обработанном выводе (внутренняя ошибка)", path)
	}
	return result, nil
}
