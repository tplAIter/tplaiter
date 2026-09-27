package engine

import (
	"fmt"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// ifPrefix/ifSuffix — обёртка условного сегмента пути.
const (
	ifPrefix = "__if_"
	ifSuffix = "__"
)

// evalIfSegment распознаёт условный сегмент пути и вычисляет его истинность на
// values. Два вида:
//
//   - __if_<group>__ — «истина по умолчанию для типа»: toggle=true, select —
//     значение группы непусто (внимание: непустое значение — не то же самое,
//     что «выбрана не служебная опция»; select с ненулевым default'ом вроде
//     "none" будет истинным всегда, см. описание поведения), multiselect — список
//     непуст, int — значение не 0.
//   - __if_<group>=<value>__ — точечная проверка атома `group=value`
//     ([manifest.ParseCondition] + [settings.Eval]), работает для любого типа
//     группы (для multiselect — «содержит»).
//
// ok=false — сегмент не условный (обычное имя каталога/файла), active/err
// не имеют смысла. err != nil — сегмент условный, но ссылается на неизвестную
// группу или синтаксически некорректен: это ошибка автора манифеста и она
// прерывает рендер.
func evalIfSegment(seg string, values settings.Values) (active, ok bool, err error) {
	if !strings.HasPrefix(seg, ifPrefix) || !strings.HasSuffix(seg, ifSuffix) {
		return false, false, nil
	}
	inner := seg[len(ifPrefix) : len(seg)-len(ifSuffix)]
	if inner == "" {
		return false, false, nil
	}

	if idx := strings.Index(inner, manifest.OpEq); idx >= 0 {
		group, value := inner[:idx], inner[idx+1:]
		if group == "" || value == "" {
			return false, true, fmt.Errorf("некорректный условный сегмент пути %q", seg)
		}
		cond, err := manifest.ParseCondition(group + manifest.OpEq + value)
		if err != nil {
			return false, true, fmt.Errorf("условный сегмент пути %q: %w", seg, err)
		}
		active, err = settings.Eval(cond, values)
		if err != nil {
			return false, true, fmt.Errorf("условный сегмент пути %q: %w", seg, err)
		}
		return active, true, nil
	}

	raw, exists := values[inner]
	if !exists {
		return false, true, fmt.Errorf("условный сегмент пути %q ссылается на неизвестную группу %q", seg, inner)
	}
	return truthy(raw), true, nil
}

// truthy определяет типо-общую «истинность» значения группы настроек:
// bool — сам по себе, string — непусто, []string — непусто, int — не 0.
// Любой другой (в т.ч. отсутствующий) тип — false.
func truthy(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val != ""
	case []string:
		return len(val) > 0
	case int:
		return val != 0
	default:
		return false
	}
}

// transformPath применяет условные сегменты __if_<group>__/__if_<group>=<value>__
// и подстановку плейсхолдеров имён (__slug__, __module__, перенос go-template
// без изменений). Возвращает (путь, включать?, ошибка).
func (r *renderer) transformPath(rel string) (string, bool, error) {
	segs := strings.Split(rel, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		active, isIf, err := evalIfSegment(seg, r.values)
		if err != nil {
			return "", false, fmt.Errorf("engine: %s: %w", rel, err)
		}
		if isIf {
			if !active {
				return "", false, nil
			}
			continue
		}
		seg = strings.ReplaceAll(seg, "__slug__", r.ctx.Project.Slug)
		seg = strings.ReplaceAll(seg, "__module__", r.ctx.Project.Module)
		out = append(out, seg)
	}
	return strings.Join(out, "/"), true, nil
}
