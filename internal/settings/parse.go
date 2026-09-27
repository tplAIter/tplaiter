package settings

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ParseSet разбирает одно CLI-значение вида "group=value" (флаг --set),
// типизируя его по манифесту:
//   - select: value должен быть id существующей невыбираемой-не-planned опции;
//   - multiselect: "a,b,c" → []string, каждый — валидная опция;
//   - toggle: true/false/yes/no/1/0/on/off → bool;
//   - int: целое число;
//   - string: как есть.
//
// Возвращает id группы и типизированное значение. Ошибки перечисляют допустимые
// значения (для select/multiselect — список опций).
func ParseSet(tpl *manifest.Template, expr string) (group string, value any, err error) {
	eq := strings.IndexByte(expr, '=')
	if eq < 0 {
		return "", nil, fmt.Errorf("значение %q не в формате group=value", expr)
	}
	group = strings.TrimSpace(expr[:eq])
	raw := strings.TrimSpace(expr[eq+1:])
	if group == "" {
		return "", nil, fmt.Errorf("значение %q без имени группы", expr)
	}

	idx := indexGroups(tpl)
	m, ok := idx[group]
	if !ok {
		return "", nil, fmt.Errorf("неизвестная группа %q", group)
	}

	value, err = typeString(m.g, raw)
	if err != nil {
		return "", nil, fmt.Errorf("группа %q: %w", group, err)
	}
	return group, value, nil
}

// LoadAnswersFile читает YAML-файл ответов (--answers) и типизирует каждое
// значение по манифесту той же логикой, что и остальной ввод. Сырые скалярные
// значения (bool/int/string) и списки приводятся к каноническим типам групп.
// Неизвестные группы в файле — ошибка (перечисляются все).
func LoadAnswersFile(tpl *manifest.Template, path string) (Values, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение файла ответов %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("разбор файла ответов %s: %w", path, err)
	}
	return typeAnswers(tpl, raw)
}

// typeAnswers типизирует сырой map ответов по манифесту. Вынесен отдельно для
// тестируемости без файловой системы.
func typeAnswers(tpl *manifest.Template, raw map[string]any) (Values, error) {
	idx := indexGroups(tpl)
	out := make(Values, len(raw))

	// Детерминированный порядок обхода — стабильные сообщения об ошибках.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var unknown []string
	for _, k := range keys {
		m, ok := idx[k]
		if !ok {
			unknown = append(unknown, k)
			continue
		}
		val, err := typeNative(m.g, raw[k])
		if err != nil {
			return nil, fmt.Errorf("группа %q: %w", k, err)
		}
		out[k] = val
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("неизвестные группы в файле ответов: %s", strings.Join(unknown, ", "))
	}
	return out, nil
}

// typeString типизирует строковый ввод (--set) по типу группы.
func typeString(g *manifest.SettingGroup, raw string) (any, error) {
	switch g.Type {
	case manifest.TypeSelect:
		if err := checkOption(g, raw); err != nil {
			return nil, err
		}
		return raw, nil
	case manifest.TypeMultiselect:
		var out []string
		if raw != "" {
			for _, part := range strings.Split(raw, ",") {
				val := strings.TrimSpace(part)
				if val == "" {
					continue
				}
				if err := checkOption(g, val); err != nil {
					return nil, err
				}
				out = append(out, val)
			}
		}
		if out == nil {
			out = []string{}
		}
		return out, nil
	case manifest.TypeToggle:
		b, err := parseBool(raw)
		if err != nil {
			return nil, err
		}
		return b, nil
	case manifest.TypeInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("значение %q не является целым числом", raw)
		}
		return n, nil
	default: // string
		return raw, nil
	}
}

// typeNative типизирует нативное yaml-значение по типу группы. Строковые формы
// (например "true" для toggle) допускаются и делегируются typeString.
func typeNative(g *manifest.SettingGroup, raw any) (any, error) {
	switch g.Type {
	case manifest.TypeSelect:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("ожидалась строка (id опции), получено %T", raw)
		}
		if err := checkOption(g, s); err != nil {
			return nil, err
		}
		return s, nil
	case manifest.TypeMultiselect:
		if s, ok := raw.(string); ok {
			return typeString(g, s)
		}
		list := toStringSlice(raw)
		for _, val := range list {
			if err := checkOption(g, val); err != nil {
				return nil, err
			}
		}
		return list, nil
	case manifest.TypeToggle:
		switch b := raw.(type) {
		case bool:
			return b, nil
		case string:
			return parseBool(b)
		default:
			return nil, fmt.Errorf("ожидался bool, получено %T", raw)
		}
	case manifest.TypeInt:
		if n, ok := toInt(raw); ok {
			return n, nil
		}
		if s, ok := raw.(string); ok {
			return typeString(g, s)
		}
		return nil, fmt.Errorf("ожидалось целое число, получено %T", raw)
	default: // string
		if s, ok := raw.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", raw), nil
	}
}

// checkOption проверяет, что value — существующая невыбираемая-не-planned опция
// группы. Ошибка перечисляет допустимые (не-planned) значения.
func checkOption(g *manifest.SettingGroup, value string) error {
	allowed := make([]string, 0, len(g.Options))
	for i := range g.Options {
		opt := &g.Options[i]
		if opt.Status == manifest.StatusPlanned {
			if opt.ID == value {
				return fmt.Errorf("опция %q помечена planned и недоступна для выбора", value)
			}
			continue
		}
		allowed = append(allowed, opt.ID)
		if opt.ID == value {
			return nil
		}
	}
	return fmt.Errorf("недопустимое значение %q, допустимо: %s", value, strings.Join(allowed, ", "))
}

// parseBool разбирает булев ввод CLI в широком наборе форм.
func parseBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "yes", "y", "on", "1":
		return true, nil
	case "false", "no", "n", "off", "0":
		return false, nil
	default:
		return false, fmt.Errorf("значение %q не булево (true/false/yes/no/on/off/1/0)", raw)
	}
}
