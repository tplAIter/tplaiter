package gen

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// ResolveParams резолвит объявленные параметры генератора g из сырых значений
// флагов CLI. provided содержит только ЯВНО заданные флаги (имя → строковое
// значение); отсутствие ключа означает «флаг не задан» → берётся Default.
//
// Возвращает карту значений по имени (тип значения соответствует Param.Type:
// string→string, bool→bool, int→int, fields→[]Field) и разобранные поля из
// параметра типа fields (для удобства сниппетов как Context.Fields). Ошибки:
// required-параметр без значения и без default, невалидное значение (int,
// fields).
func ResolveParams(g *manifest.Generator, provided map[string]string) (map[string]any, []Field, error) {
	params := make(map[string]any, len(g.Params))
	var fields []Field

	for i := range g.Params {
		p := &g.Params[i]
		raw, ok := provided[p.Name]
		if !ok {
			if p.Required && p.Default == nil {
				return nil, nil, requiredParamErr(p)
			}
			val, fs, err := defaultParamValue(p)
			if err != nil {
				return nil, nil, fmt.Errorf("параметр --%s (default): %w", p.Name, err)
			}
			params[p.Name] = val
			if p.Default != nil {
				if err := validateParamPattern(p, defaultRawValue(p)); err != nil {
					return nil, nil, fmt.Errorf("параметр --%s (default): %w", p.Name, err)
				}
			}
			if p.Type == manifest.ParamTypeFields {
				fields = fs
			}
			continue
		}
		if err := validateParamPattern(p, raw); err != nil {
			return nil, nil, fmt.Errorf("параметр --%s: %w", p.Name, err)
		}
		val, fs, err := convertParam(p, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("параметр --%s: %w", p.Name, err)
		}
		params[p.Name] = val
		if p.Type == manifest.ParamTypeFields {
			fields = fs
		}
	}
	return params, fields, nil
}

// validateParamPattern проверяет raw-значение до преобразования типа. Это
// единственная точка runtime-валидации Param: и одиночный CLI gen, и batch,
// и MCP сначала вызывают ResolveParams, поэтому запись файлов не начинается
// до отказа некорректного значения.
func validateParamPattern(p *manifest.Param, raw string) error {
	if p.Pattern == "" {
		return nil
	}
	re, err := regexp.Compile(p.Pattern)
	if err != nil {
		// Нормальный путь отсекает manifest.Validate; эта ветка защищает
		// библиотечные вызовы с вручную собранным манифестом.
		return fmt.Errorf("некорректный pattern %q: %w", p.Pattern, err)
	}
	if !re.MatchString(raw) {
		return fmt.Errorf("значение %q не соответствует pattern %q", raw, p.Pattern)
	}
	return nil
}

func defaultRawValue(p *manifest.Param) string {
	switch v := p.Default.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	default:
		// defaultParamValue вернёт более точную ошибку несовпадения типов.
		return ""
	}
}

func requiredParamErr(p *manifest.Param) error {
	if p.Description != "" {
		return fmt.Errorf("параметр --%s обязателен — %s", p.Name, p.Description)
	}
	return fmt.Errorf("параметр --%s обязателен", p.Name)
}

// convertParam преобразует строковое значение флага в типизированное значение
// согласно Param.Type (для fields — дополнительно возвращает []Field).
func convertParam(p *manifest.Param, raw string) (any, []Field, error) {
	switch p.Type {
	case manifest.ParamTypeString:
		return raw, nil, nil
	case manifest.ParamTypeBool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("ожидается bool, получено %q", raw)
		}
		return b, nil, nil
	case manifest.ParamTypeInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("ожидается int, получено %q", raw)
		}
		return n, nil, nil
	case manifest.ParamTypeFields:
		fs, err := ParseFields(raw)
		if err != nil {
			return nil, nil, err
		}
		return fs, fs, nil
	case manifest.ParamTypeList:
		return ParseList(raw), nil, nil
	default:
		return nil, nil, fmt.Errorf("неизвестный тип параметра %q", p.Type)
	}
}

// ParseList разбирает список через запятую "a,b,c" в []string. Элементы
// обрезаются по пробелам; пустые (напр. от хвостовой запятой) отбрасываются.
// Пустая/пробельная строка даёт nil — валидное «список не задан».
func ParseList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if item := strings.TrimSpace(p); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// defaultParamValue строит значение параметра из Param.Default (или нулевого
// значения типа, если Default не задан).
func defaultParamValue(p *manifest.Param) (any, []Field, error) {
	switch p.Type {
	case manifest.ParamTypeString:
		if p.Default == nil {
			return "", nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default должен быть строкой")
		}
		return s, nil, nil
	case manifest.ParamTypeBool:
		if p.Default == nil {
			return false, nil, nil
		}
		b, ok := p.Default.(bool)
		if !ok {
			return nil, nil, errors.New("default должен быть bool")
		}
		return b, nil, nil
	case manifest.ParamTypeInt:
		if p.Default == nil {
			return 0, nil, nil
		}
		n, ok := p.Default.(int)
		if !ok {
			return nil, nil, errors.New("default должен быть int")
		}
		return n, nil, nil
	case manifest.ParamTypeFields:
		if p.Default == nil {
			return []Field(nil), nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default должен быть строкой вида name:type")
		}
		fs, err := ParseFields(s)
		if err != nil {
			return nil, nil, err
		}
		return fs, fs, nil
	case manifest.ParamTypeList:
		if p.Default == nil {
			return []string(nil), nil, nil
		}
		s, ok := p.Default.(string)
		if !ok {
			return nil, nil, errors.New("default должен быть строкой вида a,b,c")
		}
		return ParseList(s), nil, nil
	default:
		return nil, nil, fmt.Errorf("неизвестный тип параметра %q", p.Type)
	}
}

// DefaultFor возвращает строковое представление Param.Default для регистрации
// значения по умолчанию в pflag.FlagSet (cmd/gen.go). Для fields/string это
// сама строка; для bool/int — их строковая форма; nil → "".
func DefaultFor(p *manifest.Param) string {
	if p.Default == nil {
		return ""
	}
	switch v := p.Default.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.Itoa(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
