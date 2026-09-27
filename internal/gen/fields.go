package gen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
)

// Field — одно поле сущности, разобранное из строки параметра типа `fields`
// (`"customer:string,amount:float64,tags:[]string"`). Доступно сниппетам как
// элемент `.Fields`: имя во всех регистрах (`.Name.Pascal` и т.п.), Go-тип для
// структур/сигнатур, SQL-тип для миграций и нулевое значение для конструкторов.
type Field struct {
	// NameRaw — имя поля как записано в спецификации (до нормализации).
	NameRaw string
	// Name — производные варианты имени (Pascal/Camel/Snake/Kebab), как у [Name].
	Name Name
	// GoType — Go-тип поля (`string`, `int64`, `time.Time`, `uuid.UUID`, `[]string`).
	GoType string
	// IsSlice — true для слайс-типов (`[]T`).
	IsSlice bool
	// Zero — литерал нулевого значения Go-типа (`""`, `0`, `false`, `nil`, `time.Time{}`).
	Zero string
	// SQLType — тип колонки для goose-миграций (`text`, `bigint`, `jsonb`, ...).
	SQLType string
}

// fieldTypeInfo — запись таблицы поддерживаемых типов полей.
type fieldTypeInfo struct {
	goType  string
	sqlType string
	zero    string
}

// fieldTypes — allowlist скалярных типов полей. Таблица расширяема:
// добавление типа — одна строка. Слайсы `[]T` строятся из базового скаляра
// (см. [parseFieldType]) и всегда маппятся в jsonb.
var fieldTypes = map[string]fieldTypeInfo{
	"string":    {goType: "string", sqlType: "text", zero: `""`},
	"int":       {goType: "int", sqlType: "bigint", zero: "0"},
	"int64":     {goType: "int64", sqlType: "bigint", zero: "0"},
	"float64":   {goType: "float64", sqlType: "double precision", zero: "0"},
	"bool":      {goType: "bool", sqlType: "boolean", zero: "false"},
	"time.Time": {goType: "time.Time", sqlType: "timestamptz", zero: "time.Time{}"},
	"uuid":      {goType: "uuid.UUID", sqlType: "uuid", zero: "uuid.UUID{}"},
}

// ParseFields разбирает спецификацию полей `"name:type,name:type,..."` в
// []Field. Пустая строка — пустой (не ошибка) результат. Ошибки (со списком
// допустимых типов): пустой элемент, отсутствие ":", невалидное имя,
// неизвестный тип, дубликат имени.
func ParseFields(spec string) ([]Field, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	parts := strings.Split(spec, ",")
	out := make([]Field, 0, len(parts))
	seen := make(map[string]bool, len(parts))

	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, fmt.Errorf("поля %q: пустой элемент (ожидается name:type)", spec)
		}
		name, typ, ok := strings.Cut(item, ":")
		name = strings.TrimSpace(name)
		typ = strings.TrimSpace(typ)
		if !ok || name == "" || typ == "" {
			return nil, fmt.Errorf("поле %q: ожидается name:type", item)
		}

		n := Name{
			Raw:    name,
			Pascal: engine.Pascal(name),
			Camel:  engine.Camel(name),
			Snake:  engine.Snake(name),
			Kebab:  engine.Kebab(name),
		}
		if n.Pascal == "" || !identRe.MatchString(n.Snake) {
			return nil, fmt.Errorf("поле %q: недопустимое имя %q (производный snake %q должен соответствовать %s)",
				item, name, n.Snake, identRe.String())
		}
		if seen[n.Snake] {
			return nil, fmt.Errorf("поле %q: дублирующееся имя %q", spec, name)
		}
		seen[n.Snake] = true

		goType, sqlType, zero, isSlice, typErr := parseFieldType(typ)
		if typErr != nil {
			return nil, fmt.Errorf("поле %q: %w", item, typErr)
		}
		out = append(out, Field{
			NameRaw: name,
			Name:    n,
			GoType:  goType,
			IsSlice: isSlice,
			Zero:    zero,
			SQLType: sqlType,
		})
	}
	return out, nil
}

// parseFieldType резолвит тип поля: скаляр из [fieldTypes] либо слайс `[]T`
// (базовый T — скаляр из allowlist; SQL-тип слайса — jsonb, нулевое — nil).
func parseFieldType(typ string) (goType, sqlType, zero string, isSlice bool, err error) {
	if base, ok := strings.CutPrefix(typ, "[]"); ok {
		info, known := fieldTypes[base]
		if !known {
			return "", "", "", false, fmt.Errorf("неизвестный тип элемента слайса %q (допустимы: %s)", base, allowedTypesList())
		}
		return "[]" + info.goType, "jsonb", "nil", true, nil
	}
	info, ok := fieldTypes[typ]
	if !ok {
		return "", "", "", false, fmt.Errorf("неизвестный тип %q (допустимы: %s)", typ, allowedTypesList())
	}
	return info.goType, info.sqlType, info.zero, false, nil
}

// allowedTypesList возвращает отсортированный список допустимых базовых типов
// (плюс форма []T) для сообщений об ошибках.
func allowedTypesList() string {
	names := make([]string, 0, len(fieldTypes)+1)
	for t := range fieldTypes {
		names = append(names, t)
	}
	sort.Strings(names)
	names = append(names, "[]T")
	return strings.Join(names, ", ")
}
