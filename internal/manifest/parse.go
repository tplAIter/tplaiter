package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ErrUnsupportedAPIVersion возвращается, когда major-версия контракта не
// поддерживается этим tplater (сообщение содержит призыв обновиться).
var ErrUnsupportedAPIVersion = errors.New("неподдерживаемая версия контракта apiVersion")

// LoadTemplate читает и разбирает манифест шаблона по пути path. Незнакомые
// поля отклоняются (KnownFields), apiVersion и kind проверяются. Валидация
// содержимого (§9) выполняется отдельно методом [Template.Validate].
func LoadTemplate(path string) (*Template, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var t Template
	if err := decodeStrict(data, &t); err != nil {
		return nil, fmt.Errorf("разбор манифеста шаблона %s: %w", path, err)
	}
	if err := checkKind(t.APIVersion, t.Kind, KindTemplate); err != nil {
		return nil, err
	}
	return &t, nil
}

// LoadRepository читает и разбирает манифест мульти-шаблонного репозитория.
func LoadRepository(path string) (*Repository, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var r Repository
	if err := decodeStrict(data, &r); err != nil {
		return nil, fmt.Errorf("разбор манифеста репозитория %s: %w", path, err)
	}
	if err := checkKind(r.APIVersion, r.Kind, KindRepository); err != nil {
		return nil, err
	}
	return &r, nil
}

// LoadProject читает и разбирает проектный маркер .tplaiter/project.yaml.
func LoadProject(path string) (*Project, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var p Project
	if err := decodeStrict(data, &p); err != nil {
		return nil, fmt.Errorf("разбор проектного маркера %s: %w", path, err)
	}
	if err := checkKind(p.APIVersion, p.Kind, KindProject); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseTemplate разбирает манифест шаблона из байтов (без чтения файла) — для
// снимков и тестов.
func ParseTemplate(data []byte) (*Template, error) {
	var t Template
	if err := decodeStrict(data, &t); err != nil {
		return nil, fmt.Errorf("разбор манифеста шаблона: %w", err)
	}
	if err := checkKind(t.APIVersion, t.Kind, KindTemplate); err != nil {
		return nil, err
	}
	return &t, nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("чтение манифеста %s: %w", path, err)
	}
	return data, nil
}

// decodeStrict разбирает YAML с KnownFields(true): любое незнакомое поле — это
// ошибка с координатами строки/колонки от yaml.v3.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// checkKind проверяет kind и major-версию apiVersion. apiVersion разбирается
// первым: несовместимый major важнее любой другой ошибки — пользователь должен
// сначала обновить CLI.
func checkKind(apiVersion, kind, want string) error {
	if err := checkAPIVersion(apiVersion); err != nil {
		return err
	}
	if kind != want {
		return fmt.Errorf("ожидается kind %q, получен %q", want, kind)
	}
	return nil
}

// checkAPIVersion проверяет группу и major-версию контракта.
func checkAPIVersion(apiVersion string) error {
	if apiVersion == "" {
		return fmt.Errorf("%w: поле apiVersion пустое (ожидается %s)", ErrUnsupportedAPIVersion, APIVersion)
	}
	group, version, ok := splitAPIVersion(apiVersion)
	if !ok || group != APIGroup {
		return fmt.Errorf("%w: неизвестный apiVersion %q (ожидается группа %s)", ErrUnsupportedAPIVersion, apiVersion, APIGroup)
	}
	major, ok := parseMajor(version)
	if !ok {
		return fmt.Errorf("%w: не удалось определить major в apiVersion %q", ErrUnsupportedAPIVersion, apiVersion)
	}
	if major != SupportedMajor {
		return fmt.Errorf(
			"%w: манифест использует major v%d (%s), а этот tplater поддерживает v%d — обнови tplater",
			ErrUnsupportedAPIVersion, major, apiVersion, SupportedMajor,
		)
	}
	return nil
}

// splitAPIVersion делит "group/version" на части.
func splitAPIVersion(s string) (group, version string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// parseMajor извлекает целое major из версии вида "v1alpha1" → 1.
func parseMajor(version string) (int, bool) {
	if len(version) < 2 || version[0] != 'v' {
		return 0, false
	}
	major := 0
	digits := 0
	for i := 1; i < len(version); i++ {
		c := version[i]
		if c < '0' || c > '9' {
			break
		}
		major = major*10 + int(c-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return major, true
}
