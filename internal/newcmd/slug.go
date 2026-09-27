package newcmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// slugRe — допустимый формат slug проекта: строчная буква, затем
// строчные буквы/цифры/подчёркивания. Совпадает с identRe генератора и
// ограничениями Go-идентификаторов, чтобы slug годился как имя пакета/модуля.
var slugRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// slugSepRe — последовательности пробелов и дефисов, которые нормализуются в
// одиночное подчёркивание перед валидацией (: "пробелы/дефисы→_").
var slugSepRe = regexp.MustCompile(`[\s-]+`)

// Slugify нормализует человекочитаемое имя проекта в slug: приводит к нижнему
// регистру, схлопывает пробелы/дефисы в "_" и проверяет результат по [slugRe].
// Ошибка перечисляет исходное имя и полученный кандидат — чтобы пользователь
// понял, что именно не прошло валидацию.
func Slugify(name string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugSepRe.ReplaceAllString(s, "_")
	if s == "" {
		return "", errors.New("newcmd: пустое имя проекта — slug не выводится")
	}
	if !slugRe.MatchString(s) {
		return "", fmt.Errorf(
			"newcmd: имя %q даёт недопустимый slug %q (ожидается %s) — задайте имя из латиницы/цифр",
			name, s, slugRe.String(),
		)
	}
	return s, nil
}

// checkTplaterVersion проверяет требование шаблона requires.tplaiter
// против версии CLI. Dev-сборка (версия не парсится как semver —
// "dev", "(devel)" и т.п.) проходит гейт всегда: разработчик шаблона на
// незарелиженном tplaiter не должен упираться в собственное требование.
func checkTplaterVersion(constraint, cliVersion string) error {
	if strings.TrimSpace(constraint) == "" {
		return nil
	}
	ver := strings.TrimSpace(cliVersion)
	// Dev-сборки проходят гейт: "dev" (ldflags-заглушка), VCS-псевдоверсии
	// v0.0.0-<timestamp>-<sha> (go build из git-дерева) и грязные сборки +dirty.
	if ver == "dev" || strings.HasPrefix(ver, "v0.0.0-") || strings.HasSuffix(ver, "+dirty") {
		return nil
	}
	v, err := semver.NewVersion(ver)
	if err != nil {
		// Непарсимая версия — локальная dev-сборка: гейт не применяется.
		return nil //nolint:nilerr // dev-сборка сознательно проходит версия-гейт.
	}
	c, cerr := semver.NewConstraint(constraint)
	if cerr != nil {
		return fmt.Errorf("newcmd: неразбираемое требование requires.tplaiter %q: %w", constraint, cerr)
	}
	if !c.Check(v) {
		return fmt.Errorf(
			"newcmd: шаблон требует tplaiter %s, а установлена %s — обновите tplaiter (`tplaiter self-upgrade`)",
			constraint, cliVersion,
		)
	}
	return nil
}

// newUUIDv4 генерирует UUID версии 4 (случайный) для идентификатора проекта в
// .tplaiter/project.yaml. Свой генератор вместо внешней зависимости
// — формат тривиален, а тянуть google/uuid ради одного вызова незачем.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("newcmd: генерация UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // версия 4
	b[8] = (b[8] & 0x3f) | 0x80 // вариант RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
