package repo

import (
	"sort"
	"strconv"
	"strings"
)

// semver — распарсенная версия vMAJOR.MINOR.PATCH. Пре-релизы (суффикс `-...`)
// считаются нестабильными и в индекс релизных тегов не попадают (:
// умолчание — «старший стабильный тег»).
type semver struct {
	major, minor, patch int
}

// parseStableSemver разбирает строку версии `vX.Y.Z` (ведущий `v` обязателен).
// Возвращает ok=false для пустого ввода, некорректного формата или пре-релиза
// (`vX.Y.Z-rc1`, `+build`) — такие теги стабильными не считаются.
func parseStableSemver(v string) (semver, bool) {
	if len(v) < 2 || v[0] != 'v' {
		return semver{}, false
	}
	core := v[1:]
	// Пре-релиз/метаданные сборки — не стабильный релиз.
	if strings.ContainsAny(core, "-+") {
		return semver{}, false
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2]}, true
}

// less сообщает, меньше ли a чем b (лексикографически по major/minor/patch).
func (a semver) less(b semver) bool {
	switch {
	case a.major != b.major:
		return a.major < b.major
	case a.minor != b.minor:
		return a.minor < b.minor
	default:
		return a.patch < b.patch
	}
}

// tagVersion — тег вместе с его распарсенной версией (для сортировки).
type tagVersion struct {
	tag     string // полный git-тег: "v1.2.0" или "name/v1.2.0"
	version string // версия-суффикс: "v1.2.0"
	ver     semver
}

// stableTagsFor фильтрует allTags, оставляя стабильные релизные теги,
// применимые к шаблону templateName в репозитории вида kind (single/multi), и
// возвращает их в полном git-виде, отсортированными по УБЫВАНИЮ версии
// (result[0] — старший стабильный тег).
//
// Правила соответствия:
//   - single: тег вида `vX.Y.Z` (без префикса);
//   - multi:  тег вида `<templateName>/vX.Y.Z`.
func stableTagsFor(allTags []string, templateName string, multi bool) []string {
	matched := make([]tagVersion, 0, len(allTags))
	prefix := templateName + "/"
	for _, tag := range allTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		var versionPart string
		if multi {
			if !strings.HasPrefix(tag, prefix) {
				continue
			}
			versionPart = strings.TrimPrefix(tag, prefix)
		} else {
			// single: только теги без «/» (иначе это чужой namespaced-тег).
			if strings.Contains(tag, "/") {
				continue
			}
			versionPart = tag
		}
		ver, ok := parseStableSemver(versionPart)
		if !ok {
			continue
		}
		matched = append(matched, tagVersion{tag: tag, version: versionPart, ver: ver})
	}

	sort.Slice(matched, func(i, j int) bool {
		// По убыванию версии; при равенстве — по имени тега для детерминизма.
		if matched[i].ver.less(matched[j].ver) {
			return false
		}
		if matched[j].ver.less(matched[i].ver) {
			return true
		}
		return matched[i].tag < matched[j].tag
	})

	out := make([]string, len(matched))
	for i, m := range matched {
		out[i] = m.tag
	}
	return out
}

// tagVersionSuffix извлекает версию-суффикс из полного git-тега относительно
// имени шаблона: `name/v1.0.0` → `v1.0.0`, `v1.0.0` → `v1.0.0`. Используется при
// сопоставлении пользовательского `@vX.Y.Z` с сохранёнными тегами.
func tagVersionSuffix(tag, templateName string) string {
	return strings.TrimPrefix(tag, templateName+"/")
}
