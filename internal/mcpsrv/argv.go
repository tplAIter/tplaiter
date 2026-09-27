package mcpsrv

import (
	"encoding/json"
	"sort"
	"strconv"
)

// Пакет mcpsrv строит argv подкоманд tplater из аргументов MCP-tool'ов. Ключевое
// правило безопасности: аргументы всегда передаются подпроцессу отдельными
// элементами слайса — никакой конкатенации в строку и никакой shell-
// интерполяции (см. exec.go). Функции ниже — чистые: они не трогают ФС и не
// исполняют процессы, поэтому их легко покрыть табличным юнит-тестом
// (argv_test.go).

// sortedSetPairs сериализует карту группа→значение в детерминированный
// (по возрастанию ключа) слайс пар вида "--set", "group=value". Детерминизм
// важен и для тестов, и для воспроизводимости вызовов агентом.
func sortedSetPairs(set map[string]string) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		out = append(out, "--set", k+"="+set[k])
	}
	return out
}

// sortedPositionalPairs сериализует карту группа→значение в детерминированный
// слайс позиционных аргументов "group=value" (для `settings set`, который
// принимает пары позиционно, а не через флаг --set).
func sortedPositionalPairs(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+values[k])
	}
	return out
}

// sortedDynamicFlags сериализует параметры генератора в динамические cobra-
// флаги вида "--fields", "name:string". В отличие от настроек проекта,
// `tplater gen` регистрирует параметры конкретного generator прямо как флаги
// (см. cmd/gen.go), поэтому общий `--set key=value` здесь неприменим.
func sortedDynamicFlags(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		out = append(out, "--"+k, values[k])
	}
	return out
}

func argvRepoAdd(alias, url, branch string) []string {
	argv := []string{"repo", "add", alias, url}
	if branch != "" {
		argv = append(argv, "--branch", branch)
	}
	return argv
}

func argvRepoList() []string { return []string{"repo", "list"} }

func argvRepoUpdate(alias string) []string {
	argv := []string{"repo", "update"}
	if alias != "" {
		argv = append(argv, alias)
	}
	return argv
}

func argvRepoRemove(alias string) []string { return []string{"repo", "remove", alias} }

func argvTemplateList(repo, name string, labels []string) []string {
	argv := []string{"template", "list"}
	if repo != "" {
		argv = append(argv, "--repo", repo)
	}
	if name != "" {
		argv = append(argv, "--name", name)
	}
	for _, l := range labels {
		argv = append(argv, "--label", l)
	}
	return argv
}

func argvTemplateShow(ref string) []string { return []string{"template", "show", ref} }

// argvProjectNew строит argv для `tplater new`. Интерактив исключён всегда:
// подпроцессу не подключается stdin (см. exec.go), а при неполноте --set сам
// `new` вернёт ошибку про обязательные группы. --defaults форсирует дефолты.
// dir здесь НЕ используется — он становится рабочим каталогом подпроцесса
// (cwd), а проект создаётся как <dir>/<slug> (единое правило dir=cwd для всех
// tool'ов, см. tools.go).
func argvProjectNew(ref, name string, set map[string]string, defaults, noHooks, noDepsCheck, noEnvSetup, yes bool, port int) []string {
	argv := []string{"new", ref, name}
	argv = append(argv, sortedSetPairs(set)...)
	if defaults {
		argv = append(argv, "--defaults")
	}
	if noHooks {
		argv = append(argv, "--no-hooks")
	}
	if noDepsCheck {
		argv = append(argv, "--no-deps-check")
	}
	if port > 0 {
		argv = append(argv, "--port", strconv.Itoa(port))
	}
	if noEnvSetup {
		argv = append(argv, "--no-env-setup")
	}
	if yes {
		argv = append(argv, "--yes")
	}
	return argv
}

func argvRun(command string, args []string) []string {
	argv := []string{"run", command}
	if len(args) > 0 {
		argv = append(argv, "--")
		argv = append(argv, args...)
	}
	return argv
}

func argvSettingsList() []string { return []string{"settings", "list"} }

// argvSettingsSet строит argv для `settings set`. --yes обязателен: интерактив
// исключён, без него команда в неинтерактивном режиме ждала бы подтверждения.
func argvSettingsSet(values map[string]string) []string {
	pairs := sortedPositionalPairs(values)
	argv := make([]string, 0, len(pairs)+3)
	argv = append(argv, "settings", "set")
	argv = append(argv, pairs...)
	argv = append(argv, "--yes")
	return argv
}

func argvUpdate(to string, dryRun, check bool) []string {
	argv := []string{"update"}
	if to != "" {
		argv = append(argv, "--to", to)
	}
	if dryRun {
		argv = append(argv, "--dry-run")
	}
	if check {
		argv = append(argv, "--check")
	}
	return argv
}

// argvStats всегда добавляет --json — результат парсится и возвращается как
// структурированный JSON (см. handleStats в tools.go).
func argvStats() []string { return []string{"stats", "--json"} }

// argvGen строит argv для `tplater gen <kind> <name>`. params сериализуются в
// динамические флаги генератора: {"fields":"name:string"} превращается в
// `--fields name:string`. Cobra регистрирует эти флаги из params манифеста до
// разбора argv; общего флага --set у команды gen нет. noBuild пропускает
// финальный build-gate, сохраняя созданные файлы при отсутствии toolchain.
func argvGen(kind, name string, params map[string]string, noBuild bool) []string {
	pairs := sortedDynamicFlags(params)
	argv := make([]string, 0, len(pairs)+3)
	argv = append(argv, "gen", kind, name)
	argv = append(argv, pairs...)
	if noBuild {
		argv = append(argv, "--no-build")
	}
	return argv
}

// genBatchOperation — входной контракт MCP gen_batch. JSON сериализуется
// только на границе с CLI; сами значения params остаются строками до
// типизации в `tplater gen batch` по manifest.Param конкретного generator.
type genBatchOperation struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params,omitempty"`
}

func argvGenBatch(operations []genBatchOperation, noBuild bool) []string {
	// genBatchOperation состоит только из строк и map[string]string, поэтому
	// json.Marshal для этого закрытого набора типов не может завершиться
	// ошибкой.
	payload, _ := json.Marshal(operations)
	argv := []string{"gen", "batch", "--operations", string(payload)}
	if noBuild {
		argv = append(argv, "--no-build")
	}
	return argv
}

func argvGenList() []string { return []string{"gen", "list"} }

func argvWorkspaceAddService(name, module string, set map[string]string, defaults, noHooks, noDepsCheck bool, port int) []string {
	argv := []string{"workspace", "add-service", name}
	if module != "" {
		argv = append(argv, "--module", module)
	}
	argv = append(argv, sortedSetPairs(set)...)
	if defaults {
		argv = append(argv, "--defaults")
	}
	if noHooks {
		argv = append(argv, "--no-hooks")
	}
	if noDepsCheck {
		argv = append(argv, "--no-deps-check")
	}
	if port > 0 {
		argv = append(argv, "--port", strconv.Itoa(port))
	}
	// MCP не подключает stdin: исключаем предложение env setup и все
	// подтверждения делаем неинтерактивными.
	return append(argv, "--no-env-setup", "--yes")
}

// argvLintTemplate: path передаётся флагом --path (native-механизм команды),
// абсолютизируется вызывающим.
func argvLintTemplate(path, combo string) []string {
	argv := []string{"lint-template"}
	if path != "" {
		argv = append(argv, "--path", path)
	}
	if combo != "" {
		argv = append(argv, "--combo", combo)
	}
	return argv
}

// argvInitTemplate: dir (если задан) передаётся флагом --dir (native-механизм
// команды, целевой каталог создаётся ею), абсолютизируется вызывающим.
func argvInitTemplate(name, dir string, multi bool) []string {
	argv := []string{"init-template", name}
	if dir != "" {
		argv = append(argv, "--dir", dir)
	}
	if multi {
		argv = append(argv, "--multi")
	}
	return argv
}

func argvProjectsList() []string { return []string{"projects", "list"} }

func argvDoctor() []string { return []string{"doctor"} }

func argvAIGen() []string { return []string{"ai", "gen"} }

// argvEnvSetup: yes форсируется всегда (интерактив исключён), name опционален
// (по умолчанию сама команда берёт "setup").
func argvEnvSetup(name string) []string {
	argv := []string{"env", "setup"}
	if name != "" {
		argv = append(argv, name)
	}
	argv = append(argv, "--yes")
	return argv
}
