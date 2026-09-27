// Package gen реализует скаффолдер `tplater gen <kind> <Name>` (SPEC-01 §6):
// перенос якорной механики go-template'овского internal/gen (маркер
// идемпотентности, вставка перед якорем, backup+откат при пост-ошибке,
// пост-шаги форматирования Go и build-gate) на манифест-модель.
//
// Главное отличие от go-template: таблица видов скаффолда — НЕ go:embed
// бинарника, а поле Generators манифеста шаблона (SPEC-01 §6). Сниппеты
// (Generator.Snippet, Anchor.Insert) читаются с диска относительно
// [Options.GeneratorsDir] — каталога-копии `<источник шаблона>/<aiConfig-подобный
// путь>`, которую задача C2 кладёт в сгенерированный проект как
// .tplaiter/generators (см. [GeneratorsRelPath] — контракт для C2/C4,
// симметричный aiconfig.AIConfigRelPath).
package gen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tplAIter/tplaiter/internal/engine"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// GeneratorsRelPath — путь каталога-копии сниппетов генераторов в
// сгенерированном проекте относительно его корня (контракт с задачами
// C2/C4: `tplater new` копирует сюда каталог, на который ссылаются
// Generator.Snippet/Anchor.Insert манифеста шаблона).
const GeneratorsRelPath = ".tplaiter/generators"

// identRe — допустимый формат производного snake-имени (перенос go-template
// без изменений: gen работает преимущественно с Go-исходниками).
var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var ErrExecutionUnavailable = errors.New("TRUST_GENERATION_EXECUTION_UNAVAILABLE")

// Name — производные варианты сырого имени скаффолда, доступные шаблонам
// target/snippet/insert как `.Name.Pascal` и т.п. (перенос go-template Data,
// без встроенного Marker — маркер идемпотентности вычисляется в [Generate] и
// прокидывается только шаблонам вставки якоря, см. [Context.Marker]).
type Name struct {
	Raw    string
	Pascal string
	Camel  string
	Snake  string
	Kebab  string
}

// Context — данные, доступные шаблонам target-пути, сниппета и вставки
// якоря (SPEC-01 §6: "контекст: Name{Pascal,Snake,...} + Settings"). Project
// добавлен сверх спеки — не мешает и облегчает сниппеты, которым нужен
// module path/slug проекта.
type Context struct {
	Name     Name
	Settings settings.View
	Project  manifest.ProjectInfo
	// Marker — маркер идемпотентности вставки (`// gen:<kind>:<snake>`).
	// Заполнен только при рендере Anchor.Insert; шаблон вставки ОБЯЗАН
	// включить `{{ .Marker }}` в свой вывод — без этого повторный gen не
	// будет обнаружен как дубликат (перенос go-template: маркер живёт в
	// теле шаблона, а не навязывается движком поверх чужого вывода).
	Marker string
	// Fields — поля сущности, разобранные из параметра типа `fields` (CG-1).
	// Пусто, если генератор не объявляет такого параметра.
	Fields []Field
	// Params — значения всех параметров генератора по имени (CG-1). Тип
	// значения зависит от Param.Type: string→string, bool→bool, int→int,
	// fields→[]Field (тот же срез, что и .Fields).
	Params map[string]any
	// MigrationSeq — следующий goose-номер миграции (NNNNN) по каталогу
	// целевого файла; заполнен только при наличии таргета с numbered: goose.
	MigrationSeq string
}

// Options — параметры одного вызова [Generate].
type Options struct {
	// ProjectRoot — корень проекта: сюда пишется Target, отсюда разрешаются
	// Anchor.File.
	ProjectRoot string
	// GeneratorsDir — каталог со сниппетами (обычно
	// filepath.Join(ProjectRoot, [GeneratorsRelPath])); Snippet/Anchor.Insert
	// разрешаются относительно него.
	GeneratorsDir string
	// Values — разрешённые настройки проекта (when-гейт + `.Settings` в
	// контексте рендера).
	Values settings.Values
	// Project — координаты проекта для `.Project` в контексте рендера.
	Project manifest.ProjectInfo
	// Fields — разобранные поля сущности (из параметра типа `fields`, CG-1);
	// прокидываются в Context.Fields. Резолвится вызывающим (cmd/gen.go) через
	// [ResolveParams].
	Fields []Field
	// Params — значения параметров генератора по имени (CG-1); прокидываются в
	// Context.Params. Резолвится вызывающим через [ResolveParams].
	Params map[string]any
	// NoBuild пропускает post-generation build-gate. По умолчанию выполняется
	// commands.build.run манифеста; старые manifest без команды сохраняют
	// fallback `go build ./...`.
	NoBuild bool
	// Runner исполняет formatter/build-gate. nil → [execx.Exec]{} (реальные
	// вызовы; depguard запрещает прямой os/exec вне internal/execx).
	Runner execx.Runner
	// Logf — опциональный логгер шагов (nil → без вывода).
	Logf func(format string, args ...any)
}

// Result — итог успешной генерации.
type Result struct {
	// Kind — вид скаффолда.
	Kind string
	// CreatedFiles — относительные пути созданных файлов (Target).
	CreatedFiles []string
	// EditedFiles — относительные пути изменённых якорных файлов.
	EditedFiles []string
}

// Status — строка результата [List].
type Status struct {
	Kind        string
	Description string
	Available   bool
	// Reason — причина недоступности (непусто только при Available=false):
	// невыполненное when-условие либо ошибка его вычисления (неизвестная
	// группа).
	Reason string
}

// Lookup находит генератор kind в манифесте. Ошибка перечисляет доступные
// виды (отсортированы).
func Lookup(tpl *manifest.Template, kind string) (*manifest.Generator, error) {
	for i := range tpl.Generators {
		if tpl.Generators[i].Kind == kind {
			return &tpl.Generators[i], nil
		}
	}
	return nil, fmt.Errorf("gen: неизвестный вид %q (доступны: %s)", kind, strings.Join(kindNames(tpl), ", "))
}

// kindNames возвращает отсортированный список видов генераторов манифеста.
func kindNames(tpl *manifest.Template) []string {
	names := make([]string, 0, len(tpl.Generators))
	for i := range tpl.Generators {
		names = append(names, tpl.Generators[i].Kind)
	}
	sort.Strings(names)
	return names
}

// List возвращает статус каждого генератора манифеста при заданных values
// (для `tplater gen list`): доступен ли (see [evalGate]) и, если нет, что
// нужно включить.
func List(tpl *manifest.Template, values settings.Values) []Status {
	out := make([]Status, 0, len(tpl.Generators))
	for i := range tpl.Generators {
		g := &tpl.Generators[i]
		ok, err := evalGate(g.When, values)
		st := Status{Kind: g.Kind, Description: g.Description, Available: ok}
		if !ok {
			st.Reason = gateReason(g.When, err)
		}
		out = append(out, st)
	}
	return out
}

// evalGate вычисляет when-гейт генератора: пустой список — всегда доступен;
// иначе достаточно ИСТИННОСТИ ОДНОГО из условий списка (семантика OR — как
// у files.anyOf, см. отчёт задачи: единственное текстовое поле "when",
// которое манифест (задача A2) сделал списком строк, а не одной строкой с
// "&&" внутри — это осмысленно только как список альтернативных гейтов;
// чистая конъюнкция уже выразима одной строкой "a=1 && b=2", как везде
// иначе в §3.2).
func evalGate(when []string, values settings.Values) (bool, error) {
	if len(when) == 0 {
		return true, nil
	}
	conds := make([]manifest.Condition, 0, len(when))
	for _, w := range when {
		cond, err := manifest.ParseCondition(w)
		if err != nil {
			return false, err
		}
		conds = append(conds, cond)
	}
	return settings.EvalAny(conds, values)
}

// gateReason формирует человекочитаемую причину недоступности генератора.
func gateReason(when []string, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.Join(when, " | ")
}

// suggestSet формирует пример `--set` для сообщения об ошибке недоступного
// генератора: конъюнкции "&&" внутри одного условия становятся запятой
// (--set принимает несколько group=value через повторный флаг), альтернативы
// OR-списка перечисляются через "или".
func suggestSet(when []string) string {
	if len(when) == 0 {
		return ""
	}
	parts := make([]string, len(when))
	for i, w := range when {
		parts[i] = strings.ReplaceAll(w, "&&", ",")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + " (или: " + strings.Join(parts[1:], " | ") + ")"
}

// Generate выполняет один скаффолд kind с именем rawName (SPEC-01 §6).
//
// Порядок: when-гейт → производные имена → рендер target-пути → проверка
// отсутствия целевого файла → рендер сниппета → для каждого anchors[] —
// проверка идемпотентности (маркер) + рендер вставки + подготовка
// insertBeforeAnchor (без записи) → запись всех файлов → best-effort formatter
// только для Go-проектов → (если !NoBuild) manifest build-gate с полным откатом (созданные файлы
// удаляются, якорные файлы восстанавливаются из backup) при провале.
func Generate(ctx context.Context, tpl *manifest.Template, kind, rawName string, opts Options) (*Result, error) {
	log := opts.Logf
	if log == nil {
		log = func(string, ...any) {}
	}

	g, err := Lookup(tpl, kind)
	if err != nil {
		return nil, err
	}

	available, gateErr := evalGate(g.When, opts.Values)
	if gateErr != nil {
		return nil, fmt.Errorf("gen %s: вычисление when: %w", kind, gateErr)
	}
	if !available {
		return nil, fmt.Errorf(
			"gen %s недоступен при текущих настройках (%s) — включи настройку: tplater settings set %s",
			kind, gateReason(g.When, nil), suggestSet(g.When),
		)
	}

	gctx, err := newContext(rawName, opts.Values, opts.Project)
	if err != nil {
		return nil, fmt.Errorf("gen %s %q: %w", kind, rawName, err)
	}
	gctx.Fields = opts.Fields
	gctx.Params = opts.Params

	// Разрешаем список таргетов: одиночная форма → один таргет; мультифайл →
	// таргеты, прошедшие свой when-гейт по настройкам.
	specs, err := resolveTargets(g, opts.Values)
	if err != nil {
		return nil, fmt.Errorf("gen %s: %w", kind, err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("gen %s: при текущих настройках ни один таргет не подлежит генерации", kind)
	}

	// Номер goose-миграции (если есть таргет numbered: goose) считается ДО
	// рендера путей — он входит в шаблон целевого пути (`.MigrationSeq`).
	if err := resolveMigrationSeq(&gctx, opts.ProjectRoot, specs); err != nil {
		return nil, fmt.Errorf("gen %s: %w", kind, err)
	}

	// Рендерим все таргеты и проверяем отсутствие ВСЕХ целевых файлов ДО любой
	// записи — частичный повтор gen (часть файлов уже есть) отклоняется целиком.
	planned, err := planTargets(opts, kind, rawName, gctx, specs)
	if err != nil {
		return nil, err
	}

	anchors, err := prepareAnchors(opts, kind, gctx, g.Anchors)
	if err != nil {
		return nil, err
	}

	_ = planned
	_ = anchors
	return nil, ErrExecutionUnavailable
	/*
		createdAbs := make([]string, 0, len(planned))
		rollback := func() {
			for _, abs := range createdAbs {
				_ = os.Remove(abs)
			}
			for _, a := range anchors {
				_ = os.WriteFile(a.abs, a.original, 0o600)
			}
		}

		createdRels := make([]string, 0, len(planned))
		for _, p := range planned {
			if mkErr := os.MkdirAll(filepath.Dir(p.abs), 0o755); mkErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: mkdir: %w", kind, mkErr)
			}
			if wErr := os.WriteFile(p.abs, p.content, 0o600); wErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: запись %s: %w", kind, p.rel, wErr)
			}
			createdAbs = append(createdAbs, p.abs)
			createdRels = append(createdRels, p.rel)
			log("created %s", p.rel)
		}

		editedRels := make([]string, 0, len(anchors))
		for _, a := range anchors {
			if wErr := os.WriteFile(a.abs, a.updated, 0o600); wErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: запись %s: %w", kind, a.rel, wErr)
			}
			editedRels = append(editedRels, a.rel)
			log("edited  %s (anchor %s)", a.rel, a.anchor)
		}

		changed := append(append([]string{}, createdAbs...), anchorAbsPaths(anchors)...)
		if isGoProject(opts.ProjectRoot) {
			runPostFormat(ctx, opts, changed, log)
		}

		if !opts.NoBuild {
			gateName, out, buildErr := runBuildGate(ctx, tpl, opts)
			log("step: %s", gateName)
			if buildErr != nil {
				rollback()
				return nil, fmt.Errorf("gen %s: сгенерированный код не собирается — изменения откачены:\n%s", kind, out)
			}
		}

		return &Result{Kind: kind, CreatedFiles: createdRels, EditedFiles: editedRels}, nil
	*/
}

// plannedFile — отрендеренный, но ещё не записанный целевой файл.
type plannedFile struct {
	rel     string
	abs     string
	content []byte
}

// resolveTargets возвращает список подлежащих генерации таргетов. Для одиночной
// формы (Snippet+Target) — один таргет. Для мультифайловой (Targets[]) —
// таргеты, прошедшие свой when-гейт по настройкам (остальные пропускаются).
func resolveTargets(g *manifest.Generator, values settings.Values) ([]manifest.Target, error) {
	if len(g.Targets) == 0 {
		return []manifest.Target{{Snippet: g.Snippet, Target: g.Target}}, nil
	}
	out := make([]manifest.Target, 0, len(g.Targets))
	for i := range g.Targets {
		t := g.Targets[i]
		ok, err := evalGate(t.When, values)
		if err != nil {
			return nil, fmt.Errorf("targets[%d].when: %w", i, err)
		}
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// planTargets рендерит целевые пути и сниппеты всех таргетов и проверяет, что
// ни один целевой файл ещё не существует (идемпотентность до записи). Дубликат
// целевого пути внутри одного вызова — тоже ошибка.
func planTargets(opts Options, kind, rawName string, gctx Context, specs []manifest.Target) ([]plannedFile, error) {
	return planTargetsWithReserved(opts, kind, rawName, gctx, specs, nil)
}

// planTargetsWithReserved — вариант [planTargets] для пакетной генерации.
// reserved содержит пути, уже запланированные предыдущими операциями batch,
// поэтому коллизия обнаруживается до первой записи на диск.
func planTargetsWithReserved(opts Options, kind, rawName string, gctx Context, specs []manifest.Target, reserved map[string]struct{}) ([]plannedFile, error) {
	out := make([]plannedFile, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for i := range specs {
		t := &specs[i]
		rel, err := renderTargetPath(t.Target, gctx)
		if err != nil {
			return nil, fmt.Errorf("gen %s: targets[%d].target: %w", kind, i, err)
		}
		if seen[rel] {
			return nil, fmt.Errorf("gen %s: целевой путь %s встречается дважды", kind, rel)
		}
		seen[rel] = true
		if _, ok := reserved[rel]; ok {
			return nil, fmt.Errorf("gen %s %q: файл %s уже запланирован другой операцией batch", kind, rawName, rel)
		}

		abs := filepath.Join(opts.ProjectRoot, filepath.FromSlash(rel))
		if _, statErr := os.Stat(abs); statErr == nil {
			return nil, fmt.Errorf("gen %s %q: файл %s уже существует (уже сгенерировано)", kind, rawName, rel)
		}
		content, err := renderTemplateFile(filepath.Join(opts.GeneratorsDir, filepath.FromSlash(t.Snippet)), gctx)
		if err != nil {
			return nil, fmt.Errorf("gen %s: %w", kind, err)
		}
		out = append(out, plannedFile{rel: rel, abs: abs, content: content})
	}
	return out, nil
}

// resolveMigrationSeq вычисляет gctx.MigrationSeq, если среди таргетов есть
// numbered: goose. Каталог миграций определяется по целевому пути такого
// таргета, отрендеренному с пустым .MigrationSeq (номер входит в имя файла, не
// в каталог). Следующий номер = max(NNNNN среди существующих файлов) + 1,
// начиная с 00001, если каталога/файлов нет.
func resolveMigrationSeq(gctx *Context, root string, specs []manifest.Target) error {
	return resolveMigrationSeqWithReserved(gctx, root, specs, nil)
}

// resolveMigrationSeqWithReserved выбирает следующий номер goose-миграции с
// учётом ещё не записанных миграций пакетной генерации. Иначе две операции в
// одном batch обе увидели бы один и тот же номер на диске.
func resolveMigrationSeqWithReserved(gctx *Context, root string, specs []manifest.Target, reserved map[string]struct{}) error {
	for i := range specs {
		if specs[i].Numbered != manifest.NumberedGoose {
			continue
		}
		rendered, err := renderTargetPath(specs[i].Target, *gctx)
		if err != nil {
			return fmt.Errorf("numbered target: %w", err)
		}
		seq, err := nextMigrationSeq(root, path.Dir(rendered))
		if err != nil {
			return err
		}
		// Будущие миграции batch ещё не лежат в каталоге, поэтому nextMigrationSeq
		// их не увидит. Номер должен быть уникален в каталоге, а не только
		// полный target-путь: 00001_ride и 00001_driver — оба некорректны.
		if reserved != nil {
			maxReserved := 0
			for rel := range reserved {
				if path.Dir(rel) != path.Dir(rendered) {
					continue
				}
				m := migSeqRe.FindStringSubmatch(path.Base(rel))
				if m == nil {
					continue
				}
				n, convErr := strconv.Atoi(m[1])
				if convErr == nil && n > maxReserved {
					maxReserved = n
				}
			}
			current, convErr := strconv.Atoi(seq)
			if convErr != nil {
				return fmt.Errorf("некорректный номер миграции %q: %w", seq, convErr)
			}
			if maxReserved >= current {
				seq = fmt.Sprintf("%05d", maxReserved+1)
			}
		}
		for {
			gctx.MigrationSeq = seq
			rendered, renderErr := renderTargetPath(specs[i].Target, *gctx)
			if renderErr != nil {
				return fmt.Errorf("numbered target: %w", renderErr)
			}
			if _, used := reserved[rendered]; !used {
				break
			}
			n, convErr := strconv.Atoi(seq)
			if convErr != nil {
				return fmt.Errorf("некорректный номер миграции %q: %w", seq, convErr)
			}
			seq = fmt.Sprintf("%05d", n+1)
		}
		return nil
	}
	return nil
}

// migSeqRe выделяет числовой префикс NNNNN_ имени goose-миграции.
var migSeqRe = regexp.MustCompile(`^(\d+)_`)

// nextMigrationSeq сканирует каталог dirRel (относительно root) на файлы вида
// NNNNN_* и возвращает следующий 5-значный номер (max+1, минимум 00001).
func nextMigrationSeq(root, dirRel string) (string, error) {
	dirAbs := filepath.Join(root, filepath.FromSlash(dirRel))
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return "00001", nil
		}
		return "", fmt.Errorf("чтение каталога миграций %s: %w", dirRel, err)
	}
	maxSeq := 0
	for _, e := range entries {
		m := migSeqRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			continue
		}
		if n > maxSeq {
			maxSeq = n
		}
	}
	return fmt.Sprintf("%05d", maxSeq+1), nil
}

// pendingAnchor — подготовленная (отрендеренная, но не записанная) правка
// одного якорного файла.
type pendingAnchor struct {
	abs      string
	rel      string
	anchor   string
	original []byte
	updated  []byte
}

// prepareAnchors рендерит вставки для всех anchors[] генератора и проверяет
// идемпотентность каждой ДО какой-либо записи на диск — чтобы ошибка в
// третьем якоре не оставляла первые два частично применёнными.
func prepareAnchors(opts Options, kind string, gctx Context, specs []manifest.Anchor) ([]pendingAnchor, error) {
	return prepareAnchorsWithState(opts, kind, gctx, specs, nil)
}

// prepareAnchorsWithState подготавливает правки якорей поверх state. State
// используется batch-генерацией, чтобы несколько операций, вставляющих в
// один файл, видели вставки друг друга ещё до записи на диск.
func prepareAnchorsWithState(opts Options, kind string, gctx Context, specs []manifest.Anchor, state map[string][]byte) ([]pendingAnchor, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if state == nil {
		state = make(map[string][]byte)
	}
	out := make([]pendingAnchor, 0, len(specs))
	pendingByPath := make(map[string]int, len(specs))
	marker := fmt.Sprintf("// gen:%s:%s", kind, gctx.Name.Snake)

	for i := range specs {
		a := &specs[i]
		anchorAbs := filepath.Join(opts.ProjectRoot, filepath.FromSlash(a.File))
		orig, exists := state[anchorAbs]
		if !exists {
			var readErr error
			orig, readErr = os.ReadFile(anchorAbs)
			if readErr != nil {
				return nil, fmt.Errorf("gen %s: чтение якорного файла %s: %w", kind, a.File, readErr)
			}
		}
		if strings.Contains(string(orig), marker) {
			return nil, fmt.Errorf("gen %s %q: маркер %q уже присутствует в %s (уже сгенерировано)",
				kind, gctx.Name.Raw, marker, a.File)
		}

		insertCtx := gctx
		insertCtx.Marker = marker
		insertPath := filepath.Join(opts.GeneratorsDir, filepath.FromSlash(a.Insert))
		block, renderErr := renderTemplateFile(insertPath, insertCtx)
		if renderErr != nil {
			return nil, fmt.Errorf("gen %s: anchors[%d].insert: %w", kind, i, renderErr)
		}
		updated, insErr := insertBeforeAnchor(string(orig), a.Anchor, string(block))
		if insErr != nil {
			return nil, fmt.Errorf("gen %s: %w", kind, insErr)
		}
		updatedBytes := []byte(updated)
		state[anchorAbs] = updatedBytes
		if j, duplicate := pendingByPath[anchorAbs]; duplicate {
			out[j].updated = updatedBytes
			continue
		}
		pendingByPath[anchorAbs] = len(out)
		out = append(out, pendingAnchor{abs: anchorAbs, rel: a.File, anchor: a.Anchor, original: orig, updated: updatedBytes})
	}
	return out, nil
}

// anchorAbsPaths возвращает абсолютные пути изменённых якорных файлов.
func anchorAbsPaths(anchors []pendingAnchor) []string {
	out := make([]string, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, a.abs)
	}
	return out
}

// newContext строит [Context] из сырого имени, разрешённых настроек и
// координат проекта, проверяя производный snake на валидность
// Go-идентификатора (перенос go-template: имя становится частью Marker и
// обычно — частью Go-кода сниппета).
func newContext(rawName string, values settings.Values, project manifest.ProjectInfo) (Context, error) {
	if strings.TrimSpace(rawName) == "" {
		return Context{}, errors.New("имя скаффолда не задано")
	}
	n := Name{
		Raw:    rawName,
		Pascal: engine.Pascal(rawName),
		Camel:  engine.Camel(rawName),
		Snake:  engine.Snake(rawName),
		Kebab:  engine.Kebab(rawName),
	}
	if n.Pascal == "" || !identRe.MatchString(n.Snake) {
		return Context{}, fmt.Errorf("недопустимое имя %q (производный snake %q должен соответствовать %s)",
			rawName, n.Snake, identRe.String())
	}
	return Context{
		Name:     n,
		Settings: settings.View(values),
		Project:  project,
	}, nil
}
