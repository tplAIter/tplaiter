package stats

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/tplAIter/tplaiter/internal/manifest"
)

// Статусы файла относительно эталонного рендера.
const (
	// StatusIdentical — рабочий файл побайтово совпадает с эталоном.
	StatusIdentical = "identical"
	// StatusModified — рабочий файл отличается (есть построчная метрика).
	StatusModified = "modified"
	// StatusModifiedBinary — рабочий файл отличается, но бинарный (без
	// построчной метрики: added/removed=0, percent=0).
	StatusModifiedBinary = "modified-binary"
	// StatusDeleted — файл есть в эталоне, но отсутствует в рабочем дереве.
	StatusDeleted = "deleted"
	// StatusExtra — файл есть в рабочем дереве, но отсутствует в эталоне
	// (в drift-score НЕ входит, выводится отдельной секцией).
	StatusExtra = "extra"
)

// Классы обновляемости файла.
const (
	// ClassNone — для identical (класс не применяется).
	ClassNone = ""
	// ClassAuto — правки пользователя, которые update приведёт 3-way чисто:
	// шаблон исторически этот файл не менял.
	ClassAuto = "auto"
	// ClassConflictProne — правки в файле, который шаблон исторически менял
	// (пересечение с diff последних N тегов) — вероятен конфликт при update.
	ClassConflictProne = "conflict-prone"
	// ClassManualOnly — update НЕ приведёт к шаблону сам: удалённый эталонный
	// файл, сломанный якорь CODEGEN, правка в copyWithoutRender-артефакте.
	ClassManualOnly = "manual-only"
)

// FileStat — дрейф одного файла.
type FileStat struct {
	Path         string  `json:"path"`
	Status       string  `json:"status"`
	Class        string  `json:"class"`
	AddedLines   int     `json:"addedLines"`
	RemovedLines int     `json:"removedLines"`
	Percent      float64 `json:"percent"`
}

// Report — итог сравнения проекта с эталоном (машиночитаемая схема `--json`
// стабильна: {score, files, extras, brokenAnchors}; поля вне схемы помечены
// json:"-").
type Report struct {
	// Score — суммарный drift-score 0..100 (взвешенное среднее по файлам
	// эталона; extra не входит).
	Score int `json:"score"`
	// Files — файлы эталона (identical/modified/deleted), отсортированы по пути.
	Files []FileStat `json:"files"`
	// Extras — пути рабочих файлов, отсутствующих в эталоне (не входят в score).
	Extras []string `json:"extras"`
	// BrokenAnchors — пути файлов, где якорь CODEGEN эталона отсутствует в work.
	BrokenAnchors []string `json:"brokenAnchors"`
	// Warnings — предупреждения (например, недоступность исторической
	// эвристики); в JSON-схему не входят.
	Warnings []string `json:"-"`
	// OldVersion — версия шаблона проекта (для заголовка текстового отчёта).
	OldVersion string `json:"-"`
}

// AnalyzeInput — чистый вход [Analyze]: результат рендера эталона плюс
// исторический контекст. Отделён от [Collect], чтобы анализ тестировался без
// git (монотонность score, классификация, JSON-схема).
type AnalyzeInput struct {
	// RefFiles — эталонный рендер: относительный slash-путь → содержимое.
	RefFiles map[string][]byte
	// WorkDir — корень рабочего дерева проекта.
	WorkDir string
	// CopyGlobs — engine.copyWithoutRender шаблона (файлы под ними manual-only).
	CopyGlobs []string
	// Generators — генераторы манифеста (источник якорей CODEGEN).
	Generators []manifest.Generator
	// Churn — множество эталонных путей, которые шаблон менял между последними
	// N тегами (историческая эвристика conflict-prone).
	Churn map[string]struct{}
	// HistAvailable — доступна ли историческая эвристика (>=2 тегов). При false
	// все modified классифицируются как auto.
	HistAvailable bool
}

// stdExcludes — каталоги, исключаемые из обхода рабочего дерева: служебный
// .tplaiter/ (baseline/снимок/реестр не входят в эталон) и .git/.
var stdExcludes = map[string]struct{}{
	".tplaiter": {},
	".git":      {},
}

// Analyze сравнивает эталонный рендер с рабочим деревом и строит отчёт дрейфа
//. Чистая функция над готовыми входами.
func Analyze(in AnalyzeInput) (*Report, error) {
	copyMatcher := newGlobMatcher(in.CopyGlobs)

	broken, err := brokenAnchors(in.RefFiles, in.WorkDir, in.Generators)
	if err != nil {
		return nil, err
	}

	workExtras, err := walkExtras(in.WorkDir, in.RefFiles)
	if err != nil {
		return nil, err
	}

	files := make([]FileStat, 0, len(in.RefFiles))
	refPaths := sortedRefPaths(in.RefFiles)
	for _, rel := range refPaths {
		refContent := in.RefFiles[rel]
		workContent, exists, rerr := readWork(in.WorkDir, rel)
		if rerr != nil {
			return nil, rerr
		}
		files = append(files, classify(rel, refContent, workContent, exists, classifyCtx{
			copyMatcher:   copyMatcher,
			broken:        broken,
			churn:         in.Churn,
			histAvailable: in.HistAvailable,
		}))
	}

	rep := &Report{
		Files:         files,
		Extras:        workExtras,
		BrokenAnchors: sortedKeys(broken),
	}
	rep.Score = int(math.Round(averageScore(files)))
	return rep, nil
}

// classifyCtx — контекст классификации одного файла.
type classifyCtx struct {
	copyMatcher   *globMatcher
	broken        map[string]struct{}
	churn         map[string]struct{}
	histAvailable bool
}

// classify вычисляет статус, класс и метрику одного эталонного файла.
func classify(rel string, refContent, workContent []byte, exists bool, ctx classifyCtx) FileStat {
	fsStat := FileStat{Path: rel}

	if !exists {
		fsStat.Status = StatusDeleted
		fsStat.Class = ClassManualOnly
		return fsStat
	}
	if bytes.Equal(refContent, workContent) {
		fsStat.Status = StatusIdentical
		fsStat.Class = ClassNone
		return fsStat
	}

	// Файл изменён. Метрика — только для текстовых файлов.
	if isBinary(refContent) || isBinary(workContent) {
		fsStat.Status = StatusModifiedBinary
	} else {
		fsStat.Status = StatusModified
		added, removed, percent := lineMetric(refContent, workContent)
		fsStat.AddedLines = added
		fsStat.RemovedLines = removed
		fsStat.Percent = roundPct(percent)
	}

	fsStat.Class = classifyModified(rel, ctx)
	return fsStat
}

// classifyModified определяет класс обновляемости изменённого файла.
func classifyModified(rel string, ctx classifyCtx) string {
	if _, ok := ctx.broken[rel]; ok {
		return ClassManualOnly
	}
	if ctx.copyMatcher.match(rel) {
		return ClassManualOnly
	}
	if !ctx.histAvailable {
		// Историческая эвристика недоступна (<2 тегов) — все правки auto.
		return ClassAuto
	}
	if _, ok := ctx.churn[rel]; ok {
		return ClassConflictProne
	}
	return ClassAuto
}

// scoreFor — вклад файла в drift-score: identical=0; deleted и
// прочие manual-only=100 за файл; modified auto=%*0.5, conflict-prone=%*1.0.
// Для modified-binary % не измерим — берётся 100 как база (файл считается
// полностью дрейфующим).
func scoreFor(f FileStat) float64 {
	switch f.Status {
	case StatusIdentical, StatusExtra:
		return 0
	case StatusDeleted:
		return 100
	}
	if f.Class == ClassManualOnly {
		return 100
	}
	base := f.Percent
	if f.Status == StatusModifiedBinary {
		base = 100
	}
	if f.Class == ClassConflictProne {
		return base * 1.0
	}
	return base * 0.5
}

// averageScore — среднее scoreFor по файлам эталона (extra исключены Analyze,
// сюда не попадают). Пустой список → 0.
func averageScore(files []FileStat) float64 {
	if len(files) == 0 {
		return 0
	}
	var sum float64
	for _, f := range files {
		sum += scoreFor(f)
	}
	return sum / float64(len(files))
}

// brokenAnchors собирает пути файлов, где якорь CODEGEN эталона (Generator.
// Anchors[].Anchor в файле Anchors[].File) отсутствует в рабочем файле. Учитывает
// только якоря, реально присутствующие в эталоне (файл сгенерирован и якорь в
// нём есть) — иначе якорь для этой конфигурации не ожидается.
func brokenAnchors(refFiles map[string][]byte, workDir string, gens []manifest.Generator) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	for i := range gens {
		for _, a := range gens[i].Anchors {
			if a.File == "" || a.Anchor == "" {
				continue
			}
			refContent, ok := refFiles[a.File]
			if !ok || !bytes.Contains(refContent, []byte(a.Anchor)) {
				continue // якорь не ожидается в этой конфигурации.
			}
			workContent, exists, err := readWork(workDir, a.File)
			if err != nil {
				return nil, err
			}
			if !exists || !bytes.Contains(workContent, []byte(a.Anchor)) {
				out[a.File] = struct{}{}
			}
		}
	}
	return out, nil
}

// walkExtras обходит рабочее дерево (исключая .tplaiter/ и .git/) и возвращает
// отсортированные slash-пути файлов, отсутствующих в эталоне.
func walkExtras(workDir string, refFiles map[string][]byte) ([]string, error) {
	var extras []string
	root := filepath.Clean(workDir)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := stdExcludes[d.Name()]; skip && path != root {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		slash := filepath.ToSlash(rel)
		if _, ok := refFiles[slash]; !ok {
			extras = append(extras, slash)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("stats: обход рабочего дерева: %w", err)
	}
	sort.Strings(extras)
	return extras, nil
}

// readWork читает файл рабочего дерева по slash-пути rel.
func readWork(workDir, rel string) ([]byte, bool, error) {
	full := filepath.Join(workDir, filepath.FromSlash(rel))
	data, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stats: чтение %s: %w", rel, err)
	}
	return data, true, nil
}

// isBinary эвристически определяет бинарный файл наличием NUL-байта в первых
// 8000 байтах (та же эвристика, что у git). Пустой файл — не бинарный.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// roundPct округляет процент до 2 знаков для стабильного JSON.
func roundPct(p float64) float64 {
	return math.Round(p*100) / 100
}

func sortedRefPaths(refFiles map[string][]byte) []string {
	out := make([]string, 0, len(refFiles))
	for k := range refFiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
