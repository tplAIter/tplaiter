package project

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/repo"
)

// ErrSourceUnavailable — сигнал от [ManifestSource.Load], что у этого
// источника попросту нет манифеста для проекта (например, снимок ещё не
// сохранён либо кеш репозитория не выкачан) — это не ошибка, а команда
// вызывающему попробовать следующий источник в цепочке. Отличать от прочих
// ошибок (испорченный YAML, ошибка файловой системы) важно: последние нужно
// вернуть пользователю как есть, не маскируя их переходом к фоллбеку.
var ErrSourceUnavailable = errors.New("источник манифеста недоступен")

// ErrNoManifest возвращается [LoadManifestForProject], когда ни один
// источник в цепочке не смог отдать манифест.
var ErrNoManifest = errors.New("нет ни кеша шаблона, ни снимка манифеста — запусти tplater update")

// ManifestSource — один способ разрешить манифест шаблона для проекта на
// зафиксированной версии. Реализации: [repoSource] (приоритетный источник —
// checkout репозитория шаблона из кеша ~/.tplaiter/repos/<repo>/... на
// зафиксированный ref) и [SnapshotSource] (офлайн-фоллбек, снимок из
// .tplaiter/manifest.snapshot.yaml).
type ManifestSource interface {
	// Name — метка источника для отчёта вызывающему ("snapshot"|"repo").
	Name() string
	// Load разрешает манифест для proj. Возвращает [ErrSourceUnavailable],
	// если у источника попросту нечего предложить (не ошибка — сигнал
	// "пропусти меня, попробуй следующий источник").
	Load(proj *manifest.Project) (*manifest.Template, error)
}

// SnapshotSource читает манифест из .tplaiter/manifest.snapshot.yaml в корне
// проекта Root — снимок, который `tplater new`/`update`
// сохраняют на месте, чтобы `run`/`gen` работали офлайн и при недоступном
// репозитории шаблона.
type SnapshotSource struct {
	Root string
}

// Name реализует [ManifestSource].
func (SnapshotSource) Name() string { return "snapshot" }

// Load реализует [ManifestSource]. proj не используется: снимок уже
// привязан к конкретному проекту самим своим расположением внутри Root.
func (s SnapshotSource) Load(_ *manifest.Project) (*manifest.Template, error) {
	path := filepath.Join(s.Root, manifest.SnapshotRelPath)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSourceUnavailable
		}
		return nil, fmt.Errorf("project: проверка снимка манифеста %s: %w", path, err)
	}

	tpl, err := manifest.LoadSnapshot(path)
	if err != nil {
		return nil, fmt.Errorf("project: загрузка снимка манифеста %s: %w", path, err)
	}
	return tpl, nil
}

// templateManifestFileName — имя манифеста шаблона в корне checkout'а (та же
// приватная константа, что в internal/repo/scan.go и internal/renderref).
const templateManifestFileName = "template.manifest.yaml"

// repoSource — приоритетный источник манифеста: чтение из кеша репозитория
// шаблона (~/.tplaiter/repos/<repo>/...) на версии, зафиксированной в
// proj.Template.Version. Через [repo.Manager] резолвит ссылку
// `<repo>/<name>@<version>` в git-ref, делает checkout нужного
// ref в отдельный worktree локального клона (сеть/токены не нужны — операция
// чисто локальная) и разбирает template.manifest.yaml. Так `run`/`env`/`gen`
// начинают работать без снимка, пока жив кеш репозитория.
//
// Любая неготовность кеша (репозиторий не добавлен, версии нет в индексе, клон
// отсутствует, манифест не разобрался) трактуется как [ErrSourceUnavailable] —
// это priority-but-optional источник, надёжный фоллбек — [SnapshotSource].
type repoSource struct {
	home string
	repo string
}

// Name реализует [ManifestSource].
func (repoSource) Name() string { return "repo" }

// Load реализует [ManifestSource]: резолвит и выкачивает манифест шаблона из
// кеша репозитория на зафиксированной версии. Возвращает [ErrSourceUnavailable]
// при любой неготовности кеша (см. [repoSource]).
func (s repoSource) Load(proj *manifest.Project) (*manifest.Template, error) {
	if s.repo == "" || proj.Template.Name == "" || proj.Template.Version == "" {
		return nil, ErrSourceUnavailable
	}
	// Локальный менеджер: реальный git-runner, без стора токенов и UI — checkout
	// worktree'а существующего клона не требует ни сети, ни аутентификации.
	mgr := repo.New(s.home, execx.Exec{}, nil, repo.UI{})

	ref := s.repo + "/" + proj.Template.Name + "@" + proj.Template.Version
	resolved, err := mgr.ResolveRef(ref)
	if err != nil {
		// Неготовность кеша (репо не добавлен, версии нет в индексе) — сигнал
		// фоллбека на снимок, не ошибка процесса.
		return nil, ErrSourceUnavailable
	}

	ctx := context.Background()
	src, cleanup, err := mgr.Checkout(ctx, resolved.RepoAlias, resolved.GitRef, resolved.Entry.Path)
	if err != nil {
		return nil, ErrSourceUnavailable // клон/ref недоступны — фоллбек на снимок.
	}
	defer func() { _ = cleanup() }()

	data, err := fs.ReadFile(src, templateManifestFileName)
	if err != nil {
		return nil, ErrSourceUnavailable // манифест не прочитан — фоллбек.
	}
	tpl, err := manifest.ParseTemplate(data)
	if err != nil {
		return nil, ErrSourceUnavailable // манифест не разобран — фоллбек.
	}
	return tpl, nil
}

// LoadManifestForProject разрешает манифест шаблона для проекта proj,
// корень которого — root, перебирая источники в порядке приоритета:
// репо-кеш ([repoSource]) → снимок ([SnapshotSource]).
// Возвращает манифест, метку сработавшего источника
// ("snapshot"|"repo") и ошибку. Если ни один источник не смог отдать
// манифест — [ErrNoManifest]; любая иная ошибка источника (испорченный
// снимок и т.п.) возвращается как есть, без попытки следующего источника.
func LoadManifestForProject(root string, proj *manifest.Project, home string) (*manifest.Template, string, error) {
	sources := []ManifestSource{
		repoSource{home: home, repo: proj.Template.Repo},
		SnapshotSource{Root: root},
	}

	for _, src := range sources {
		tpl, err := src.Load(proj)
		switch {
		case err == nil:
			return tpl, src.Name(), nil
		case errors.Is(err, ErrSourceUnavailable):
			continue
		default:
			return nil, "", err
		}
	}

	return nil, "", ErrNoManifest
}
