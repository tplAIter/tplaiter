// Package repo управляет репозиториями шаблонов (helm-модель):
// добавление/удаление/обновление git-репозиториев, скан и индексация их
// манифестов, аутентификация git-операций через стор токенов и резолюция
// ссылок вида `<repo>/<name>@<version>`.
//
// Все вызовы git идут через [execx.Runner], поэтому интеграционные тесты
// используют реальный git в t.TempDir (без сети, через file://-репозитории), а
// auth-ветки покрываются моками glab/gh поверх [execx.RecordingRunner].
package repo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/execx"
	"github.com/tplAIter/tplaiter/internal/state"
	"github.com/tplAIter/tplaiter/internal/ui"
)

// aliasRe — допустимый формат алиаса репозитория: строчная буква, затем
// строчные буквы/цифры/дефис.
var aliasRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// UI — набор потоков ввода-вывода и палитра для сообщений менеджера. In
// используется для интерактивных ответов (выбор auth-варианта, ввод токена);
// Interactive сообщает, можно ли вообще задавать вопросы (обычно — TTY на
// stdin). ReadSecret, если задан, читает токен без эха (в CLI — через term); в
// тестах остаётся nil, и токен читается строкой из In.
type UI struct {
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
	Palette     ui.Palette
	Interactive bool
	ReadSecret  func(prompt string) (string, error)
}

// Manager инкапсулирует операции над реестром репозиториев шаблонов.
type Manager struct {
	home      string
	runner    execx.Runner
	authStore *auth.Store
	ui        UI
	in        *bufio.Reader

	// now — источник времени для index.GeneratedAt; переопределяется в тестах.
	now func() time.Time
}

// New создаёт менеджер. home — домашний каталог tplater (см. state.Home);
// authStore может быть nil — тогда auth-флоу для https-URL недоступен (git
// пойдёт без credential-helper'а, что подходит для публичных/file://-репо).
func New(home string, runner execx.Runner, authStore *auth.Store, u UI) *Manager {
	var r *bufio.Reader
	if u.In != nil {
		r = bufio.NewReader(u.In)
	}
	return &Manager{
		home:      home,
		runner:    runner,
		authStore: authStore,
		ui:        u,
		in:        r,
		now:       time.Now,
	}
}

// AddOptions — параметры repo add.
type AddOptions struct {
	Alias  string
	URL    string
	Branch string
	// TokenStdin — читать токен из stdin (неинтерактивный auth) вместо диалога.
	TokenStdin bool
}

// Info — строка вывода repo list: запись реестра + агрегаты из индекса.
type Info struct {
	Ref       state.RepoRef
	Templates int
	UpdatedAt time.Time
}

// reposDir возвращает путь к каталогу кеша клонов (~/.tplaiter/repos).
func (m *Manager) reposDir() string { return filepath.Join(m.home, "repos") }

// cloneDir возвращает путь к клону репозитория alias.
func (m *Manager) cloneDir(alias string) string { return filepath.Join(m.reposDir(), alias) }

// Add добавляет репозиторий: валидирует алиас, определяет тип по host,
// проводит auth-флоу (для https), клонирует с фильтром blob:none, сканирует и
// индексирует манифесты, затем атомарно пишет config.yaml и index.yaml под
// межпроцессным локом.
func (m *Manager) Add(ctx context.Context, opts AddOptions) error {
	if err := validateAlias(opts.Alias); err != nil {
		return err
	}
	if opts.URL == "" {
		return errors.New("repo: пустой URL")
	}

	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return err
	}
	if _, ok := findRepo(cfg.Repos, opts.Alias); ok {
		return fmt.Errorf("repo: алиас %q уже используется", opts.Alias)
	}

	host, _ := parseGitURL(opts.URL)
	kind := detectKind(host)

	authEnv, err := m.resolveGitAuth(ctx, opts.URL, kind, opts.TokenStdin)
	if err != nil {
		return err
	}

	dest := m.cloneDir(opts.Alias)
	// Чистим возможный остаток от прерванной попытки с тем же алиасом.
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(m.reposDir(), 0o700); err != nil {
		return fmt.Errorf("repo: создание каталога кеша: %w", err)
	}

	cloneArgs := []string{"clone", "--filter=blob:none"}
	if opts.Branch != "" {
		cloneArgs = append(cloneArgs, "--branch", opts.Branch)
	}
	cloneArgs = append(cloneArgs, opts.URL, dest)

	sp := ui.NewSpinner(m.ui.Err, m.ui.Palette)
	sp.Start("Клонирую %s → %s", opts.URL, dest)
	_, cloneErr := m.git(ctx, "", cloneArgs, authEnv)
	sp.Stop()
	if cloneErr != nil {
		_ = os.RemoveAll(dest)
		return fmt.Errorf("repo: клонирование %s: %w", opts.URL, cloneErr)
	}

	branch := opts.Branch
	if branch == "" {
		branch = m.currentBranch(ctx, dest)
	}

	// strict=true: битый манифест при add — фатальная ошибка (репо не
	// регистрируется). Отличие от update см. в комментарии scanRepo.
	entries, err := m.scanRepo(ctx, dest, branch, true)
	if err != nil {
		_ = os.RemoveAll(dest)
		return err
	}

	ref := state.RepoRef{Alias: opts.Alias, URL: opts.URL, Branch: opts.Branch, Type: kind}
	if err := state.WithLock(m.home, func() error {
		cfg, err := state.LoadConfig(m.home)
		if err != nil {
			return err
		}
		if _, ok := findRepo(cfg.Repos, opts.Alias); ok {
			return fmt.Errorf("repo: алиас %q уже используется", opts.Alias)
		}
		cfg.Repos = append(cfg.Repos, ref)
		if err := state.SaveConfig(m.home, cfg); err != nil {
			return err
		}
		return m.writeIndexEntry(opts.Alias, entries)
	}); err != nil {
		_ = os.RemoveAll(dest)
		return err
	}

	m.printf("Добавлен репозиторий %s (%s), шаблонов: %d\n", opts.Alias, kind, len(entries))
	return nil
}

// Remove удаляет репозиторий из конфига и индекса и стирает его клон.
func (m *Manager) Remove(alias string) error {
	if err := state.WithLock(m.home, func() error {
		cfg, err := state.LoadConfig(m.home)
		if err != nil {
			return err
		}
		if _, ok := findRepo(cfg.Repos, alias); !ok {
			return fmt.Errorf("repo: репозиторий %q не найден", alias)
		}
		cfg.Repos = removeRepo(cfg.Repos, alias)
		if err := state.SaveConfig(m.home, cfg); err != nil {
			return err
		}

		idx, err := m.loadIndex()
		if err != nil {
			return err
		}
		delete(idx.Repos, alias)
		idx.GeneratedAt = m.now()
		return state.SaveIndex(m.home, idx)
	}); err != nil {
		return err
	}

	if err := os.RemoveAll(m.cloneDir(alias)); err != nil {
		return fmt.Errorf("repo: удаление клона %q: %w", alias, err)
	}
	m.printf("Удалён репозиторий %s\n", alias)
	return nil
}

// Update делает git fetch --tags --force (кеш одноразовый: переехавший тег в origin не должен блокировать обновление) и переиндексацию: всех репозиториев (alias
// пустой) либо одного. В отличие от Add, битый манифест шаблона при update —
// предупреждение с пропуском шаблона (репозиторий не ломается), см. scanRepo.
func (m *Manager) Update(ctx context.Context, alias string) error {
	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return err
	}

	var targets []state.RepoRef
	if alias == "" {
		targets = cfg.Repos
	} else {
		ref, ok := findRepo(cfg.Repos, alias)
		if !ok {
			return fmt.Errorf("repo: репозиторий %q не найден", alias)
		}
		targets = []state.RepoRef{ref}
	}
	if len(targets) == 0 {
		m.printf("Нет добавленных репозиториев\n")
		return nil
	}

	for _, ref := range targets {
		dest := m.cloneDir(ref.Alias)
		if _, statErr := os.Stat(dest); statErr != nil {
			m.warnf("репозиторий %q: клон отсутствует (%s) — пропускаю; выполните `tplater repo remove/add`\n", ref.Alias, dest)
			continue
		}
		authEnv, aerr := m.resolveGitAuthQuiet(ref.URL, ref.Type)
		if aerr != nil {
			return aerr
		}
		sp := ui.NewSpinner(m.ui.Err, m.ui.Palette)
		sp.Start("Обновляю %s", ref.Alias)
		_, fetchErr := m.git(ctx, dest, []string{"fetch", "--tags", "--force", "--prune", "origin"}, authEnv)
		sp.Stop()
		if fetchErr != nil {
			return fmt.Errorf("repo: fetch %q: %w", ref.Alias, fetchErr)
		}

		branch := ref.Branch
		if branch == "" {
			branch = m.currentBranch(ctx, dest)
		}

		// fetch (выше) обновляет только remote-tracking ref origin/<branch>;
		// сам кеш-клон (рабочее дерево + локальный HEAD) без явного
		// checkout+reset остаётся на прежнем коммите, и index.yaml
		// переиндексируется по СТАРОМУ содержимому, хотя команда рапортует
		// успех и обновляет метку времени index.yaml. Синхронизируем
		// рабочее дерево с обновлённым origin/<branch>, чтобы update
		// реально подтягивал новые правки (detached HEAD — пропускаем, это
		// не наш обычный сценарий одноразового кеша).
		if branch != "HEAD" {
			if _, err := m.git(ctx, dest, []string{"checkout", branch}, authEnv); err != nil {
				return fmt.Errorf("repo: checkout %q@%s: %w", ref.Alias, branch, err)
			}
			if _, err := m.git(ctx, dest, []string{"reset", "--hard", "origin/" + branch}, authEnv); err != nil {
				return fmt.Errorf("repo: reset %q@%s: %w", ref.Alias, branch, err)
			}
		} else {
			m.warnf("репозиторий %q: detached HEAD в кеше — пропускаю fast-forward рабочего дерева, только переиндексирую\n", ref.Alias)
		}

		entries, err := m.scanRepo(ctx, dest, branch, false)
		if err != nil {
			return err
		}
		if err := state.WithLock(m.home, func() error {
			return m.writeIndexEntry(ref.Alias, entries)
		}); err != nil {
			return err
		}
		m.printf("  %s: шаблонов %d\n", ref.Alias, len(entries))
	}
	return nil
}

// List возвращает записи реестра, обогащённые числом шаблонов из индекса и
// временем последнего обновления клона (mtime каталога repos/<alias>).
func (m *Manager) List() ([]Info, error) {
	cfg, err := state.LoadConfig(m.home)
	if err != nil {
		return nil, err
	}
	idx, err := m.loadIndex()
	if err != nil {
		return nil, err
	}

	out := make([]Info, 0, len(cfg.Repos))
	for _, ref := range cfg.Repos {
		info := Info{Ref: ref, Templates: len(idx.Repos[ref.Alias])}
		if st, statErr := os.Stat(m.cloneDir(ref.Alias)); statErr == nil {
			info.UpdatedAt = st.ModTime()
		}
		out = append(out, info)
	}
	return out, nil
}

// Templates возвращает агрегированный индекс шаблонов по всем добавленным
// репозиториям (alias -> его шаблоны), в том же виде, в каком он хранится в
// index.yaml. Источник для `template list`:
// команда сама фильтрует по repo/name/labels — здесь только чтение кеша с
// той же устойчивостью к повреждённому index.yaml, что и у [Manager.List]/
// [Manager.ResolveRef] (см. [Manager.loadIndex]).
func (m *Manager) Templates() (map[string][]state.TemplateEntry, error) {
	idx, err := m.loadIndex()
	if err != nil {
		return nil, err
	}
	return idx.Repos, nil
}

// writeIndexEntry перезаписывает набор шаблонов одного репозитория в index.yaml.
// Вызывать только под state.WithLock.
func (m *Manager) writeIndexEntry(alias string, entries []state.TemplateEntry) error {
	idx, err := m.loadIndex()
	if err != nil {
		return err
	}
	if idx.Repos == nil {
		idx.Repos = map[string][]state.TemplateEntry{}
	}
	idx.Repos[alias] = entries
	idx.GeneratedAt = m.now()
	return state.SaveIndex(m.home, idx)
}

// loadIndex читает индекс, трактуя ErrIndexCorrupted как пустой кеш (индекс —
// перестраиваемый кеш): повреждённый файл не должен ломать команду.
func (m *Manager) loadIndex() (state.Index, error) {
	idx, err := state.LoadIndex(m.home)
	if err != nil {
		if isIndexCorrupted(err) {
			m.warnf("index.yaml повреждён — перестраиваю кеш\n")
			return state.NewIndex(m.now()), nil
		}
		return state.Index{}, err
	}
	return idx, nil
}

// git запускает git в каталоге dir (пустой — текущий) с дополнительным
// окружением extraEnv (обычно credential-helper из auth.HelperEnv).
func (m *Manager) git(ctx context.Context, dir string, args, extraEnv []string) (execx.Result, error) {
	return m.runner.Run(ctx, "git", args, execx.Options{Dir: dir, Env: extraEnv})
}

// CloneDir возвращает путь к кеш-клону репозитория alias
// (~/.tplaiter/repos/<alias>). Экспортирован АДДИТИВНО для internal/contribute
// (`tplater upgrade`): команда апгрейда создаёт ветку прямо в
// кеш-клоне и после push возвращает его на исходный ref, поэтому ей нужен путь
// к клону (внутренний [Manager.cloneDir] остаётся приватным для остального кода).
func (m *Manager) CloneDir(alias string) string { return m.cloneDir(alias) }

// RunGit запускает произвольную git-команду в каталоге dir с дополнительным
// окружением extraEnv (обычно credential-helper из [auth.HelperEnv] для push).
// Тонкая экспортированная обёртка над приватным [Manager.git]; добавлена
// АДДИТИВНО для internal/contribute (`tplater upgrade`), которому
// нужно вести ветку/коммит/push/format-patch в кеш-клоне тем же раннером, что и
// остальные git-операции менеджера (важно для мокабельности в тестах).
func (m *Manager) RunGit(ctx context.Context, dir string, args, extraEnv []string) (execx.Result, error) {
	return m.git(ctx, dir, args, extraEnv)
}

// currentBranch возвращает имя текущей ветки клона; при ошибке — "HEAD".
func (m *Manager) currentBranch(ctx context.Context, dir string) string {
	res, err := m.git(ctx, dir, []string{"rev-parse", "--abbrev-ref", "HEAD"}, nil)
	if err != nil {
		return "HEAD"
	}
	b := strings.TrimSpace(res.Stdout)
	if b == "" || b == "HEAD" {
		return "HEAD"
	}
	return b
}

func (m *Manager) printf(format string, a ...any) {
	if m.ui.Out != nil {
		fmt.Fprintf(m.ui.Out, format, a...)
	}
}

func (m *Manager) warnf(format string, a ...any) {
	if m.ui.Err == nil {
		return
	}
	fmt.Fprint(m.ui.Err, m.ui.Palette.Warn("предупреждение: "))
	fmt.Fprintf(m.ui.Err, format, a...)
}

// validateAlias проверяет формат алиаса (^[a-z][a-z0-9-]*$).
func validateAlias(alias string) error {
	if alias == "" {
		return errors.New("repo: пустой алиас")
	}
	if !aliasRe.MatchString(alias) {
		return fmt.Errorf("repo: некорректный алиас %q (ожидается ^[a-z][a-z0-9-]*$)", alias)
	}
	return nil
}

func findRepo(repos []state.RepoRef, alias string) (state.RepoRef, bool) {
	for _, r := range repos {
		if r.Alias == alias {
			return r, true
		}
	}
	return state.RepoRef{}, false
}

func removeRepo(repos []state.RepoRef, alias string) []state.RepoRef {
	out := repos[:0:0]
	for _, r := range repos {
		if r.Alias != alias {
			out = append(out, r)
		}
	}
	return out
}

// detectKind определяет вид хостинга по host: gitlab.* и scm.* →
// gitlab; github.* → github; иначе — обычный git.
func detectKind(host string) state.RepoKind {
	h := strings.ToLower(host)
	switch {
	case strings.HasPrefix(h, "gitlab.") || strings.HasPrefix(h, "scm."):
		return state.RepoKindGitLab
	case strings.HasPrefix(h, "github."):
		return state.RepoKindGitHub
	default:
		return state.RepoKindGit
	}
}

// parseGitURL извлекает host и нормализованный путь репозитория из git-URL:
// http(s)://host/path, ssh://[user@]host[:port]/path и scp-подобного
// [user@]host:path. Путь возвращается без ведущих/замыкающих «/» и суффикса
// ".git". Для file://-URL host пуст (kind → git, auth не требуется).
func parseGitURL(raw string) (host, repoPath string) {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return u.Hostname(), normalizeRepoPath(u.Path)
		}
		return "", normalizeRepoPath(raw)
	}
	// scp-подобная форма: [user@]host:path — двоеточие до первого «/».
	if i := strings.Index(raw, ":"); i > 0 {
		if slash := strings.Index(raw, "/"); slash == -1 || slash > i {
			hostPart := raw[:i]
			if at := strings.LastIndex(hostPart, "@"); at >= 0 {
				hostPart = hostPart[at+1:]
			}
			return hostPart, normalizeRepoPath(raw[i+1:])
		}
	}
	return "", normalizeRepoPath(raw)
}

// normalizeRepoPath приводит путь к виду хранения Credential.Repo: без ведущих/
// замыкающих «/» и без суффикса ".git".
func normalizeRepoPath(p string) string {
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	return p
}

// isHTTPURL сообщает, что URL требует http(s)-аутентификации (для ssh/file://
// credential-helper не задействуется).
func isHTTPURL(raw string) bool {
	return strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://")
}

func isIndexCorrupted(err error) bool {
	return errors.Is(err, state.ErrIndexCorrupted)
}
