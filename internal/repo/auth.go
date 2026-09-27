package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tplAIter/tplaiter/internal/auth"
	"github.com/tplAIter/tplaiter/internal/state"
)

// toolForKind сопоставляет вид репозитория инструменту auth (колонка tool в
// сторе; для самого git-credential-протокола инструмент не важен — findForHost
// его игнорирует, — но он нужен для показа и для выбора glab/gh).
func toolForKind(kind state.RepoKind) string {
	switch kind {
	case state.RepoKindGitLab:
		return "gitlab"
	case state.RepoKindGitHub:
		return "github"
	default:
		return "git"
	}
}

// resolveGitAuth готовит окружение git-операций для repo add.
//
// Для не-http(s) URL (ssh, file://) credential-helper не нужен — возвращает nil.
// Для http(s): если токен для host уже в сторе — сразу возвращает helper-env
// (auth.HelperEnv). Иначе — auth-флоу:
//   - tokenStdin: читаем токен из stdin, сохраняем, возвращаем helper-env;
//   - неинтерактивный режим (нет TTY и не stdin): пропускаем (git пойдёт без
//     наших кредов — подходит для публичных репозиториев);
//   - интерактивный: предлагаем (t) ввести токен, (g) импорт из glab/gh,
//     (s) пропустить.
func (m *Manager) resolveGitAuth(ctx context.Context, repoURL string, kind state.RepoKind, tokenStdin bool) ([]string, error) {
	if !isHTTPURL(repoURL) {
		return nil, nil
	}
	host, repoPath := parseGitURL(repoURL)
	tool := toolForKind(kind)

	if m.authStore != nil {
		if _, found, err := m.authStore.Get(host, repoPath, tool); err != nil {
			return nil, err
		} else if found {
			return auth.HelperEnv(repoURL), nil
		}
	}

	if tokenStdin {
		return m.storeTokenFromReader(host, tool, repoURL)
	}
	if !m.ui.Interactive {
		m.warnf("токен для %s не найден, продолжаю без аутентификации (для приватного репозитория добавьте токен: `tplater auth add %s`)\n", host, host)
		return nil, nil
	}
	return m.interactiveAuth(ctx, repoURL, host, kind, tool)
}

// resolveGitAuthQuiet — auth для repo update (без диалогов): использует токен из
// стора, если он есть; иначе идёт без кредов (для приватного репо fetch упадёт с
// внятной ошибкой git — пользователь сделает `auth add`).
func (m *Manager) resolveGitAuthQuiet(repoURL string, kind state.RepoKind) ([]string, error) {
	if !isHTTPURL(repoURL) || m.authStore == nil {
		return nil, nil
	}
	host, repoPath := parseGitURL(repoURL)
	if _, found, err := m.authStore.Get(host, repoPath, toolForKind(kind)); err != nil {
		return nil, err
	} else if found {
		return auth.HelperEnv(repoURL), nil
	}
	return nil, nil
}

// interactiveAuth ведёт диалог выбора способа аутентификации. Полноценный
// интерактив (huh/скрытый ввод) — реализация ; здесь текстовые подсказки и чтение
// строки из ui.In (для токена — через ui.ReadSecret, если задан).
func (m *Manager) interactiveAuth(ctx context.Context, repoURL, host string, kind state.RepoKind, tool string) ([]string, error) {
	if m.authStore == nil {
		m.warnf("хранилище токенов недоступно — продолжаю без аутентификации\n")
		return nil, nil
	}
	bin, importable := importBinFor(kind)

	m.printf("Токен для %s не найден. Выберите способ аутентификации:\n", host)
	m.printf("  [t] ввести токен вручную\n")
	if importable {
		m.printf("  [g] войти и импортировать токен через %s\n", bin)
	}
	m.printf("  [s] пропустить (без аутентификации)\n")
	m.printf("Выбор [t/%ss]: ", pick(importable, "g/", ""))

	choice, err := m.readLine()
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "t", "":
		return m.storeTokenInteractive(host, tool, repoURL)
	case "g":
		if !importable {
			m.warnf("импорт через glab/gh недоступен для этого хоста — введите токен вручную\n")
			return m.storeTokenInteractive(host, tool, repoURL)
		}
		return m.importAndStore(ctx, bin, tool, host, repoURL)
	case "s":
		m.warnf("продолжаю без аутентификации\n")
		return nil, nil
	default:
		return nil, fmt.Errorf("repo: неизвестный выбор %q", choice)
	}
}

// importBinFor возвращает бинарник импорта токена для вида репозитория.
func importBinFor(kind state.RepoKind) (bin string, ok bool) {
	switch kind {
	case state.RepoKindGitLab:
		return "glab", true
	case state.RepoKindGitHub:
		return "gh", true
	default:
		return "", false
	}
}

// importAndStore импортирует токен через glab/gh (auth.ImportFromTool) и, при
// успехе, возвращает helper-env. Отсутствие бинарника/логина даёт понятную
// ошибку с рецептом (её порождает auth.ImportFromTool).
func (m *Manager) importAndStore(ctx context.Context, bin, tool, host, repoURL string) ([]string, error) {
	m.printf("Пробую импортировать токен через `%s auth token`…\n", bin)
	if _, err := auth.ImportFromTool(ctx, m.authStore, m.runner, bin, tool, host); err != nil {
		return nil, err
	}
	m.printf("Токен импортирован из %s и сохранён для %s\n", bin, host)
	return auth.HelperEnv(repoURL), nil
}

// storeTokenInteractive запрашивает токен (скрытый ввод, если задан ReadSecret)
// и сохраняет его на уровне хоста.
func (m *Manager) storeTokenInteractive(host, tool, repoURL string) ([]string, error) {
	hint := tokenHint(tool)
	if hint != "" {
		m.printf("%s\n", hint)
	}
	var (
		token string
		err   error
	)
	if m.ui.ReadSecret != nil {
		token, err = m.ui.ReadSecret("Токен: ")
	} else {
		m.printf("Токен: ")
		token, err = m.readLine()
	}
	if err != nil {
		return nil, err
	}
	return m.putToken(host, tool, repoURL, strings.TrimSpace(token))
}

// storeTokenFromReader читает токен из ui.In целиком (режим --token-stdin).
func (m *Manager) storeTokenFromReader(host, tool, repoURL string) ([]string, error) {
	if m.ui.In == nil {
		return nil, errors.New("repo: --token-stdin задан, но stdin не подключён")
	}
	data, err := io.ReadAll(m.in)
	if err != nil {
		return nil, fmt.Errorf("repo: чтение токена из stdin: %w", err)
	}
	return m.putToken(host, tool, repoURL, strings.TrimSpace(string(data)))
}

func (m *Manager) putToken(host, tool, repoURL, token string) ([]string, error) {
	if token == "" {
		return nil, errors.New("repo: пустой токен")
	}
	if _, err := m.authStore.Put(auth.Credential{
		Host:  host,
		Tool:  tool,
		Token: token,
		Note:  "добавлен при `repo add`",
	}); err != nil {
		return nil, err
	}
	m.printf("Токен сохранён для %s\n", host)
	return auth.HelperEnv(repoURL), nil
}

// readLine читает одну строку из ui.In (без завершающего перевода строки).
func (m *Manager) readLine() (string, error) {
	if m.in == nil {
		return "", errors.New("repo: ввод недоступен (stdin не подключён)")
	}
	line, err := m.in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("repo: чтение ввода: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// tokenHint подсказывает, где выпустить токен и какие scopes нужны.
func tokenHint(tool string) string {
	switch tool {
	case "gitlab":
		return "Выпустите Personal Access Token в GitLab (Settings → Access Tokens), scope: read_repository."
	case "github":
		return "Выпустите Personal Access Token в GitHub (Settings → Developer settings → Tokens), scope: repo (read)."
	default:
		return ""
	}
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
