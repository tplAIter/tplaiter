package auth

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// RunGitCredential реализует протокол git credential helper (см.
// `git help credential`) для операций get/store/erase. Атрибуты читаются со
// stdin (строки key=value до первой пустой строки или EOF), ответ пишется в out.
//
// Политика хранилища tplater:
//   - get   — ищем токен по host (+path при credential.useHttpPath), выводим
//     username/password. Если токен не найден — НИЧЕГО не выводим и выходим с
//     кодом 0 (штатный протокол git: helper молча «пасует», git переходит к
//     следующему helper'у или к интерактивному запросу). Мы НЕ считаем это
//     ошибкой процесса.
//   - store — git сообщает креды после успешной аутентификации. Мы лишь
//     отмечаем факт использования (TouchLastUsed) уже существующей записи и
//     НИКОГДА не создаём токен автоматически: пополнение стора — только через
//     явные `tplater auth add` / `import-*` (иначе в БД оседали бы креды,
//     введённые пользователем в git-промпте вне ведома tplater).
//   - erase — no-op с логом: токены удаляются только через `tplater auth
//     remove`, чтобы сбой аутентификации не приводил к тихой потере токена.
//
// now передаётся аргументом (для тестируемости TouchLastUsed). logw — куда
// писать диагностику (обычно stderr); токен туда не попадает.
func RunGitCredential(s *Store, op string, in io.Reader, out, logw io.Writer, now time.Time) error {
	attrs, err := parseCredentialInput(in)
	if err != nil {
		return fmt.Errorf("auth: git-credential: чтение ввода: %w", err)
	}
	host := attrs["host"]
	repo := normalizeRepoPath(attrs["path"])

	switch op {
	case "get":
		cred, found, err := s.findForHost(host, repo)
		if err != nil {
			return err
		}
		if !found {
			// Молчаливый выход 0 — git попробует другие источники.
			return nil
		}
		fmt.Fprintf(out, "username=%s\n", credentialUsername(cred))
		fmt.Fprintf(out, "password=%s\n", cred.Token)
		return nil

	case "store":
		cred, found, err := s.findForHost(host, repo)
		if err != nil {
			return err
		}
		if !found {
			fmt.Fprintln(logw, "tplater auth: store — нет сохранённого токена для этого хоста, "+
				"автоматически не создаём (используйте `tplater auth add`)")
			return nil
		}
		return s.TouchLastUsed(cred.ID, now)

	case "erase":
		fmt.Fprintln(logw, "tplater auth: erase — no-op (токены удаляются только через `tplater auth remove`)")
		return nil

	default:
		return fmt.Errorf("auth: git-credential: неизвестная операция %q", op)
	}
}

// credentialUsername возвращает имя пользователя для git. Если оно не задано в
// сторе, подставляем осмысленный дефолт под инструмент: для GitLab/GitHub при
// доступе по PAT username практически игнорируется, но git требует его наличия,
// иначе повторно запрашивает интерактивно.
func credentialUsername(c Credential) string {
	if c.Username != "" {
		return c.Username
	}
	switch c.Tool {
	case "gitlab":
		return "oauth2"
	case "github":
		return "x-access-token"
	default:
		return "git"
	}
}

// parseCredentialInput разбирает вход git credential: строки key=value до
// первой пустой строки (или EOF).
func parseCredentialInput(r io.Reader) (map[string]string, error) {
	attrs := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		attrs[key] = val
	}
	return attrs, sc.Err()
}

// normalizeRepoPath нормализует git-путь (атрибут path при useHttpPath) к виду,
// в котором хранится Credential.Repo: без ведущих/замыкающих слэшей и без
// суффикса ".git".
func normalizeRepoPath(p string) string {
	p = strings.Trim(p, "/")
	p = strings.TrimSuffix(p, ".git")
	return p
}

// HelperEnv возвращает переменные окружения (формат GIT_CONFIG_COUNT/KEY/VALUE),
// которые подключают tplater как git credential helper ТОЛЬКО для одной команды
// git — эквивалент `git -c credential.helper="!tplater auth git-credential"`,
// но без правки глобального git-конфига. Значения кладутся в
// execx.Options.Env перед запуском git (clone/fetch/push).
//
// Первый (пустой) credential.helper сбрасывает список helper'ов из
// пользовательских конфигов, второй ставит наш. Для http(s)-URL дополнительно
// включаем credential.useHttpPath, чтобы git передавал path и мы могли выбрать
// токен уровня репозитория; для ssh helper не задействуется, флаг path не нужен.
func HelperEnv(repoURL string) []string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "tplaiter"
	}
	helper := "!" + exe + " auth git-credential"

	env := []string{
		"GIT_CONFIG_KEY_0=credential.helper",
		"GIT_CONFIG_VALUE_0=",
		"GIT_CONFIG_KEY_1=credential.helper",
		"GIT_CONFIG_VALUE_1=" + helper,
	}
	count := 2
	if isHTTPURL(repoURL) {
		env = append(env,
			"GIT_CONFIG_KEY_2=credential.useHttpPath",
			"GIT_CONFIG_VALUE_2=true")
		count = 3
	}
	return append([]string{"GIT_CONFIG_COUNT=" + strconv.Itoa(count)}, env...)
}

func isHTTPURL(url string) bool {
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")
}
