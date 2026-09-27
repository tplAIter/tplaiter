// Package auth хранит токены доступа к репозиториям шаблонов и предоставляет
// git credential helper, через который git-операции (clone/fetch/push)
// получают эти токены per-command, не трогая глобальный git-конфиг
// (см. документацию — решение ревью владельца: токены храним).
//
// Хранилище — SQLite-файл ~/.tplaiter/tplater.db (драйвер modernc.org/sqlite,
// pure-Go без cgo), права 0600. Токен лежит plaintext локально; интеграция с
// системным keychain — задел ROADMAP. Токен НИКОГДА не должен попадать в логи
// и текст ошибок: для отображения используйте [Store.MaskedList] и [MaskToken].
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// modernc.org/sqlite регистрирует драйвер database/sql под именем "sqlite"
	// (pure-Go, без cgo) — это единственная причина импорта.
	_ "modernc.org/sqlite"

	"github.com/tplAIter/tplaiter/internal/state"
)

// dbFileName — имя файла хранилища в домашнем каталоге tplater.
const dbFileName = "tplater.db"

// dbFilePerm — права на файл БД: доступ только владельцу (в файле лежат токены).
const dbFilePerm = 0o600

// schemaVersion — текущая версия схемы БД. Инкрементируется при добавлении
// миграций в [migrate].
const schemaVersion = 1

// timeLayout — единый формат сериализации времени в БД. UTC + RFC3339 с 'Z'
// даёт лексикографически сравнимые строки (нужно для запросов по expires_at).
const timeLayout = time.RFC3339

// credColumns — порядок колонок для SELECT/сканирования (см. [scanCredential]).
//
//nolint:gosec // G101: это список имён колонок SQL, а не секрет.
const credColumns = "id, host, repo, tool, token, username, scopes, note, created_at, last_used_at, expires_at"

// Credential — запись хранилища токенов.
//
// Repo == "" означает токен уровня хоста (в БД хранится как NULL). Нулевое
// значение LastUsedAt/ExpiresAt означает NULL (время не задано).
type Credential struct {
	ID         int64
	Host       string
	Repo       string
	Tool       string // gitlab | github | git | other
	Token      string
	Username   string
	Scopes     string
	Note       string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// Store — хранилище токенов поверх database/sql + modernc.org/sqlite.
//
// ctx хранится из [Open] намеренно: методы стора (Put/Get/List/...) не
// принимают context в сигнатуре (см. документацию — API стора), а все
// database/sql-вызовы обязаны быть context-aware (линтер noctx). Контекст
// задаётся один раз на время жизни стора при открытии.
type Store struct {
	db   *sql.DB
	ctx  context.Context
	path string
}

// Open открывает (создавая при необходимости) хранилище токенов в домашнем
// каталоге tplater, применяет миграции схемы и чинит права файла до 0600.
// ctx используется для ping и миграций.
func Open(ctx context.Context) (*Store, error) {
	home, _, err := state.EnsureHome()
	if err != nil {
		return nil, fmt.Errorf("auth: домашний каталог: %w", err)
	}
	path := filepath.Join(home, dbFileName)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("auth: открытие БД: %w", err)
	}
	// Один коннект: modernc.org/sqlite + один процесс — избегаем "database is
	// locked" при конкурентных запросах внутри процесса.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: настройка БД: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: проверка БД: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Файл создаётся драйвером при первом Exec (миграции) — чиним/подтверждаем
	// права строго после этого.
	if err := os.Chmod(path, dbFilePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: права файла БД: %w", err)
	}

	return &Store{db: db, ctx: ctx, path: path}, nil
}

// Close закрывает соединение с БД.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path возвращает путь к файлу БД (для диагностики/тестов).
func (s *Store) Path() string { return s.path }

// migrate создаёт таблицу schema_version при первом запуске и применяет шаги
// миграции до [schemaVersion]. Идемпотентно.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("auth: миграция schema_version: %w", err)
	}

	var current int
	err := db.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return fmt.Errorf("auth: инициализация schema_version: %w", err)
		}
		current = 0
	case err != nil:
		return fmt.Errorf("auth: чтение schema_version: %w", err)
	}

	if current >= schemaVersion {
		return nil
	}

	if current < 1 {
		if _, err := db.ExecContext(ctx, createCredentialsTable); err != nil {
			return fmt.Errorf("auth: миграция credentials: %w", err)
		}
	}

	if _, err := db.ExecContext(ctx, `UPDATE schema_version SET version = ?`, schemaVersion); err != nil {
		return fmt.Errorf("auth: обновление schema_version: %w", err)
	}
	return nil
}

//nolint:gosec // G101: это DDL-схема таблицы, а не хардкод учётных данных.
const createCredentialsTable = `
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  repo TEXT,
  tool TEXT NOT NULL DEFAULT 'git',
  token TEXT NOT NULL,
  username TEXT,
  scopes TEXT,
  note TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  expires_at TEXT,
  UNIQUE(host, repo, tool)
)`

// Put вставляет или обновляет (upsert по host/repo/tool) запись и возвращает её
// id. Upsert выполнен вручную (SELECT + UPDATE/INSERT в транзакции), а не через
// ON CONFLICT: в SQLite NULL-значения в UNIQUE-индексе считаются различными, из-
// за чего ON CONFLICT не срабатывал бы для токенов уровня хоста (repo = NULL).
func (s *Store) Put(c Credential) (int64, error) {
	if c.Tool == "" {
		c.Tool = "git"
	}

	tx, err := s.db.BeginTx(s.ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("auth: put: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id       int64
		selQuery string
		selArgs  []any
	)
	if c.Repo == "" {
		selQuery = `SELECT id FROM credentials WHERE host = ? AND repo IS NULL AND tool = ?`
		selArgs = []any{c.Host, c.Tool}
	} else {
		selQuery = `SELECT id FROM credentials WHERE host = ? AND repo = ? AND tool = ?`
		selArgs = []any{c.Host, c.Repo, c.Tool}
	}

	err = tx.QueryRowContext(s.ctx, selQuery, selArgs...).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, insErr := tx.ExecContext(
			s.ctx,
			`INSERT INTO credentials
			  (host, repo, tool, token, username, scopes, note, created_at, last_used_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.Host, nullString(c.Repo), c.Tool, c.Token,
			nullString(c.Username), nullString(c.Scopes), nullString(c.Note),
			nowUTC(), nullTime(c.LastUsedAt), nullTime(c.ExpiresAt),
		)
		if insErr != nil {
			return 0, fmt.Errorf("auth: put: insert: %w", insErr)
		}
		id, insErr = res.LastInsertId()
		if insErr != nil {
			return 0, fmt.Errorf("auth: put: last id: %w", insErr)
		}
	case err != nil:
		return 0, fmt.Errorf("auth: put: select: %w", err)
	default:
		if _, updErr := tx.ExecContext(
			s.ctx,
			`UPDATE credentials
			   SET token = ?, username = ?, scopes = ?, note = ?, expires_at = ?
			 WHERE id = ?`,
			c.Token, nullString(c.Username), nullString(c.Scopes),
			nullString(c.Note), nullTime(c.ExpiresAt), id,
		); updErr != nil {
			return 0, fmt.Errorf("auth: put: update: %w", updErr)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("auth: put: commit: %w", err)
	}
	return id, nil
}

// Get возвращает токен для host/repo/tool с приоритетом точного repo-match над
// токеном уровня хоста (repo = NULL). found=false, если ничего не найдено.
func (s *Store) Get(host, repo, tool string) (Credential, bool, error) {
	if repo != "" {
		c, ok, err := s.queryOne(
			`SELECT `+credColumns+` FROM credentials
			  WHERE host = ? AND repo = ? AND tool = ?
			  ORDER BY last_used_at DESC, created_at DESC LIMIT 1`,
			host, repo, tool,
		)
		if err != nil || ok {
			return c, ok, err
		}
	}
	return s.queryOne(
		`SELECT `+credColumns+` FROM credentials
		  WHERE host = ? AND repo IS NULL AND tool = ?
		  ORDER BY last_used_at DESC, created_at DESC LIMIT 1`,
		host, tool,
	)
}

// findForHost ищет токен для git credential helper: приоритет repo-match над
// уровнем хоста, БЕЗ фильтра по tool (git-протоколу инструмент неизвестен).
func (s *Store) findForHost(host, repo string) (Credential, bool, error) {
	if repo != "" {
		c, ok, err := s.queryOne(
			`SELECT `+credColumns+` FROM credentials
			  WHERE host = ? AND repo = ?
			  ORDER BY last_used_at DESC, created_at DESC LIMIT 1`,
			host, repo,
		)
		if err != nil || ok {
			return c, ok, err
		}
	}
	return s.queryOne(
		`SELECT `+credColumns+` FROM credentials
		  WHERE host = ? AND repo IS NULL
		  ORDER BY last_used_at DESC, created_at DESC LIMIT 1`,
		host,
	)
}

func (s *Store) queryOne(query string, args ...any) (Credential, bool, error) {
	c, err := scanCredential(s.db.QueryRowContext(s.ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, fmt.Errorf("auth: запрос токена: %w", err)
	}
	return c, true, nil
}

// List возвращает все записи с ПОЛНЫМ токеном. Предназначен для внутреннего
// использования; для показа пользователю всегда используйте [Store.MaskedList].
func (s *Store) List() ([]Credential, error) {
	return s.list()
}

// MaskedList возвращает все записи с маскированным токеном ([MaskToken]),
// безопасно для вывода на экран/в лог.
func (s *Store) MaskedList() ([]Credential, error) {
	creds, err := s.list()
	if err != nil {
		return nil, err
	}
	for i := range creds {
		creds[i].Token = MaskToken(creds[i].Token)
	}
	return creds, nil
}

func (s *Store) list() ([]Credential, error) {
	rows, err := s.db.QueryContext(
		s.ctx,
		`SELECT `+credColumns+` FROM credentials ORDER BY host, repo, tool`,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: список токенов: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Credential
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("auth: чтение токена: %w", scanErr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: список токенов: %w", err)
	}
	return out, nil
}

// Delete удаляет запись по id.
func (s *Store) Delete(id int64) error {
	if _, err := s.db.ExecContext(s.ctx, `DELETE FROM credentials WHERE id = ?`, id); err != nil {
		return fmt.Errorf("auth: удаление токена: %w", err)
	}
	return nil
}

// TouchLastUsed проставляет last_used_at = when для записи id. Время передаётся
// аргументом (а не time.Now внутри) для тестируемости.
func (s *Store) TouchLastUsed(id int64, when time.Time) error {
	if _, err := s.db.ExecContext(
		s.ctx,
		`UPDATE credentials SET last_used_at = ? WHERE id = ?`,
		when.UTC().Format(timeLayout), id,
	); err != nil {
		return fmt.Errorf("auth: отметка использования токена: %w", err)
	}
	return nil
}

// ExpiredSoon возвращает записи, срок действия которых (expires_at) истекает не
// позднее чем через within от текущего момента. Задел под будущие
// предупреждения о ротации токенов.
func (s *Store) ExpiredSoon(within time.Duration) ([]Credential, error) {
	cutoff := time.Now().Add(within).UTC().Format(timeLayout)
	rows, err := s.db.QueryContext(
		s.ctx,
		`SELECT `+credColumns+` FROM credentials
		  WHERE expires_at IS NOT NULL AND expires_at <= ?
		  ORDER BY expires_at`, cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: истекающие токены: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Credential
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("auth: чтение токена: %w", scanErr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: истекающие токены: %w", err)
	}
	return out, nil
}

// rowScanner абстрагирует *sql.Row и *sql.Rows для общего сканирования.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredential(sc rowScanner) (Credential, error) {
	var (
		c                            Credential
		repo, username, scopes, note sql.NullString
		createdAt                    string
		lastUsed, expires            sql.NullString
	)
	if err := sc.Scan(
		&c.ID, &c.Host, &repo, &c.Tool, &c.Token,
		&username, &scopes, &note, &createdAt, &lastUsed, &expires,
	); err != nil {
		return Credential{}, err
	}
	c.Repo = repo.String
	c.Username = username.String
	c.Scopes = scopes.String
	c.Note = note.String
	c.CreatedAt = parseTime(createdAt)
	if lastUsed.Valid {
		c.LastUsedAt = parseTime(lastUsed.String)
	}
	if expires.Valid {
		c.ExpiresAt = parseTime(expires.String)
	}
	return c, nil
}

// MaskToken маскирует токен для показа: первые и последние два символа, три
// точки между ними (например, "ab...yz"). Короткие токены (<8) скрываются
// целиком, чтобы не раскрывать их значимую часть.
func MaskToken(token string) string {
	r := []rune(token)
	if len(r) == 0 {
		return ""
	}
	if len(r) < 8 {
		return "****"
	}
	return string(r[:2]) + "..." + string(r[len(r)-2:])
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(timeLayout)
}

func nowUTC() string {
	return time.Now().UTC().Format(timeLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
