// Package auth stores access tokens for template repositories and provides a
// git credential helper through which git operations (clone/fetch/push) obtain
// tokens per command without touching the global git config (see the docs; the
// owner review decision is to store tokens).
//
// The store is the SQLite file ~/.tplaiter/tplater.db (modernc.org/sqlite,
// pure Go without cgo), with mode 0600. Tokens are stored locally in plaintext;
// system keychain integration is on the ROADMAP. Tokens must NEVER appear in
// logs or error text: use [Store.MaskedList] and [MaskToken] for display.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// modernc.org/sqlite registers the database/sql driver as "sqlite" (pure Go,
	// without cgo); this is the sole reason for the import.
	_ "modernc.org/sqlite"

	"github.com/tplAIter/tplaiter/internal/state"
)

// dbFileName — store file name in the tplater home directory.
const dbFileName = "tplater.db"

// dbFilePerm — database file mode: owner access only (the file contains tokens).
const dbFilePerm = 0o600

// schemaVersion — current database schema version. Incremented when migrations
// are added to [migrate].
const schemaVersion = 1

// timeLayout — common time serialization format in the database. UTC + RFC3339
// with 'Z' produces lexicographically comparable strings (needed for expires_at queries).
const timeLayout = time.RFC3339

// credColumns — column order for SELECT/scanning (see [scanCredential]).
//
//nolint:gosec // G101: this is a list of SQL column names, not a secret.
const credColumns = "id, host, repo, tool, token, username, scopes, note, created_at, last_used_at, expires_at"

// Credential — token store entry.
//
// Repo == "" means a host-level token (stored as NULL in the database). A zero
// LastUsedAt/ExpiresAt value means NULL (time not set).
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

// Store — token store backed by database/sql + modernc.org/sqlite.
//
// ctx is intentionally retained from [Open]: store methods (Put/Get/List/...) do
// not accept context in their signatures (see the store API docs), while all
// database/sql calls must be context-aware (noctx linter). The context is set
// once for the store lifetime at opening.
type Store struct {
	db   *sql.DB
	ctx  context.Context
	path string
}

// Open opens (creating as needed) the token store in the tplater home directory,
// applies schema migrations, and fixes the file mode to 0600. ctx is used for
// ping and migrations.
func Open(ctx context.Context) (*Store, error) {
	home, _, err := state.EnsureHome()
	if err != nil {
		return nil, fmt.Errorf("auth: home directory: %w", err)
	}
	path := filepath.Join(home, dbFileName)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("auth: opening database: %w", err)
	}
	// One connection: modernc.org/sqlite plus one process avoids "database is
	// locked" during concurrent requests within the process.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: database configuration: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: database check: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	// The driver creates the file on the first Exec (migrations); fix/confirm the
	// mode strictly after that.
	if err := os.Chmod(path, dbFilePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: database file permissions: %w", err)
	}

	return &Store{db: db, ctx: ctx, path: path}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the database file path (for diagnostics/tests).
func (s *Store) Path() string { return s.path }

// migrate creates the schema_version table on first run and applies migration
// steps through [schemaVersion]. It is idempotent.
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("auth: schema_version migration: %w", err)
	}

	var current int
	err := db.QueryRowContext(ctx, `SELECT version FROM schema_version LIMIT 1`).Scan(&current)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return fmt.Errorf("auth: schema_version initialization: %w", err)
		}
		current = 0
	case err != nil:
		return fmt.Errorf("auth: reading schema_version: %w", err)
	}

	if current >= schemaVersion {
		return nil
	}

	if current < 1 {
		if _, err := db.ExecContext(ctx, createCredentialsTable); err != nil {
			return fmt.Errorf("auth: credentials migration: %w", err)
		}
	}

	if _, err := db.ExecContext(ctx, `UPDATE schema_version SET version = ?`, schemaVersion); err != nil {
		return fmt.Errorf("auth: updating schema_version: %w", err)
	}
	return nil
}

//nolint:gosec // G101: this is a table DDL schema, not hardcoded credentials.
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

// Put inserts or updates (upsert by host/repo/tool) an entry and returns its ID.
// The upsert is manual (SELECT + UPDATE/INSERT in a transaction), rather than
// ON CONFLICT: SQLite treats NULL values in a UNIQUE index as distinct, so
// ON CONFLICT would not work for host-level tokens (repo = NULL).
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

// Get returns the token for host/repo/tool, preferring an exact repo match over
// the host-level token (repo = NULL). found=false when nothing is found.
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

// findForHost looks up a token for the git credential helper: repo match takes
// priority over host level, with NO tool filter (the git protocol does not identify the tool).
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
		return Credential{}, false, fmt.Errorf("auth: token query: %w", err)
	}
	return c, true, nil
}

// List returns all entries with the FULL token. It is for internal use; always
// use [Store.MaskedList] to show entries to a user.
func (s *Store) List() ([]Credential, error) {
	return s.list()
}

// MaskedList returns all entries with masked tokens ([MaskToken]), safe for
// display on screen or in logs.
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
		return nil, fmt.Errorf("auth: token list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Credential
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("auth: reading token: %w", scanErr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: token list: %w", err)
	}
	return out, nil
}

// Delete removes an entry by ID.
func (s *Store) Delete(id int64) error {
	if _, err := s.db.ExecContext(s.ctx, `DELETE FROM credentials WHERE id = ?`, id); err != nil {
		return fmt.Errorf("auth: token deletion: %w", err)
	}
	return nil
}

// TouchLastUsed sets last_used_at = when for entry ID. The time is passed as an
// argument (rather than calling time.Now internally) for testability.
func (s *Store) TouchLastUsed(id int64, when time.Time) error {
	if _, err := s.db.ExecContext(
		s.ctx,
		`UPDATE credentials SET last_used_at = ? WHERE id = ?`,
		when.UTC().Format(timeLayout), id,
	); err != nil {
		return fmt.Errorf("auth: token usage marking: %w", err)
	}
	return nil
}

// ExpiredSoon returns entries whose validity (expires_at) expires no later than
// within from now. This supports future token rotation warnings.
func (s *Store) ExpiredSoon(within time.Duration) ([]Credential, error) {
	cutoff := time.Now().Add(within).UTC().Format(timeLayout)
	rows, err := s.db.QueryContext(
		s.ctx,
		`SELECT `+credColumns+` FROM credentials
		  WHERE expires_at IS NOT NULL AND expires_at <= ?
		  ORDER BY expires_at`, cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: expiring tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Credential
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("auth: reading token: %w", scanErr)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: expiring tokens: %w", err)
	}
	return out, nil
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scanning.
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

// MaskToken masks a token for display: the first and last two characters with
// three dots between them (for example, "ab...yz"). Short tokens (<8) are
// hidden entirely so no meaningful part is disclosed.
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
