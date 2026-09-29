//go:build darwin || linux

package trustload

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

func TestReadStoreRecoveryStateUsesFixedHealthTuple(t *testing.T) {
	fixture, _ := newCrashFixture(t)
	defer func() {
		if err := closeCrashFixture(fixture); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()

	ctx := context.Background()
	first, err := readStoreRecoveryState(ctx, fixture.binding)
	if err != nil {
		t.Fatalf("read recovery state: %v", err)
	}
	second, err := readStoreRecoveryState(ctx, fixture.binding)
	if err != nil {
		t.Fatalf("repeat recovery state: %v", err)
	}
	if first != second {
		t.Fatalf("health tuple changed between reads: first=%+v second=%+v", first, second)
	}
	expected := storeRecoveryState{
		schemaVersion:    2,
		userVersion:      0,
		applicationID:    0,
		pageSize:         4096,
		pageCount:        7,
		freelistCount:    0,
		schemaEntryCount: 2,
	}
	if first != expected {
		t.Fatalf("health tuple=%+v want=%+v", first, expected)
	}
}

func TestReadStoreRecoveryStateRejectsFixedHealthFailures(t *testing.T) {
	cases := []struct {
		name  string
		phase string
	}{
		{name: "query-only-set", phase: storeRecoveryHealthQueryOnlySet},
		{name: "query-only-readback", phase: storeRecoveryHealthQueryOnlyReadback},
		{name: "schema-version", phase: "query:0"},
		{name: "user-version", phase: "query:1"},
		{name: "application-id", phase: "query:2"},
		{name: "page-size", phase: "query:3"},
		{name: "page-count", phase: "query:4"},
		{name: "freelist-count", phase: "query:5"},
		{name: "schema-entry-count", phase: "query:6"},
		{name: "integrity", phase: "integrity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture, _ := newCrashFixture(t)
			defer func() { _ = closeCrashFixture(fixture) }()
			ctx := context.WithValue(context.Background(), storeRecoveryHealthFaultKey{}, storeRecoveryHealthFault{
				phase: tc.phase,
				err:   errors.New("injected health failure"),
			})
			if state, err := readStoreRecoveryState(ctx, fixture.binding); err == nil {
				t.Fatalf("phase %q returned state=%+v without error", tc.phase, state)
			}
		})
	}
}

type recoveryFaultConnector struct {
	query    error
	rows     [][]driver.Value
	rowsErr  error
	closeErr error
}

func (c *recoveryFaultConnector) Connect(context.Context) (driver.Conn, error) {
	return &recoveryFaultConn{config: c}, nil
}
func (c *recoveryFaultConnector) Driver() driver.Driver { return c }

func (c *recoveryFaultConnector) Open(string) (driver.Conn, error) {
	return &recoveryFaultConn{config: c}, nil
}

type recoveryFaultConn struct{ config *recoveryFaultConnector }

func (*recoveryFaultConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}
func (*recoveryFaultConn) Close() error              { return nil }
func (*recoveryFaultConn) Begin() (driver.Tx, error) { return nil, errors.New("begin unsupported") }
func (c *recoveryFaultConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.config.query != nil {
		return nil, c.config.query
	}
	return &recoveryFaultRows{config: c.config}, nil
}

type recoveryFaultRows struct {
	config *recoveryFaultConnector
	index  int
	closed bool
}

func (*recoveryFaultRows) Columns() []string { return []string{"value"} }
func (r *recoveryFaultRows) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.config.closeErr
}

func (r *recoveryFaultRows) Next(dest []driver.Value) error {
	if r.index < len(r.config.rows) {
		copy(dest, r.config.rows[r.index])
		r.index++
		return nil
	}
	if r.config.rowsErr != nil {
		err := r.config.rowsErr
		r.config.rowsErr = nil
		return err
	}
	return io.EOF
}

func newRecoveryFaultConn(t *testing.T, cfg *recoveryFaultConnector) *sql.Conn {
	t.Helper()
	db := sql.OpenDB(cfg)
	t.Cleanup(func() { _ = db.Close() })
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("fault conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestReadStoreRecoveryScalarFaultRows(t *testing.T) {
	cases := []struct {
		name string
		cfg  recoveryFaultConnector
	}{
		{name: "query-error", cfg: recoveryFaultConnector{query: errors.New("query failure")}},
		{name: "scan-type-error", cfg: recoveryFaultConnector{rows: [][]driver.Value{{"not-an-integer"}}}},
		{name: "zero-rows", cfg: recoveryFaultConnector{}},
		{name: "extra-rows", cfg: recoveryFaultConnector{rows: [][]driver.Value{{int64(1)}, {int64(2)}}}},
		{name: "rows-error", cfg: recoveryFaultConnector{rowsErr: errors.New("iteration failure")}},
		{name: "close-error", cfg: recoveryFaultConnector{rows: [][]driver.Value{{int64(1)}}, closeErr: errors.New("close failure")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newRecoveryFaultConn(t, &tc.cfg)
			if value, err := readStoreRecoveryScalar(context.Background(), conn, "SELECT fixed"); err == nil {
				t.Fatalf("fault accepted value=%d", value)
			}
		})
	}
}

func TestReadStoreRecoveryIntegrityFaultRows(t *testing.T) {
	cases := []struct {
		name string
		cfg  recoveryFaultConnector
	}{
		{name: "query-error", cfg: recoveryFaultConnector{query: errors.New("query failure")}},
		{name: "scan-type-error", cfg: recoveryFaultConnector{rows: [][]driver.Value{{int64(1)}}}},
		{name: "zero-rows", cfg: recoveryFaultConnector{}},
		{name: "wrong-result", cfg: recoveryFaultConnector{rows: [][]driver.Value{{"corrupt"}}}},
		{name: "extra-rows", cfg: recoveryFaultConnector{rows: [][]driver.Value{{"ok"}, {"ok"}}}},
		{name: "rows-error", cfg: recoveryFaultConnector{rows: [][]driver.Value{{"ok"}}, rowsErr: errors.New("iteration failure")}},
		{name: "close-error", cfg: recoveryFaultConnector{rows: [][]driver.Value{{"ok"}}, closeErr: errors.New("close failure")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newRecoveryFaultConn(t, &tc.cfg)
			if err := readStoreRecoveryIntegrity(context.Background(), conn); err == nil {
				t.Fatal("fault accepted")
			}
		})
	}
}
