package trustload

// This file contains only the private ownership seam for the secure store
// adapter.  Store/Enroll/Refresh start using it in SA2 after the callback and
// descriptor proof has been independently accepted.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type storeMode uint8

const (
	storeRead storeMode = iota + 1
	storeEnroll
	storeRefresh
	storeRecover
)

func (m storeMode) writable() bool { return m != storeRead }

// fixedConnector deliberately has one physical connection. database/sql is
// otherwise permitted to replace a closed connection, which would detach a
// transaction from the leased directory/VFS capability.
type fixedConnector struct {
	dsn    string
	proof  *storeProofObserver
	mu     sync.Mutex
	opened bool
	closed bool
}

var storePhysicalClose = func(conn *sql.Conn) error { return conn.Close() }

func (c *fixedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrProvenanceUnavailable
	}
	if c.proof != nil {
		if err := c.proof.checkpoint("driver.open", false); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.opened {
		return nil, ErrProvenanceUnavailable
	}
	c.opened = true
	// A zero Driver has no package-level registered functions or hooks.
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		c.opened = false
		return nil, fmt.Errorf("%w: %v", ErrProvenanceUnavailable, err)
	}
	if c.proof != nil {
		c.proof.resource("physical", 1)
	}
	if c.proof != nil {
		if err := c.proof.checkpoint("driver.open", true); err != nil {
			_ = conn.Close()
			c.proof.resource("physical", -1)
			c.opened = false
			return nil, err
		}
	}
	return conn, nil
}

func closeObservedConn(observer *storeProofObserver, conn *sql.Conn) error {
	if conn == nil {
		return nil
	}
	err := storePhysicalClose(conn)
	if observer != nil {
		observer.resource("physical", -1)
	}
	return err
}

func (c *fixedConnector) Driver() driver.Driver { return &sqlite.Driver{} }

func (c *fixedConnector) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

type sqlBinding struct {
	lease *rootLease
	mode  storeMode
	vfs   *storeVFS
	db    *sql.DB
	conn  *sql.Conn
	gate  *fixedConnector

	mu       sync.Mutex
	closed   bool
	closeErr error
}

type storeSetupFault struct {
	phase                   string
	err                     error
	cancel                  context.CancelFunc
	afterSidecarCheck       func()
	beforeReaderPublication func()
}
type storeSetupFaultKey struct{}

type storeProofObserver struct {
	mu                                    sync.Mutex
	allocs, frees, registers, unregisters int
	tlsCreates, tlsCloses                 int
	rootFDs, rootFDCloses                 int
	rootFDOpened, rootFDClosed            []int
	vfsOpens, vfsCloses                   int
	physicalOpens, physicalCloses         int
	openClasses                           [3]int
	openAttempts                          [3]int
	trace                                 []storeTraceEvent
	traceSeq                              int64
	traceHook                             func(storeTraceEvent)
	hits                                  map[string][2]int
	cancelHits                            map[string][2]int
	ctx                                   context.Context
	cancel                                context.CancelFunc
	failPhase, cancelPhase                string
	cancelAfter                           bool
}

type storeTraceEvent struct {
	Seq       int64 `json:"seq"`
	Op        int64 `json:"op"`
	Kind      int64 `json:"kind"`
	Offset    int64 `json:"offset"`
	Requested int64 `json:"requested"`
	Completed int64 `json:"completed"`
	Result    int64 `json:"result"`
}

const (
	storeTraceOpen int64 = iota + 1
	storeTraceWrite
	storeTraceFileSync
	storeTraceRootSync
	storeTraceTruncate
	storeTraceUnlink
	storeTraceCommitControl
	storeTraceCloseControl
)

const (
	storeTraceKindRoot int64 = 3
)

func (o *storeProofObserver) traceEvent(op, kind, offset, requested, completed, result int64) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.traceSeq++
	event := storeTraceEvent{Seq: o.traceSeq, Op: op, Kind: kind, Offset: offset, Requested: requested, Completed: completed, Result: result}
	o.trace = append(o.trace, event)
	hook := o.traceHook
	o.mu.Unlock()
	if hook != nil {
		hook(event)
	}
}

func (o *storeProofObserver) traceSnapshot() []storeTraceEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]storeTraceEvent(nil), o.trace...)
}

func (o *storeProofObserver) traceReset() {
	o.mu.Lock()
	o.trace = nil
	o.traceSeq = 0
	o.mu.Unlock()
}

func (o *storeProofObserver) openClass(kind int64) {
	if o == nil || kind < 0 || kind >= int64(len(o.openClasses)) {
		return
	}
	o.mu.Lock()
	o.openClasses[kind]++
	o.mu.Unlock()
}

func (o *storeProofObserver) openAttempt(kind int64) {
	if o == nil {
		return
	}
	if kind < 0 || kind >= int64(len(o.openAttempts)) {
		kind = 0
	}
	o.mu.Lock()
	o.openAttempts[kind]++
	o.mu.Unlock()
}

type storeProofObserverKey struct{}

// rootFD records exact descriptors acquired and released by the secure root
// traversal. It is observer-owned proof state and is inert without an observer.
func (o *storeProofObserver) rootFD(fd int, acquired bool) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if acquired {
		o.rootFDs++
		o.rootFDOpened = append(o.rootFDOpened, fd)
	} else {
		o.rootFDCloses++
		o.rootFDClosed = append(o.rootFDClosed, fd)
	}
}

func storeProofObserverFrom(ctx context.Context) *storeProofObserver {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(storeProofObserverKey{}).(*storeProofObserver)
	return o
}

func (o *storeProofObserver) resource(kind string, delta int) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	switch kind {
	case "tls":
		if delta > 0 {
			o.tlsCreates++
		} else {
			o.tlsCloses++
		}
	case "rootfd":
		if delta > 0 {
			o.rootFDs++
		} else {
			o.rootFDCloses++
		}
	case "vfsfile":
		if delta > 0 {
			o.vfsOpens++
		} else {
			o.vfsCloses++
		}
	case "physical":
		if delta > 0 {
			o.physicalOpens++
		} else {
			o.physicalCloses++
		}
	}
}

func (o *storeProofObserver) checkpoint(phase string, after bool) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	if o.hits == nil {
		o.hits = make(map[string][2]int)
	}
	index := 0
	if after {
		index = 1
	}
	counts := o.hits[phase]
	counts[index]++
	o.hits[phase] = counts
	if o.failPhase == phase && !after {
		o.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	if o.cancelPhase == phase && o.cancelAfter == after && o.cancel != nil {
		if o.cancelHits == nil {
			o.cancelHits = make(map[string][2]int)
		}
		cancelCounts := o.cancelHits[phase]
		cancelCounts[index]++
		o.cancelHits[phase] = cancelCounts
		o.cancel()
	}
	ctx := o.ctx
	o.mu.Unlock()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return ErrProvenanceUnavailable
		}
	}
	return nil
}

func storeSetupProbe(ctx context.Context, phase string) error {
	if observer := storeProofObserverFrom(ctx); observer != nil {
		if err := observer.checkpoint(phase, false); err != nil {
			return err
		}
	}
	fault, _ := ctx.Value(storeSetupFaultKey{}).(storeSetupFault)
	if fault.phase == phase {
		if fault.cancel != nil {
			fault.cancel()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return fault.err
	}
	return ctx.Err()
}

func storeSetupComplete(ctx context.Context, phase string) error {
	if observer := storeProofObserverFrom(ctx); observer != nil {
		return observer.checkpoint(phase, true)
	}
	return ctx.Err()
}

// storeSetupAfterSidecarCheck is a private deterministic test seam. It lets
// namespace tests insert a sidecar exactly after the first reader precheck;
// the production path immediately repeats the precheck before publishing a
// reader binding. It carries no authority and is unreachable outside tests in
// this package.
func storeSetupAfterSidecarCheck(ctx context.Context) {
	fault, _ := ctx.Value(storeSetupFaultKey{}).(storeSetupFault)
	if fault.afterSidecarCheck != nil {
		fault.afterSidecarCheck()
	}
}

func storeSetupBeforeReaderPublication(ctx context.Context) {
	fault, _ := ctx.Value(storeSetupFaultKey{}).(storeSetupFault)
	if fault.beforeReaderPublication != nil {
		fault.beforeReaderPublication()
	}
}

func openSQLBinding(ctx context.Context, lease *rootLease, mode storeMode) (*sqlBinding, error) {
	if ctx == nil || lease == nil || lease.closedState() || (mode != storeRead && mode != storeEnroll && mode != storeRefresh && mode != storeRecover) {
		return nil, ErrProvenanceUnavailable
	}
	if lease.mode == storeRead && mode != storeRead {
		return nil, ErrProvenanceUnavailable
	}
	if mode == storeRead {
		if err := lease.pendingSidecar(); err != nil {
			return nil, err
		}
		storeSetupAfterSidecarCheck(ctx)
		if err := lease.pendingSidecar(); err != nil {
			return nil, err
		}
	}
	storeSetupBeforeReaderPublication(ctx)
	v, err := newStoreVFSObserved(lease, mode, storeProofObserverFrom(ctx))
	if err != nil {
		return nil, err
	}
	gate := &fixedConnector{dsn: v.dsn(), proof: storeProofObserverFrom(ctx)}
	db := sql.OpenDB(gate)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	if observer := storeProofObserverFrom(ctx); observer != nil {
		if err := observer.checkpoint("db.Conn", false); err != nil {
			gate.close()
			_ = db.Close()
			_ = v.Close()
			return nil, err
		}
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		gate.close()
		_ = db.Close()
		_ = v.Close()
		return nil, ErrProvenanceUnavailable
	}
	if observer := storeProofObserverFrom(ctx); observer != nil {
		if err := observer.checkpoint("db.Conn", true); err != nil {
			_ = closeObservedConn(gate.proof, conn)
			gate.close()
			_ = db.Close()
			_ = v.Close()
			return nil, err
		}
	}
	// These restrictions are per physical connection, so set them only after
	// acquiring the retained Conn and never through DB.* methods.
	if err := storeSetupProbe(ctx, "conn.ATTACHED"); err != nil {
		_ = closeObservedConn(gate.proof, conn)
		gate.close()
		_ = db.Close()
		_ = v.Close()
		return nil, ErrProvenanceUnavailable
	}
	if _, err := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_ATTACHED, 0); err != nil {
		_ = closeObservedConn(gate.proof, conn)
		gate.close()
		_ = db.Close()
		_ = v.Close()
		return nil, ErrProvenanceUnavailable
	}
	if err := storeSetupComplete(ctx, "conn.ATTACHED"); err != nil {
		_ = closeObservedConn(gate.proof, conn)
		gate.close()
		_ = db.Close()
		_ = v.Close()
		return nil, ErrProvenanceUnavailable
	}
	if err := configureStoreConnection(ctx, conn, mode); err != nil {
		_ = closeObservedConn(gate.proof, conn)
		gate.close()
		_ = db.Close()
		_ = v.Close()
		return nil, ErrProvenanceUnavailable
	}
	b := &sqlBinding{lease: lease, mode: mode, vfs: v, db: db, conn: conn, gate: gate}
	return b, nil
}

// storeRecoveryState is the fixed, schema-independent SQLite health tuple
// used by the recovery adapter. It is deliberately private: these values are
// engine observations and do not authenticate application rows or grant any
// authority to remove a sidecar.
type storeRecoveryState struct {
	schemaVersion    int64
	userVersion      int64
	applicationID    int64
	pageSize         int64
	pageCount        int64
	freelistCount    int64
	schemaEntryCount int64
}

type storeRecoveryHealthFault struct {
	phase string
	err   error
}

type storeRecoveryHealthFaultKey struct{}

func storeRecoveryHealthFaultFrom(ctx context.Context) storeRecoveryHealthFault {
	if ctx == nil {
		return storeRecoveryHealthFault{}
	}
	fault, _ := ctx.Value(storeRecoveryHealthFaultKey{}).(storeRecoveryHealthFault)
	return fault
}

func checkStoreRecoveryHealthFault(ctx context.Context, phase string) error {
	fault := storeRecoveryHealthFaultFrom(ctx)
	if fault.phase == phase {
		if fault.err != nil {
			return fault.err
		}
		return ErrProvenanceUnavailable
	}
	return nil
}

const (
	storeRecoveryHealthQueryOnlySet      = "health:exec:PRAGMA query_only=ON"
	storeRecoveryHealthQueryOnlyReadback = "health:query:PRAGMA query_only"
)

var storeRecoveryHealthQueries = [...]string{
	"PRAGMA main.schema_version",
	"PRAGMA main.user_version",
	"PRAGMA main.application_id",
	"PRAGMA main.page_size",
	"PRAGMA main.page_count",
	"PRAGMA main.freelist_count",
	"SELECT count(*) FROM main.sqlite_schema",
}

func readStoreRecoveryScalar(ctx context.Context, conn *sql.Conn, query string) (int64, error) {
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	var value int64
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			continue
		}
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return 0, err
		}
	}
	iterErr := rows.Err()
	closeErr := rows.Close()
	if iterErr != nil {
		return 0, iterErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if count != 1 {
		return 0, ErrProvenanceUnavailable
	}
	return value, nil
}

func readStoreRecoveryIntegrity(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA main.integrity_check")
	if err != nil {
		return err
	}
	count := 0
	valid := true
	for rows.Next() {
		count++
		var result string
		if err := rows.Scan(&result); err != nil {
			_ = rows.Close()
			return err
		}
		if count != 1 || result != "ok" {
			valid = false
		}
	}
	iterErr := rows.Err()
	closeErr := rows.Close()
	if iterErr != nil {
		return iterErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !valid || count != 1 {
		return ErrProvenanceUnavailable
	}
	return nil
}

// readStoreRecoveryState applies the fixed SQL health gate to a retained
// binding. It intentionally accepts neither SQL nor an expected tuple from a
// caller. The test-only context seam can inject bounded failures, but cannot
// replace a query, scan value, or successful health result.
func readStoreRecoveryState(ctx context.Context, binding *sqlBinding) (storeRecoveryState, error) {
	if ctx == nil || binding == nil || binding.conn == nil {
		return storeRecoveryState{}, ErrProvenanceUnavailable
	}
	if err := storeSetupProbe(ctx, "exec:PRAGMA query_only=ON"); err != nil {
		return storeRecoveryState{}, err
	}
	if _, err := binding.conn.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
		return storeRecoveryState{}, fmt.Errorf("store recovery query_only: %w", err)
	}
	if err := storeSetupComplete(ctx, "exec:PRAGMA query_only=ON"); err != nil {
		return storeRecoveryState{}, err
	}
	if err := checkStoreRecoveryHealthFault(ctx, storeRecoveryHealthQueryOnlySet); err != nil {
		return storeRecoveryState{}, err
	}
	if err := storeSetupProbe(ctx, "query:PRAGMA query_only"); err != nil {
		return storeRecoveryState{}, err
	}
	queryOnly, err := readStoreRecoveryScalar(ctx, binding.conn, "PRAGMA main.query_only")
	if err != nil {
		return storeRecoveryState{}, fmt.Errorf("store recovery query_only readback: %w", err)
	}
	if err := storeSetupComplete(ctx, "query:PRAGMA query_only"); err != nil {
		return storeRecoveryState{}, err
	}
	if err := checkStoreRecoveryHealthFault(ctx, storeRecoveryHealthQueryOnlyReadback); err != nil {
		return storeRecoveryState{}, err
	}
	if queryOnly != 1 {
		return storeRecoveryState{}, ErrProvenanceUnavailable
	}

	var state storeRecoveryState
	values := [...]*int64{
		&state.schemaVersion,
		&state.userVersion,
		&state.applicationID,
		&state.pageSize,
		&state.pageCount,
		&state.freelistCount,
		&state.schemaEntryCount,
	}
	for i, query := range storeRecoveryHealthQueries {
		if err := checkStoreRecoveryHealthFault(ctx, fmt.Sprintf("query:%d", i)); err != nil {
			return storeRecoveryState{}, err
		}
		value, err := readStoreRecoveryScalar(ctx, binding.conn, query)
		if err != nil {
			return storeRecoveryState{}, fmt.Errorf("store recovery health query %q: %w", query, err)
		}
		*values[i] = value
	}
	if state.schemaVersion < 0 || state.userVersion < 0 || state.pageSize < 512 || state.pageSize > 65536 || state.pageSize&(state.pageSize-1) != 0 || state.pageCount <= 0 || state.freelistCount < 0 || state.freelistCount > state.pageCount || state.schemaEntryCount <= 0 {
		return storeRecoveryState{}, ErrProvenanceUnavailable
	}
	if err := checkStoreRecoveryHealthFault(ctx, "integrity"); err != nil {
		return storeRecoveryState{}, err
	}
	if err := readStoreRecoveryIntegrity(ctx, binding.conn); err != nil {
		return storeRecoveryState{}, fmt.Errorf("store recovery integrity: %w", err)
	}
	return state, nil
}

func storeRecoveryStateEqual(left, right storeRecoveryState) bool { return left == right }

// configureStoreConnection applies fixed restrictions to the one retained
// SQLite connection and immediately reads them back. No caller supplied mode,
// pragma, DSN option, or replacement connection can weaken this policy.
func configureStoreConnection(ctx context.Context, conn *sql.Conn, mode storeMode) error {
	if ctx == nil || conn == nil {
		return ErrProvenanceUnavailable
	}
	for _, stmt := range []string{
		"PRAGMA temp_store=MEMORY",
		"PRAGMA mmap_size=0",
		"PRAGMA trusted_schema=OFF",
	} {
		if err := storeSetupProbe(ctx, "exec:"+stmt); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store pragma %q: %w", stmt, err)
		}
		if err := storeSetupComplete(ctx, "exec:"+stmt); err != nil {
			return err
		}
	}
	if mode == storeRead {
		if err := storeSetupProbe(ctx, "exec:PRAGMA query_only=ON"); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA query_only=ON"); err != nil {
			return fmt.Errorf("store query_only: %w", err)
		}
		if err := storeSetupComplete(ctx, "exec:PRAGMA query_only=ON"); err != nil {
			return err
		}
	} else {
		for _, stmt := range []string{"PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL"} {
			if err := storeSetupProbe(ctx, "exec:"+stmt); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("store pragma %q: %w", stmt, err)
			}
			if err := storeSetupComplete(ctx, "exec:"+stmt); err != nil {
				return err
			}
		}
	}
	var tempStore, mmapSize, trustedSchema, queryOnly int
	if err := storeSetupProbe(ctx, "query:PRAGMA temp_store"); err != nil {
		return err
	} else if err := conn.QueryRowContext(ctx, "PRAGMA temp_store").Scan(&tempStore); err != nil || tempStore != 2 {
		return fmt.Errorf("store temp_store=%d: %w", tempStore, ErrProvenanceUnavailable)
	}
	if err := storeSetupComplete(ctx, "query:PRAGMA temp_store"); err != nil {
		return err
	}
	if err := storeSetupProbe(ctx, "query:PRAGMA mmap_size"); err != nil {
		return err
	} else if err := conn.QueryRowContext(ctx, "PRAGMA mmap_size").Scan(&mmapSize); err != nil {
		// SQLite omits the result when this VFS has no mmap capability. The
		// adapter supplies version-1 I/O methods only (no xFetch/xUnfetch), so
		// that omission is the same fixed zero-mmap policy, not a fallback.
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store mmap_size readback: %w", err)
		}
		mmapSize = 0
	}
	if err := storeSetupComplete(ctx, "query:PRAGMA mmap_size"); err != nil {
		return err
	}
	if mmapSize != 0 {
		return fmt.Errorf("store mmap_size=%d: %w", mmapSize, ErrProvenanceUnavailable)
	}
	if err := storeSetupProbe(ctx, "query:PRAGMA trusted_schema"); err != nil {
		return err
	} else if err := conn.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil || trustedSchema != 0 {
		return fmt.Errorf("store trusted_schema=%d: %w", trustedSchema, ErrProvenanceUnavailable)
	}
	if err := storeSetupComplete(ctx, "query:PRAGMA trusted_schema"); err != nil {
		return err
	}
	if err := storeSetupProbe(ctx, "query:PRAGMA query_only"); err != nil {
		return err
	} else if err := conn.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
		return fmt.Errorf("store query_only readback: %w", err)
	}
	if err := storeSetupComplete(ctx, "query:PRAGMA query_only"); err != nil {
		return err
	}
	if mode == storeRead && queryOnly != 1 {
		return fmt.Errorf("store query_only=%d: %w", queryOnly, ErrProvenanceUnavailable)
	}
	if mode != storeRead {
		var journalMode string
		var synchronous int
		if err := storeSetupProbe(ctx, "query:PRAGMA journal_mode"); err != nil {
			return err
		} else if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil || journalMode != "delete" {
			return fmt.Errorf("store journal_mode=%q: %w", journalMode, ErrProvenanceUnavailable)
		}
		if err := storeSetupComplete(ctx, "query:PRAGMA journal_mode"); err != nil {
			return err
		}
		if err := storeSetupProbe(ctx, "query:PRAGMA synchronous"); err != nil {
			return err
		} else if err := conn.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
			return fmt.Errorf("store synchronous=%d: %w", synchronous, ErrProvenanceUnavailable)
		}
		if err := storeSetupComplete(ctx, "query:PRAGMA synchronous"); err != nil {
			return err
		}
	}
	return nil
}

func (b *sqlBinding) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	if b.closeErr != nil {
		err := b.closeErr
		b.mu.Unlock()
		return err
	}
	b.mu.Unlock()
	var err error
	if b.conn != nil {
		err = closeObservedConn(b.gate.proof, b.conn)
	}
	if b.gate != nil {
		b.gate.close()
	}
	if b.db != nil {
		if closeErr := b.db.Close(); err == nil {
			err = closeErr
		}
	}
	// VFS allocations remain live until database/sql has returned the sole
	// driver connection and SQLite has called every xClose callback.
	if b.vfs != nil {
		if closeErr := b.vfs.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		b.mu.Lock()
		b.closeErr = ErrProvenanceUnavailable
		b.mu.Unlock()
		return ErrProvenanceUnavailable
	}
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

type storeSession struct {
	lease   *rootLease
	binding *sqlBinding
}

func (s *storeSession) Close() error {
	if s == nil {
		return nil
	}
	if s.binding != nil {
		if err := s.binding.Close(); err != nil {
			return err
		}
	}
	if s.lease != nil {
		return s.lease.Close()
	}
	return nil
}

var errStoreAdapterUnavailable = errors.New("trustload: secure store adapter unavailable")
