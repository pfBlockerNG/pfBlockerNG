// The stats databases' behaviour that a table dump cannot pin: the worker's batching, bounds and stop, the retry and
// rollback of a failed write, the PRAGMA, corruption and concurrency handling, what gates the open, and that DNS keeps
// answering when a database cannot be used. They mirror the DB tests of tests/test_pfb_unbound.py and the
// tests/test_dns_metric_*.py files; the table contents themselves are pinned by pfb_unbound_sqlite_oracle_test.go.
package decider

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

// sqlRig is a booted module over its own stats databases, written synchronously (the worker is stopped) with no pause
// between the attempts of a failed write.
type sqlRig struct {
	m      *pfbUnbound
	dir    string
	log    *bytes.Buffer
	sleeps atomic.Int64
}

func (r *sqlRig) path(db int) string {
	if db == dbResolver {
		return filepath.Join(r.dir, sqlFileNames["resolver"])
	}
	return filepath.Join(r.dir, sqlFileNames["dnsbl"])
}

// sqlCustomGroups is the dnsbl database as PHP's dnsbl_save_stats() leaves it: a counter row and a custom owner epoch per group.
func sqlCustomGroups(counter int, names ...string) []string {
	statements := []string{
		"CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)",
		"CREATE TABLE dnsbl_group_epochs (owner TEXT NOT NULL, origin TEXT NOT NULL, epoch TEXT NOT NULL, PRIMARY KEY(owner, origin))",
	}
	for i, name := range names {
		statements = append(statements,
			fmt.Sprintf("INSERT INTO dnsbl VALUES ('%s', '', 1, %d)", name, counter),
			fmt.Sprintf("INSERT INTO dnsbl_group_epochs VALUES ('%s', 'custom', '%032x')", name, i+1))
	}
	return statements
}

// newSqlRig boots a module with python_enable on and `main` added to its [MAIN] section; forwarding = true opens the DNSBL
// database without a feed.
func newSqlRig(t *testing.T, main string, presql map[string][]string) *sqlRig {
	t.Helper()
	r := &sqlRig{log: modCaptureLog(t)}
	r.dir = modIniDir(t, "[MAIN]\npython_enable = true\n"+main)
	for db, statements := range presql {
		sqlExec(t, filepath.Join(r.dir, sqlFileNames[db]), statements...)
	}
	previous := dbRetrySleep
	dbRetrySleep = func(time.Duration) { r.sleeps.Add(1) }
	t.Cleanup(func() { dbRetrySleep = previous })
	m, err := boot(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	r.m = m
	m.logSink = func(string, string) {}
	m.stopDbWorker()
	t.Cleanup(func() { m.closeDb(); m.stopLogging() })
	return r
}

func resolverEvent(qtype, transport string) dbEvent {
	return dbEvent{qtype: qtype, transport: transport}
}

func blockEvent(group, epoch string) dbEvent {
	return dbEvent{dnsbl: true, group: group, owner: group, origin: "custom", epoch: epoch, qtype: "A", transport: "UDP"}
}

func (r *sqlRig) groupEpoch(t *testing.T, group string) string {
	t.Helper()
	return sqlValue(t, r.path(dbDnsbl), "SELECT epoch FROM dnsbl_group_epochs WHERE owner=?", group).(string)
}

// sqlRows is `columns` of every row of a table, sorted, as text.
func sqlRows(t *testing.T, path, table, columns string) string {
	t.Helper()
	db := openSqlFile(t, path)
	rows, err := db.Query("SELECT " + columns + " FROM " + table + " ORDER BY 1, 2, 3")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		cells := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(cells))
		for i, cell := range cells {
			parts[i] = fmt.Sprint(cell)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return strings.Join(out, ";")
}

// --- the worker ---

func TestSqliteWorkerFlushesDimensionsOnce(t *testing.T) {
	for _, mode := range []string{"threshold", "idle", "stop", "retry"} {
		t.Run(mode, func(t *testing.T) {
			r := newSqlRig(t, "forwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(7, "First")})
			m := r.m
			sqlExec(t, r.path(dbResolver), "UPDATE resolver SET totalqueries = 10 WHERE row = 0")
			previous := dbMaxBatch
			dbMaxBatch = 100
			if mode == "threshold" || mode == "retry" {
				dbMaxBatch = 2
			}
			t.Cleanup(func() { dbMaxBatch = previous })
			if mode == "retry" {
				sqlExec(t, r.path(dbResolver), "CREATE TRIGGER reject_detail BEFORE INSERT ON dns_metric_queries BEGIN SELECT RAISE(ABORT, 'detail rejected'); END")
			}
			queue := make(chan dbTask, 8)
			queue <- dbTask{event: resolverEvent("A", "UDP")}
			queue <- dbTask{event: blockEvent("First", r.groupEpoch(t, "First"))}
			queue <- dbTask{stop: true}
			w := newDbWorker(m, queue)
			idleSeen := false
			inner := w.get
			w.get = func() (dbTask, bool) {
				if len(queue) == 1 { // only the stop is left
					if mode == "retry" && !idleSeen {
						if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(10) {
							t.Errorf("a failed flush left totalqueries = %v, want the 10 before it", got)
						}
						sqlExec(t, r.path(dbResolver), "DROP TRIGGER reject_detail")
					}
					if (mode == "idle" || mode == "retry") && !idleSeen {
						idleSeen = true
						return dbTask{}, false
					}
					if mode != "stop" {
						if got := sqlRows(t, r.path(dbResolver), "dns_metric_queries", "qtype, transport, count"); got != "A UDP 1" {
							t.Errorf("before the stop, dns_metric_queries = %q: the %s flush did not run", got, mode)
						}
						if got := sqlRows(t, r.path(dbDnsbl), "dns_metric_blocks", "groupname, qtype, transport, count"); got != "First A UDP 1" {
							t.Errorf("before the stop, dns_metric_blocks = %q: the %s flush did not run", got, mode)
						}
					}
				}
				return inner()
			}
			w.run()
			if len(queue) != 0 {
				t.Errorf("the worker left %d tasks queued", len(queue))
			}
			if got := sqlRows(t, r.path(dbResolver), "dns_metric_queries", "qtype, transport, count"); got != "A UDP 1" {
				t.Errorf("dns_metric_queries = %q, want one A UDP row counted once", got)
			}
			if got := sqlRows(t, r.path(dbDnsbl), "dns_metric_blocks", "groupname, qtype, transport, count"); got != "First A UDP 1" {
				t.Errorf("dns_metric_blocks = %q, want one First A UDP row counted once", got)
			}
			if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(11) {
				t.Errorf("totalqueries = %v, want 11: each event counted once", got)
			}
			if got := sqlValue(t, r.path(dbDnsbl), "SELECT counter FROM dnsbl WHERE groupname='First'"); got != int64(8) {
				t.Errorf("counter = %v, want 8: each event counted once", got)
			}
		})
	}
}

// The stop task drains what follows it: events queued behind the stop are still counted.
func TestSqliteStopDrainsWhatFollowsIt(t *testing.T) {
	r := newSqlRig(t, "", nil)
	queue := make(chan dbTask, 8)
	queue <- dbTask{stop: true}
	queue <- dbTask{event: resolverEvent("A", "UDP")}
	queue <- dbTask{event: resolverEvent("A", "TCP")}
	newDbWorker(r.m, queue).run()
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(2) {
		t.Errorf("totalqueries = %v, want 2: the stop must drain the events behind it", got)
	}
}

func TestSqliteEnqueueDropsWhenTheQueueIsFull(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.dbWorker.Store(newDbWorker(r.m, make(chan dbTask, 2))) // no goroutine drains it
	t.Cleanup(func() { r.m.dbWorker.Store(nil) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			r.m.dbEnqueue(resolverEvent("A", "UDP"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dbEnqueue blocked on a full queue: it must never hold the DNS path")
	}
	if got := r.m.dbDropped.Load(); got != 1 {
		t.Errorf("db_dropped = %d, want 1: the third event found the 2-slot queue full", got)
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(0) {
		t.Errorf("totalqueries = %v: a queued event must not reach the database before the worker flushes", got)
	}
}

func TestSqliteWorkerFlushesOnStopAndFallsBackToSynchronousWrites(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.startDbWorker()
	for range 10 {
		r.m.dbEnqueue(resolverEvent("", ""))
	}
	r.m.stopDbWorker()
	if r.m.dbWorker.Load() != nil {
		t.Error("db_worker is still set after the stop")
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(10) {
		t.Errorf("totalqueries after the stop = %v, want 10: the stop flushes what the worker holds", got)
	}
	r.m.dbEnqueue(resolverEvent("", ""))
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(11) {
		t.Errorf("totalqueries = %v, want 11: with no worker the write is synchronous", got)
	}
	r.m.stopDbWorker() // a second stop does nothing
}

func TestSqliteConcurrentEnqueuesAreAllCounted(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.startDbWorker()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 400 {
				r.m.dbEnqueue(resolverEvent("A", fmt.Sprint("T", g)))
			}
		}()
	}
	wg.Wait()
	r.m.stopDbWorker()
	if got := r.m.dbDropped.Load(); got != 0 {
		t.Fatalf("db_dropped = %d with 3200 events in a 5000-slot queue", got)
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(3200) {
		t.Errorf("totalqueries = %v, want 3200", got)
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT SUM(count) FROM dns_metric_queries"); got != int64(3200) {
		t.Errorf("the detail rows sum to %v, want 3200", got)
	}
}

// --- a failed write ---

func TestSqliteDetailFailureRollsBackTheAggregateBeforeRetrying(t *testing.T) {
	for _, db := range []int{dbResolver, dbDnsbl} {
		for _, retry := range []bool{false, true} {
			t.Run(fmt.Sprintf("db%d-retry%v", db, retry), func(t *testing.T) {
				r := newSqlRig(t, "forwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(7, "First")})
				sqlExec(t, r.path(dbResolver), "UPDATE resolver SET totalqueries = 10 WHERE row = 0")
				path, table := r.path(dbResolver), "dns_metric_queries"
				event := resolverEvent("A", "UDP")
				if db == dbDnsbl {
					path, table, event = r.path(dbDnsbl), "dns_metric_blocks", blockEvent("First", r.groupEpoch(t, "First"))
				}
				// A real SQLite failure after the aggregate UPDATE must roll the whole event back.
				sqlExec(t, path, "CREATE TRIGGER reject_detail BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT, 'detail rejected'); END")
				if retry {
					dbRetrySleep = func(time.Duration) {
						r.sleeps.Add(1)
						sqlExec(t, path, "DROP TRIGGER IF EXISTS reject_detail")
					}
				}
				r.m.dbEnqueue(event)
				aggregate := "SELECT totalqueries FROM resolver"
				want := int64(10)
				if db == dbDnsbl {
					aggregate, want = "SELECT counter FROM dnsbl WHERE groupname='First'", 7
				}
				details := int64(0)
				if retry {
					want++
					details = 1
				}
				if got := sqlValue(t, path, aggregate); got != want {
					t.Errorf("aggregate = %v, want %d", got, want)
				}
				if got := sqlValue(t, path, "SELECT COALESCE(SUM(count), 0) FROM "+table); got != details {
					t.Errorf("%s holds %v, want %d: the detail and the aggregate commit together", table, got, details)
				}
				wantSleeps := int64(3) // four attempts, a pause after each but the last
				if retry {
					wantSleeps = 1
				}
				if got := r.sleeps.Load(); got != wantSleeps {
					t.Errorf("pauses between attempts = %d, want %d", got, wantSleeps)
				}
				if failed := strings.Contains(r.log.String(), "sqlite write failed"); failed == retry {
					t.Errorf("the final failure is logged = %v, want %v:\n%s", failed, !retry, r.log)
				}
			})
		}
	}
}

func TestSqliteFailedBatchCannotResurrectClients(t *testing.T) {
	r := newSqlRig(t, "metrics_client_ip = true\nforwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(0, "First")})
	const old, current = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for _, db := range []int{dbResolver, dbDnsbl} {
		sqlExec(t, r.path(db), "UPDATE dns_metric_settings SET client_ip=1, epoch='"+old+"' WHERE row=0")
	}
	r.m.closeDb()
	r.m.dbCapturePrivacyEpochs()
	for _, db := range []int{dbResolver, dbDnsbl} {
		if got := r.m.metricsPrivacyEpochs[db]; got != old {
			t.Fatalf("db %d: captured epoch %q, want the opted-in %q", db, got, old)
		}
	}
	groupEpoch := r.groupEpoch(t, "First")
	resolver := map[dbEvent]int64{{qtype: "A", transport: "UDP", client: "2001:db8::10", clientEpoch: old}: 1}
	dnsbl := map[dbEvent]int64{{dnsbl: true, group: "First", owner: "First", origin: "custom", epoch: groupEpoch, qtype: "A", transport: "UDP", client: "2001:db8::10", clientEpoch: old}: 1}
	deltas := map[groupKey]int64{{"First", "First", "custom", groupEpoch}: 1}
	for _, db := range []int{dbResolver, dbDnsbl} {
		table := "dns_metric_queries"
		if db == dbDnsbl {
			table = "dns_metric_blocks"
		}
		sqlExec(t, r.path(db), "CREATE TRIGGER reject_detail BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT, 'real failure'); END")
	}
	// The first attempts fail; before the retry the owner turns the policy off and a new epoch begins.
	dbRetrySleep = func(time.Duration) {
		r.sleeps.Add(1)
		for _, db := range []int{dbResolver, dbDnsbl} {
			sqlExec(t, r.path(db), "UPDATE dns_metric_settings SET client_ip=0, epoch='"+current+"' WHERE row=0", "DROP TRIGGER IF EXISTS reject_detail")
		}
	}
	if !r.m.dbFlushResolver(1, resolver) || !r.m.dbFlushDnsbl(deltas, dnsbl) {
		t.Fatalf("the retry after the policy change did not write:\n%s", r.log)
	}
	if got := sqlRows(t, r.path(dbResolver), "dns_metric_queries", "qtype, transport, client_ip, count"); got != "A UDP  1" {
		t.Errorf("dns_metric_queries = %q: the client of the old epoch was written", got)
	}
	if got := sqlRows(t, r.path(dbDnsbl), "dns_metric_blocks", "groupname, qtype, transport, client_ip, count"); got != "First A UDP  1" {
		t.Errorf("dns_metric_blocks = %q: the client of the old epoch was written", got)
	}
}

func TestSqliteRetainedBatchKeepsItsDetailsWhenTheFlushFails(t *testing.T) {
	r := newSqlRig(t, "", nil)
	sqlExec(t, r.path(dbResolver), "CREATE TRIGGER reject_detail BEFORE INSERT ON dns_metric_queries BEGIN SELECT RAISE(ABORT, 'real failure'); END")
	details := map[dbEvent]int64{resolverEvent("A", "UDP"): 2}
	if r.m.dbFlushResolver(2, details) {
		t.Fatal("a flush the database rejects reported success")
	}
	if len(details) != 1 || details[resolverEvent("A", "UDP")] != 2 {
		t.Errorf("details = %v after a failed flush: the caller retries them", details)
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver"); got != int64(0) {
		t.Errorf("totalqueries = %v after a failed flush", got)
	}
}

// --- connecting ---

func TestSqliteConnectIsWalAndSilent(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.dbClose(dbResolver)
	r.log.Reset()
	if !r.m.dbValidate(dbResolver) {
		t.Fatal("the resolver database did not reopen")
	}
	if got := sqlValue(t, r.path(dbResolver), "PRAGMA journal_mode"); got != "wal" {
		t.Errorf("journal_mode = %v, want wal", got)
	}
	if strings.Contains(r.log.String(), "[pfBlockerNG]") {
		t.Errorf("a healthy connect logged:\n%s", r.log)
	}
}

func TestSqliteConnectLogsPragmaFailureAndStillInitialises(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.dbClose(dbResolver)
	r.log.Reset()
	previous := dbPragmas
	dbPragmas = []string{previous[0], "PRAGMA busy_timeout=NOT A NUMBER ;; bad", previous[2]}
	t.Cleanup(func() { dbPragmas = previous })
	if !r.m.dbValidate(dbResolver) {
		t.Fatal("a PRAGMA failure stopped the connect: the connection still works on SQLite defaults")
	}
	if !strings.Contains(r.log.String(), "PRAGMA setup failed") {
		t.Errorf("the PRAGMA failure was not logged:\n%s", r.log)
	}
	if got := sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver WHERE row = 0"); got != int64(0) {
		t.Errorf("the seed row after a failed PRAGMA = %v, want 0: the tables must still be created", got)
	}
}

func TestSqliteUnsupportedSchemaIsRefusedAndRolledBack(t *testing.T) {
	cases := []struct {
		db      int
		table   string
		columns string
		values  string
	}{
		{dbResolver, "dns_metric_queries", "qtype TEXT, transport TEXT, count INTEGER", "'A','UDP',7"},
		{dbDnsbl, "dns_metric_blocks", "owner TEXT, origin TEXT, groupname TEXT, qtype TEXT, transport TEXT, count INTEGER", "'First','custom','First','A','UDP',7"},
	}
	for _, c := range cases {
		t.Run(c.table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "migration.sqlite")
			// A real naming collision makes the settings seed fail after the detail table was migrated.
			sqlExec(t, path, "CREATE TABLE "+c.table+" ("+c.columns+")", "INSERT INTO "+c.table+" VALUES ("+c.values+")", "CREATE TABLE dns_metric_settings (wrong TEXT)")
			before := sqlRows(t, path, c.table, "*")
			con, err := openSqlFile(t, path).Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer con.Close()
			m := &pfbUnbound{}
			if err := m.dbCreate(context.Background(), con, c.db); err == nil {
				t.Fatal("dbCreate succeeded over a colliding settings table")
			}
			if got := sqlRows(t, path, c.table, "*"); got != before {
				t.Errorf("%s = %q after the failure, was %q", c.table, got, before)
			}
			if got := sqlStrings(t, openSqlFile(t, path), "SELECT name FROM pragma_table_info('"+c.table+"') WHERE name='listener_ip'"); len(got) != 0 {
				t.Errorf("%s kept the migrated columns: the savepoint did not roll back", c.table)
			}
			if got := sqlStrings(t, openSqlFile(t, path), "SELECT name FROM sqlite_master WHERE name LIKE '%_old'"); len(got) != 0 {
				t.Errorf("leftover tables %q", got)
			}
		})
	}
	t.Run("not a metric table", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "unknown.sqlite")
		sqlExec(t, path, "CREATE TABLE dns_metric_queries (qtype TEXT, other TEXT, count INTEGER)")
		con, err := openSqlFile(t, path).Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer con.Close()
		err = (&pfbUnbound{}).dbCreate(context.Background(), con, dbResolver)
		if err == nil || !strings.Contains(err.Error(), "Unsupported DNS metric schema: dns_metric_queries") {
			t.Errorf("dbCreate over an unknown schema = %v, want Unsupported DNS metric schema: dns_metric_queries", err)
		}
	})
}

// --- corruption and recovery ---

func TestSqliteRecoversACorruptDatabase(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.closeDb()
	path := r.path(dbResolver)
	for _, file := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.WriteFile(file, []byte("this is not a database, nor its journal"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !r.m.validateDbWithRecovery(dbResolver) {
		t.Fatalf("a corrupt database was not recovered:\n%s", r.log)
	}
	if got := sqlValue(t, path, "SELECT totalqueries FROM resolver WHERE row = 0"); got != int64(0) {
		t.Errorf("the rebuilt database has totalqueries = %v, want its fresh seed 0", got)
	}
	r.m.dbEnqueue(resolverEvent("A", "UDP"))
	if got := sqlValue(t, path, "SELECT totalqueries FROM resolver"); got != int64(1) {
		t.Errorf("totalqueries = %v after a write, want 1", got)
	}
}

// A database whose pages are still in its write-ahead log and whose schema the module refuses is recovered: the file and its
// sidecars go and a fresh database is read. (The removal of the -wal itself is not observable here: SQLite deletes a log
// that sits next to a zero-length database file, so a recovery that left it behind would pass too.)
func TestSqliteRecoveryRemovesTheStaleSidecars(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.closeDb()
	path := r.path(dbResolver)
	other := filepath.Join(t.TempDir(), "other.sqlite")
	pool, err := sql.Open("sqlite", other)
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE dns_metric_queries (qtype TEXT, other TEXT, count INTEGER)", "INSERT INTO dns_metric_queries VALUES ('A', 'x', 3)",
	} {
		if _, err := pool.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	// The log is complete while the connection is open.
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(other + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+suffix, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pool.Close()
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("no write-ahead log to leave behind: %v", err)
	}
	if !r.m.validateDbWithRecovery(dbResolver) {
		t.Fatalf("the database was not recovered:\n%s", r.log)
	}
	if got := sqlStrings(t, openSqlFile(t, path), "SELECT name FROM pragma_table_info('dns_metric_queries') WHERE name='other'"); len(got) != 0 {
		t.Error("the recreated database holds the old schema")
	}
	if got := sqlValue(t, path, "SELECT totalqueries FROM resolver WHERE row = 0"); got != int64(0) {
		t.Errorf("totalqueries = %v in the recreated database, want its fresh seed 0", got)
	}
	if got := sqlValue(t, path, "PRAGMA journal_mode"); got != "wal" {
		t.Errorf("journal_mode = %v after the recovery, want wal", got)
	}
}

// Python's os.remove refuses a directory, so a directory at the database path (or at a sidecar's) is left alone and the
// validate reports false.
func TestSqliteRecoveryNeverRemovesADirectory(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.closeDb()
	path := r.path(dbResolver)
	for _, file := range []string{path, path + "-wal", path + "-shm"} {
		os.Remove(file)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if r.m.validateDbWithRecovery(dbResolver) {
		t.Error("a directory at the database path validated")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Errorf("the directory at the database path was removed: %v", err)
	}
	if !strings.Contains(r.log.String(), "sqlite write failed") {
		t.Errorf("the failure was not reported:\n%s", r.log)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("this is not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		os.Remove(sidecar)
	}
	if err := os.Mkdir(path+"-wal", 0o755); err != nil {
		t.Fatal(err)
	}
	r.m.validateDbWithRecovery(dbResolver)
	if info, err := os.Stat(path + "-wal"); err != nil || !info.IsDir() {
		t.Errorf("the directory at the -wal path was removed: %v", err)
	}
}

// Only one recoverer deletes: it holds dbRecoveryMu across its validate, remove and revalidate, so a loser's validate finds the
// winner's database. The pause between attempts runs inside the first validate, which is where a recoverer without the
// lock would let another in.
func TestSqliteConcurrentRecoveryKeepsTheWinnersDatabase(t *testing.T) {
	r := newSqlRig(t, "", nil)
	r.m.closeDb()
	path := r.path(dbResolver)
	if err := os.WriteFile(path, []byte("garbage, not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	dbRetrySleep = func(time.Duration) {
		if r.m.dbRecoveryMu.TryLock() {
			r.m.dbRecoveryMu.Unlock()
			t.Error("a validate ran without dbRecoveryMu held: a second recoverer could delete the winner's database")
		}
	}
	var wg sync.WaitGroup
	results := make([]bool, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = r.m.validateDbWithRecovery(dbResolver)
		}()
	}
	wg.Wait()
	for i, ok := range results {
		if !ok {
			t.Errorf("recoverer %d failed: a losing racer must find the winner's database valid", i)
		}
	}
	r.m.dbEnqueue(resolverEvent("A", "UDP"))
	// The cached connection must write the file on disk: a loser's remove would leave it on an unlinked inode.
	if got := sqlValue(t, path, "SELECT totalqueries FROM resolver"); got != int64(1) {
		t.Errorf("the counter on disk = %v, want 1: the recovery deleted the winner's live file", got)
	}
}

// The ini's opt-in alone grants no authority: only a database that is itself opted in (client_ip = 1) yields its epoch.
func TestSqliteIniOptInNeedsTheDatabasesOwnOptIn(t *testing.T) {
	r := newSqlRig(t, "metrics_client_ip = true\nforwarding = true\n", nil)
	if len(r.m.metricsPrivacyEpochs) != 0 {
		t.Fatalf("epochs = %v from databases with client_ip = 0", r.m.metricsPrivacyEpochs)
	}
	for _, db := range []int{dbResolver, dbDnsbl} {
		sqlExec(t, r.path(db), "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
	}
	r.m.dbCapturePrivacyEpochs()
	for _, db := range []int{dbResolver, dbDnsbl} {
		want := sqlValue(t, r.path(db), "SELECT epoch FROM dns_metric_settings WHERE row=0")
		if got := r.m.metricsPrivacyEpochs[db]; got != want {
			t.Errorf("db %d: epoch %q after the opt-in, want %q", db, got, want)
		}
	}
}

// The path of a database is a path, not a URI: a ?, #, % or space in a directory name must not move the files.
func TestSqliteDatabasePathIsNotReadAsAURI(t *testing.T) {
	for _, name := range []string{"q?mark", "hash#tag", "pct%41", "sp ace", "all ?#% x"} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, name)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\nforwarding = true\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			m := modMust(t, dir)
			if !m.sqlite3ResolverCon.Load() || !m.sqlite3DnsblCon.Load() {
				t.Fatalf("a database did not open:\n%s", modCaptureLog(t))
			}
			for _, file := range sqlFileNames {
				if info, err := os.Stat(filepath.Join(dir, file)); err != nil || info.Size() == 0 {
					t.Errorf("%s is not in %s: %v", file, name, err)
				}
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != name {
				t.Errorf("the directory %q holds %d entries, want only %q: a file went elsewhere", parent, len(entries), name)
			}
		})
	}
}

// The worker flushes once the flush interval has run, though events keep arriving (so the queue is never idle) and the batch is
// small: the clock is the test's, so no wait is involved.
func TestSqliteWorkerFlushesWhenTheIntervalHasRun(t *testing.T) {
	r := newSqlRig(t, "", nil)
	queue := make(chan dbTask, 8)
	w := newDbWorker(r.m, queue)
	clock := time.Unix(1000, 0)
	w.now = func() time.Time { return clock }
	counted := func() any { return sqlValue(t, r.path(dbResolver), "SELECT totalqueries FROM resolver") }
	event := dbTask{event: resolverEvent("A", "UDP")}
	call := 0
	w.get = func() (dbTask, bool) {
		call++
		switch call {
		case 1:
			return event, true
		case 2:
			clock = clock.Add(dbFlushInterval - time.Millisecond)
			return event, true
		case 3:
			if got := counted(); got != int64(0) {
				t.Errorf("totalqueries = %v just short of the interval, want nothing flushed", got)
			}
			clock = clock.Add(time.Millisecond)
			return event, true
		case 4:
			if got := counted(); got != int64(3) {
				t.Errorf("totalqueries = %v once the interval had run, want the 3 events flushed", got)
			}
		}
		return dbTask{stop: true}, true
	}
	w.run()
}

// A detail row is written only under a live incarnation of its group and an origin that is custom or builtin, whatever the
// aggregate did.
func TestSqliteDetailRowsNeedTheGroupsLiveEpochAndAKnownOrigin(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(0, "First")})
	live := r.groupEpoch(t, "First")
	sqlExec(t, r.path(dbDnsbl), "INSERT INTO dnsbl_group_epochs VALUES ('First', 'weird', 'x')")
	odd := dbEvent{dnsbl: true, group: "First", owner: "First", origin: "weird", epoch: "x", qtype: "A", transport: "UDP"}
	deltas := map[groupKey]int64{{"First", "First", "custom", live}: 1}
	details := map[dbEvent]int64{blockEvent("First", live): 1, blockEvent("First", "stale"): 5, odd: 7}
	if !r.m.dbFlushDnsbl(deltas, details) {
		t.Fatalf("the flush failed:\n%s", r.log)
	}
	if got := sqlRows(t, r.path(dbDnsbl), "dns_metric_blocks", "groupname, origin, qtype, transport, count"); got != "First custom A UDP 1" {
		t.Errorf("dns_metric_blocks = %q, want only the live incarnation's row", got)
	}
	if got := sqlRows(t, r.path(dbDnsbl), "dns_metric_totals", "groupname, origin, count"); got != "First custom 1" {
		t.Errorf("dns_metric_totals = %q, want the live group's 1", got)
	}
}

// --- what opens the databases ---

func TestSqliteStatsWantedIsBlacklistOrForwarding(t *testing.T) {
	m := &pfbUnbound{}
	for _, c := range []struct{ blacklist, forwarding, want bool }{{false, false, false}, {true, false, true}, {false, true, true}, {true, true, true}} {
		if got := m.dnsblStatsWanted(&pfbSettings{pythonBlacklist: c.blacklist, forwarding: c.forwarding}); got != c.want {
			t.Errorf("python_blacklist=%v forwarding=%v: wanted = %v, want %v", c.blacklist, c.forwarding, got, c.want)
		}
	}
}

func TestSqliteOpenDnsblIfWantedIsIdempotentAndRetriesAfterAFailure(t *testing.T) {
	r := newSqlRig(t, "", nil)
	if r.m.sqlite3DnsblCon.Load() {
		t.Fatal("the DNSBL database opened with nothing wanting it")
	}
	wanted := &pfbSettings{pythonBlacklist: true}
	blocked := r.path(dbDnsbl)
	if err := os.MkdirAll(filepath.Join(blocked, "keep"), 0o755); err != nil { // neither openable nor removable
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep", "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.m.openDnsblStatsDbIfWanted(wanted)
	if r.m.sqlite3DnsblCon.Load() {
		t.Fatal("a database that cannot open set sqlite3_dnsbl_con")
	}
	if !strings.Contains(r.log.String(), "Failed to open pfb_py_dnsbl.sqlite database after recovery attempt") {
		t.Errorf("the failure was not reported:\n%s", r.log)
	}
	if err := os.RemoveAll(blocked); err != nil {
		t.Fatal(err)
	}
	r.m.openDnsblStatsDbIfWanted(&pfbSettings{}) // nothing wants it: no open
	if r.m.sqlite3DnsblCon.Load() {
		t.Fatal("the database opened though neither python_blacklist nor forwarding is on")
	}
	r.m.openDnsblStatsDbIfWanted(wanted)
	if !r.m.sqlite3DnsblCon.Load() {
		t.Fatalf("the database did not open once it could:\n%s", r.log)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	r.m.dbClose(dbDnsbl)
	r.m.openDnsblStatsDbIfWanted(wanted) // already open: a second call must not connect again
	if _, err := os.Stat(blocked); err == nil {
		t.Error("an already open database was opened again")
	}
}

// A database that is slow to open must not hold the publishers: the change is published first (Python's flag flips at
// once), and the open runs outside publishMu.
func assertOpensOutsidePublishMu(t *testing.T, fire func(m *pfbUnbound)) {
	t.Helper()
	r := newSqlRig(t, "", nil)
	blocked := r.path(dbDnsbl)
	if err := os.MkdirAll(filepath.Join(blocked, "keep"), 0o755); err != nil { // neither openable nor removable
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	dbRetrySleep = func(time.Duration) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fire(r.m)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the change never reached the database open")
	}
	if !r.m.snapshot.Load().settings.pythonBlacklist {
		t.Error("the change was not published before the database open began")
	}
	locked := make(chan struct{})
	go func() {
		r.m.publishMu.Lock()
		r.m.publishMu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Error("publishMu is held while the database opens: a slow open would hold every publisher")
	}
	close(release)
	<-done
}

func TestSqliteControlEnableOpensTheDatabaseOutsidePublishMu(t *testing.T) {
	assertOpensOutsidePublishMu(t, func(m *pfbUnbound) { m.pfbApplyControlCommand([]string{"python_control", "enable"}) })
}

func TestSqliteControlTimerExpiryOpensTheDatabaseOutsidePublishMu(t *testing.T) {
	assertOpensOutsidePublishMu(t, func(m *pfbUnbound) { m.controlSleep() })
}

// A swap whose settings turn forwarding on, with no list, wants the Upstream counter (issue #860): the gate is
// _dnsbl_stats_wanted, not python_blacklist alone.
func TestSqliteSwapForForwardingAloneOpensTheDnsblDatabase(t *testing.T) {
	r := newSqlRig(t, "", nil)
	if r.m.sqlite3DnsblCon.Load() {
		t.Fatal("the DNSBL database opened with nothing wanting it")
	}
	r.m.rebuildAndSwap(func() (*snapshot, error) {
		next := newSnapshot()
		settings := *r.m.snapshot.Load().settings
		settings.forwarding = true
		next.settings = &settings
		return next, nil
	}, false)
	if !r.m.sqlite3DnsblCon.Load() {
		t.Errorf("a swap with forwarding on did not open the DNSBL database:\n%s", r.log)
	}
	if _, err := os.Stat(r.path(dbDnsbl)); err != nil {
		t.Errorf("no DNSBL database file: %v", err)
	}
}

// statsOutageModule is a module with one blocked name whose two stats databases cannot be opened or recovered.
func statsOutageModule(t *testing.T) *pfbUnbound {
	t.Helper()
	dir := t.TempDir()
	for _, name := range sqlFileNames {
		if err := os.MkdirAll(filepath.Join(dir, name, "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "keep", "file"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"pfb_unbound.ini":      "[MAIN]\npython_enable = true\npython_blocking = true\npython_reply = true\ndnsbl_ipv4 = 10.10.10.1\nmetrics_client_ip = true\n",
		"pfb_py_raw/feed0.txt": "lf1.example\n",
		"pfb_py_sources.json":  `{"version": 1, "config": {}, "feeds": [{"raw": "pfb_py_raw/feed0.txt", "feed": "F1", "group": "G1", "log_flag": "1"}]}`,
	}
	for rel, text := range files {
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previous := dbRetrySleep
	dbRetrySleep = func(time.Duration) {}
	t.Cleanup(func() { dbRetrySleep = previous })
	m, err := boot(dir)
	if err != nil {
		t.Fatalf("a stats database that cannot open failed the boot: %v", err)
	}
	m.logSink = func(string, string) {}
	t.Cleanup(func() { m.closeDb(); m.stopLogging() })
	return m
}

func TestSqliteDnsKeepsAnsweringWhenTheStatsDatabasesCannotOpen(t *testing.T) {
	log := modCaptureLog(t)
	m := statsOutageModule(t)
	if m.sqlite3ResolverCon.Load() || m.sqlite3DnsblCon.Load() {
		t.Error("a database that cannot open set its availability flag")
	}
	for _, want := range []string{"Failed to open pfb_py_resolver.sqlite database", "Failed to open pfb_py_dnsbl.sqlite database"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	if len(m.metricsPrivacyEpochs) != 0 {
		t.Errorf("privacy epochs = %v: no database granted authority", m.metricsPrivacyEpochs)
	}
	f := newFrontend(m)
	wire := qtypeWire(t, "lf1.example.", 1)
	answer := f.resolve(wire, "192.0.2.10", func([]byte) []byte {
		t.Error("a blocked name was forwarded")
		return nil
	}, "UDP", "", "")
	reply, err := dnswire.Parse(answer)
	if err != nil {
		t.Fatalf("the answer does not parse: %v", err)
	}
	if reply.Rcode() != 0 || len(reply.Answers) != 1 || reply.Answers[0].Rtype != dnswire.TYPE_A || !bytes.Equal(reply.Answers[0].Rdata, []byte{10, 10, 10, 1}) {
		t.Errorf("the blocked name was answered %+v, want NOERROR with the DNSBL address 10.10.10.1", reply)
	}
	m.dbEnqueue(resolverEvent("A", "UDP")) // with the flags off nothing is counted, and nothing breaks
}

// --- epochs ---

func TestSqliteGroupEpochReadFailureKeepsDnsAvailableWithoutAccounting(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", map[string][]string{"dnsbl": sqlCustomGroups(0, "First")})
	if !r.m.sqlite3DnsblCon.Load() {
		t.Fatal("the DNSBL database did not open")
	}
	if got := r.m.dbGroupEpochs(true, r.m.snapshot.Load()); got[[2]string{"First", "custom"}] == "" {
		t.Fatalf("epochs = %v, want First/custom", got)
	}
	sqlExec(t, r.path(dbDnsbl), "DROP TABLE dnsbl_group_epochs")
	if got := r.m.dbGroupEpochs(true, r.m.snapshot.Load()); len(got) != 0 {
		t.Errorf("epochs = %v from an unreadable table, want none", got)
	}
	if r.m.sqlite3DnsblCon.Load() {
		t.Error("sqlite3_dnsbl_con stayed on after the epoch read failed")
	}
	if !strings.Contains(r.log.String(), "DNSBL accounting unavailable: ") {
		t.Errorf("the failure was not reported:\n%s", r.log)
	}
	r.m.dbEnqueue(blockEvent("First", "x")) // accounting is off: no write, no panic
}

func TestSqliteMissingOwnerEpochsAreReported(t *testing.T) {
	r := newSqlRig(t, "forwarding = true\n", nil)
	snap := newSnapshot()
	snap.dataDB["a.example"] = &blockEntry{index: 1}
	snap.feedGroupIndexDB[1] = feedGroup{feed: "F", group: "Lost"}
	// The TOP1M fallback is another rule of its own Group: its owner counts although the zone's own owner is named.
	snap.feedGroupIndexDB[2] = feedGroup{feed: "F2", group: "FallbackLost"}
	snap.zoneDB["b.example"] = &blockEntry{groupOwner: "DNSBL_Missing", groupOrigin: "builtin", hasGroupOwner: true, hasGroupOrigin: true, top1mFallback: &blockEntry{index: 2}}
	snap.regexDB.set("r", &regexEntry{groupOwner: "Rx", groupOrigin: "custom"})
	r.log.Reset()
	epochs := r.m.dbGroupEpochs(true, snap)
	if _, ok := epochs[[2]string{"Upstream", "builtin"}]; !ok {
		t.Errorf("epochs = %v, want the builtin owners", epochs)
	}
	want := "DNSBL accounting unavailable for owners: [('DNSBL_Missing', 'builtin'), ('FallbackLost', 'custom'), ('Lost', 'custom'), ('Rx', 'custom')]"
	if !strings.Contains(r.log.String(), want) {
		t.Errorf("log = %q, want it to name every owner without an epoch:\n%s", r.log, want)
	}
}

func TestSqlitePrivacyAuthorityFailureNeverBreaksDns(t *testing.T) {
	r := newSqlRig(t, "metrics_client_ip = true\nforwarding = true\n", nil)
	for _, db := range []int{dbResolver, dbDnsbl} {
		sqlExec(t, r.path(db), "UPDATE dns_metric_settings SET client_ip=1 WHERE row=0")
	}
	r.m.closeDb()
	for _, db := range []int{dbResolver, dbDnsbl} {
		if err := os.Remove(r.path(db)); err != nil {
			t.Fatal(err)
		}
		os.Remove(r.path(db) + "-wal")
		os.Remove(r.path(db) + "-shm")
		if err := os.MkdirAll(filepath.Join(r.path(db), "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r.m.dbCapturePrivacyEpochs()
	if len(r.m.metricsPrivacyEpochs) != 0 {
		t.Errorf("epochs = %v from databases that cannot be read", r.m.metricsPrivacyEpochs)
	}
	if !strings.Contains(r.log.String(), "Client metric authority unavailable") {
		t.Errorf("the failure was not reported:\n%s", r.log)
	}
	if client, epoch := r.m.metricClient(dbResolver, "192.0.2.10"); client != "" || epoch != "" {
		t.Errorf("metricClient = %q, %q without authority, want blanks", client, epoch)
	}
}

func TestSqliteMetricClientNeedsTheCapturedEpoch(t *testing.T) {
	m := &pfbUnbound{metricsPrivacyEpochs: map[int]string{dbResolver: "e1"}}
	for _, c := range []struct {
		db         int
		ip         string
		client, ep string
	}{
		{dbResolver, "192.0.2.10", "192.0.2.10", "e1"},
		{dbResolver, "::ffff:192.0.2.7", "192.0.2.7", "e1"},
		{dbResolver, "fe80::1%em0", "", "e1"},
		{dbResolver, "0.0.0.0", "", "e1"},
		{dbResolver, "Unknown", "", "e1"},
		{dbDnsbl, "192.0.2.10", "", ""},
	} {
		if client, epoch := m.metricClient(c.db, c.ip); client != c.client || epoch != c.ep {
			t.Errorf("metricClient(%d, %q) = %q, %q, want %q, %q", c.db, c.ip, client, epoch, c.client, c.ep)
		}
	}
}

// --- the counter enqueue sites ---

func TestSqliteRowWritersEnqueueTheMetricDimensions(t *testing.T) {
	block := func(f func(*dnsblDecision)) *dnsblDecision {
		d := &dnsblDecision{isFound: true, logType: "1", bType: "DNSBL", pType: "Python", feed: "F", group: "G1", bEval: "x.example", groupOwner: "G1", groupOrigin: "custom"}
		f(d)
		return d
	}
	cases := []struct {
		name   string
		nolog  bool
		epoch  string
		dnsbl  *dnsblDecision
		events []dbEvent
	}{
		{"block", false, "e", block(func(*dnsblDecision) {}), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
			{dnsbl: true, group: "G1", owner: "G1", origin: "custom", epoch: "e", qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"silent log type still counts", false, "e", block(func(d *dnsblDecision) { d.logType = "6" }), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
			{dnsbl: true, group: "G1", owner: "G1", origin: "custom", epoch: "e", qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"python_nolog VIP block: no group counter", true, "e", block(func(*dnsblDecision) {}), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"python_nolog null block counts", true, "e", block(func(d *dnsblDecision) { d.nullBlocking = true }), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
			{dnsbl: true, group: "G1", owner: "G1", origin: "custom", epoch: "e", qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"no group", false, "e", block(func(d *dnsblDecision) { d.group = "" }), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"no epoch", false, "", block(func(*dnsblDecision) {}), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
		{"whitelisted", false, "e", block(func(d *dnsblDecision) { d.inWhitelist = true }), []dbEvent{
			{qtype: "A", transport: "TCP", listenerIP: "192.0.2.1", listenerInterface: "em0", client: "192.0.2.10", clientEpoch: "pe"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSqlRig(t, "forwarding = true\n", nil)
			m := r.m
			queue := make(chan dbTask, 8)
			m.dbWorker.Store(newDbWorker(m, queue))
			t.Cleanup(func() { m.dbWorker.Store(nil) })
			m.sqlite3ResolverCon.Store(true)
			m.sqlite3DnsblCon.Store(true)
			m.metricsPrivacyEpochs = map[int]string{dbResolver: "pe", dbDnsbl: "pe"}
			settings := *m.snapshot.Load().settings
			settings.pythonNolog = c.nolog
			snap := *m.snapshot.Load()
			snap.settings = &settings
			m.snapshot.Store(&snap)
			qstate := newModuleQstate(queryInfo{"x.example.", 1, RR_CLASS_IN}, "192.0.2.10", 0, 0, "TCP", "192.0.2.1", "em0")
			qip := "192.0.2.10"
			m.getDetailsDnsbl("dnsbl", nil, qstate, &logKwargs{pfbAddr: &qip}, c.dnsbl, c.epoch)
			var got []dbEvent
			for len(queue) > 0 {
				got = append(got, (<-queue).event)
			}
			if len(got) != len(c.events) {
				t.Fatalf("enqueued %d events %+v, want %d %+v", len(got), got, len(c.events), c.events)
			}
			for i := range got {
				if got[i] != c.events[i] {
					t.Errorf("event %d = %+v, want %+v", i, got[i], c.events[i])
				}
			}
		})
	}
}

func TestSqliteMetricQtypeFallsBackToTheNumber(t *testing.T) {
	qstate := newModuleQstate(queryInfo{"x.", 65400, RR_CLASS_IN}, "", 0, 0, "", "", "")
	qinfo := &queryInfo{"x.", 28, RR_CLASS_IN}
	for _, c := range []struct {
		qstate *moduleQstate
		qinfo  *queryInfo
		qType  string
		want   string
	}{
		{qstate, nil, "A", "A"},
		{qstate, nil, "Unknown", "TYPE65400"},
		{nil, qinfo, "Unknown", "TYPE28"},
		{nil, nil, "Unknown", ""},
	} {
		if got := metricQtype(c.qstate, c.qinfo, c.qType); got != c.want {
			t.Errorf("metricQtype(%v, %v, %q) = %q, want %q", c.qstate != nil, c.qinfo != nil, c.qType, got, c.want)
		}
	}
}

// sqlite3.connect(timeout=100000) gives the connection a busy timeout of 100000 s before any PRAGMA runs, and PRAGMA
// busy_timeout=100000 then sets 100 s: a connection whose PRAGMA setup fails keeps the connect's timeout, never none.
func TestSqliteConnectHasPythonsBusyTimeoutWhetherOrNotThePragmasRun(t *testing.T) {
	busyTimeout := func(c *dbConn) int64 {
		t.Helper()
		var ms int64
		if err := c.con.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&ms); err != nil {
			t.Fatal(err)
		}
		return ms
	}
	r := newSqlRig(t, "", nil)
	r.m.dbClose(dbResolver)
	c, err := r.m.dbConnect(dbResolver)
	if err != nil {
		t.Fatal(err)
	}
	if got := busyTimeout(c); got != 100_000 {
		t.Errorf("busy_timeout after the PRAGMAs = %d ms, want 100000 (PRAGMA busy_timeout=100000)", got)
	}
	c.close()

	previous := dbPragmas
	dbPragmas = []string{"PRAGMA journal_mode=NOT A MODE ;; bad", previous[1], previous[2]}
	t.Cleanup(func() { dbPragmas = previous })
	c, err = r.m.dbConnect(dbResolver)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if got := busyTimeout(c); got != 100_000_000 {
		t.Errorf("busy_timeout when the PRAGMA setup fails first = %d ms, want 100000000 (sqlite3.connect timeout=100000 s)", got)
	}
}
