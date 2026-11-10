// Go translation of the statistics databases of pfb_unbound.py: pfb_py_resolver.sqlite and pfb_py_dnsbl.sqlite, their
// schema and migrations, the counters the row writers enqueue, the privacy epochs and group-epoch authority that gate
// them, and the worker that batches the writes off the DNS path. The driver is pure Go (modernc.org/sqlite): the gateway
// builds without cgo. What matters is the tables' rows, never the bytes of the files.
package decider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const (
	dbResolver = 1 // DB_RESOLVER
	dbDnsbl    = 2 // DB_DNSBL

	dbQueueMaxsize  = 5000        // PFB_DB_QUEUE_MAXSIZE
	dbFlushInterval = time.Second // PFB_DB_FLUSH_INTERVAL
)

var (
	// dbMaxBatch is PFB_DB_MAX_BATCH: the keys a batch holds before the worker flushes it.
	dbMaxBatch = 2000
	// dbRetrySleep is _db_run's pause between attempts.
	dbRetrySleep = time.Sleep
	// dbStopWait bounds deinit's wait for the worker (join(timeout=5)).
	dbStopWait = 5 * time.Second
	// dbPragmas are the connection settings: WAL (read back, and warned about when it did not hold), a 100 s busy timeout
	// and NORMAL synchronous.
	dbPragmas = []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=100000", "PRAGMA synchronous=NORMAL"}
	// dbBuiltinOwners is _DNSBL_BUILTIN_OWNERS: the synthetic groups every dnsbl database owns an epoch for.
	dbBuiltinOwners = []string{"Upstream", "DNSBL_IDN", "DNSBL_Homoglyph", "DNSBL_Homoglyph_Suspect", "DNSBL_TLD_Allow", "DNSBL_Regex", "DNSBL_TLD"}
)

// dbEvent is one counter increment, the tuple pfb_db_enqueue takes: a resolver event leaves the group fields empty. client
// and clientEpoch are _metric_client's pair: the address and the privacy epoch it was captured under.
type dbEvent struct {
	dnsbl                                           bool
	group, owner, origin, epoch                     string
	qtype, transport, listenerIP, listenerInterface string
	client, clientEpoch                             string
}

// groupKey is the dnsbl event's group and the epoch of its incarnation: what the per-group counter is keyed by.
type groupKey struct{ group, owner, origin, epoch string }

func (e dbEvent) groupKey() groupKey { return groupKey{e.group, e.owner, e.origin, e.epoch} }

// dbConn is an entry of _db_conns: one connection kept open, with the pool that owns it so that closing it rolls back
// whatever transaction a fault left open.
type dbConn struct {
	pool *sql.DB
	con  *sql.Conn
}

func (c *dbConn) close() {
	c.con.Close()
	c.pool.Close()
}

func (m *pfbUnbound) dbFile(db int) string {
	switch db {
	case dbResolver:
		return m.pfb.pfbPyResolver
	case dbDnsbl:
		return m.pfb.pfbPyDnsbl
	}
	return ""
}

// dbConnect is _db_connect: a new connection with its settings and the tables created. A PRAGMA that fails is logged and the
// connect goes on, on SQLite's defaults.
func (m *pfbUnbound) dbConnect(db int) (*dbConn, error) {
	path := m.dbFile(db)
	if path == "" {
		return nil, errors.New("no database path")
	}
	pool, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(1)
	ctx := context.Background()
	con, err := pool.Conn(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	c := &dbConn{pool, con}
	// A silently failed PRAGMA leaves rollback-journal instead of WAL, where a writer's commit blocks readers (issue #771):
	// the connection still works, so the connect does not fail, but the fallback must be visible in the log.
	if err := func() error {
		var mode string
		if err := con.QueryRowContext(ctx, dbPragmas[0]).Scan(&mode); err != nil {
			return err
		}
		for _, pragma := range dbPragmas[1:] {
			if _, err := con.ExecContext(ctx, pragma); err != nil {
				return err
			}
		}
		if strings.ToLower(mode) != "wal" {
			logErr(fmt.Sprintf("[pfBlockerNG]: sqlite journal_mode is '%s' (wanted 'wal') db %s: concurrent readers may hit 'database is locked'", strings.ToLower(mode), path))
		}
		return nil
	}(); err != nil {
		logErr(fmt.Sprintf("[pfBlockerNG]: sqlite PRAGMA setup failed db %s: %v", path, err))
	}
	if err := m.dbCreate(ctx, con, db); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// dbCreate is _db_create: the tables of the database, its metric settings row, all in one savepoint so that a failure
// leaves the old schema and its rows as they were.
func (m *pfbUnbound) dbCreate(ctx context.Context, c *sql.Conn, db int) (err error) {
	if _, err = c.ExecContext(ctx, "SAVEPOINT dns_metric_schema"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			c.ExecContext(ctx, "ROLLBACK TO dns_metric_schema")
			c.ExecContext(ctx, "RELEASE dns_metric_schema")
		}
	}()
	if err = m.dbCreateTables(ctx, c, db); err != nil {
		return err
	}
	for _, statement := range []string{
		"CREATE TABLE IF NOT EXISTS dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER NOT NULL, epoch TEXT NOT NULL)",
		"INSERT OR IGNORE INTO dns_metric_settings VALUES (0,0,lower(hex(randomblob(16))))",
		"RELEASE dns_metric_schema",
	} {
		if _, err = c.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (m *pfbUnbound) dbCreateTables(ctx context.Context, c *sql.Conn, db int) error {
	exec := func(query string, args ...any) error {
		_, err := c.ExecContext(ctx, query, args...)
		return err
	}
	switch db {
	case dbResolver:
		if err := exec("CREATE TABLE IF NOT EXISTS resolver (row integer, totalqueries integer, queries integer)"); err != nil {
			return err
		}
		// Seeded atomically, a no-op once present: a re-init or reconnect keeps the accumulated totals.
		if err := exec("INSERT INTO resolver ( row, totalqueries, queries ) SELECT 0, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM resolver)"); err != nil {
			return err
		}
		return dbMetricTable(ctx, c, "dns_metric_queries", []string{"qtype", "transport"})
	case dbDnsbl:
		if err := exec("CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER )"); err != nil {
			return err
		}
		// Issue #285 / #858: the synthetic Upstream group is no feed, so dnsbl_save_stats() never creates its row.
		if err := exec("INSERT INTO dnsbl ( groupname, timestamp, entries, counter ) SELECT 'Upstream', ?, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM dnsbl WHERE groupname = 'Upstream')", m.makeTimestamp()); err != nil {
			return err
		}
		if err := dbMetricTable(ctx, c, "dns_metric_blocks", []string{"owner", "origin", "groupname", "qtype", "transport"}); err != nil {
			return err
		}
		for _, statement := range []string{
			"CREATE TABLE IF NOT EXISTS dns_metric_totals (owner TEXT NOT NULL, origin TEXT NOT NULL, groupname TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(owner, origin, groupname))",
			"CREATE TABLE IF NOT EXISTS dnsbl_group_epochs (owner TEXT NOT NULL, origin TEXT NOT NULL, epoch TEXT NOT NULL, PRIMARY KEY(owner, origin))",
		} {
			if err := exec(statement); err != nil {
				return err
			}
		}
		for _, owner := range dbBuiltinOwners {
			if err := exec("INSERT OR IGNORE INTO dnsbl_group_epochs VALUES (?, 'builtin', lower(hex(randomblob(16))))", owner); err != nil {
				return err
			}
		}
		// Legacy display names prove custom ownership only outside the synthetic namespace.
		args := make([]any, len(dbBuiltinOwners))
		for i, owner := range dbBuiltinOwners {
			args[i] = owner
		}
		return exec("INSERT OR IGNORE INTO dnsbl_group_epochs SELECT DISTINCT groupname, 'custom', lower(hex(randomblob(16))) FROM dnsbl "+
			"WHERE substr(groupname, 1, 6) = 'DNSBL_' AND groupname NOT IN ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
	}
	return nil
}

// dbMetricTable creates a metric table of `labels` plus the listener and client dimensions, or migrates the one of a
// release without them (its rows carry over under blank dimensions); any other schema is refused.
func dbMetricTable(ctx context.Context, c *sql.Conn, table string, labels []string) error {
	rows, err := c.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	var columns []string
	for rows.Next() {
		var cid, notnull, pk int64
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		columns = append(columns, name)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	dimensions := append(slices.Clone(labels), "listener_ip", "listener_interface", "client_ip")
	legacy := slices.Equal(columns, append(slices.Clone(labels), "count"))
	if len(columns) > 0 && !slices.Equal(columns, append(slices.Clone(dimensions), "count")) {
		if !legacy {
			return errors.New("Unsupported DNS metric schema: " + table)
		}
		if _, err := c.ExecContext(ctx, "ALTER TABLE "+table+" RENAME TO "+table+"_old"); err != nil {
			return err
		}
	}
	definitions := make([]string, len(dimensions))
	for i, label := range dimensions {
		definitions[i] = label + " TEXT NOT NULL DEFAULT ''"
	}
	if _, err := c.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+table+" ("+strings.Join(definitions, ", ")+", count INTEGER NOT NULL, PRIMARY KEY("+strings.Join(dimensions, ",")+"))"); err != nil {
		return err
	}
	if legacy {
		list := strings.Join(labels, ",")
		if _, err := c.ExecContext(ctx, "INSERT INTO "+table+" ("+list+",count) SELECT "+list+",count FROM "+table+"_old"); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, "DROP TABLE "+table+"_old"); err != nil {
			return err
		}
	}
	return nil
}

// dbConnLocked is the cached connection of a database, opened on first use; the caller holds dbMu.
func (m *pfbUnbound) dbConnLocked(db int) (*dbConn, error) {
	if c := m.dbConns[db]; c != nil {
		return c, nil
	}
	c, err := m.dbConnect(db)
	if err != nil {
		return nil, err
	}
	if m.dbConns == nil {
		m.dbConns = map[int]*dbConn{}
	}
	m.dbConns[db] = c
	return c, nil
}

func (m *pfbUnbound) dbCloseLocked(db int) {
	if c := m.dbConns[db]; c != nil {
		c.close()
		delete(m.dbConns, db)
	}
}

// dbClose is _db_close: the connection goes, and the next use opens and creates the database again.
func (m *pfbUnbound) dbClose(db int) {
	m.dbMu.Lock()
	defer m.dbMu.Unlock()
	m.dbCloseLocked(db)
}

// closeDb is the end of deinit's database half: the worker drains and stops, then every connection closes.
func (m *pfbUnbound) closeDb() {
	m.stopDbWorker()
	m.dbMu.Lock()
	defer m.dbMu.Unlock()
	for db := range m.dbConns {
		m.dbCloseLocked(db)
	}
}

// dbRun runs work against the persistent connection. On a fault it closes the connection (which rolls the write back),
// reconnects, which creates the tables again, and runs it again: four attempts, so that a dequeued write is not dropped
// on a transient error. work holds its own transaction, committed as its last statement.
func (m *pfbUnbound) dbRun(db int, work func(ctx context.Context, c *sql.Conn) error) bool {
	m.dbMu.Lock()
	defer m.dbMu.Unlock()
	for attempt := range 4 {
		c, err := m.dbConnLocked(db)
		if err == nil {
			err = work(context.Background(), c.con)
		}
		if err == nil {
			return true
		}
		m.dbCloseLocked(db)
		if attempt == 3 {
			logErr(fmt.Sprintf("[pfBlockerNG]: sqlite write failed db %s: %v", m.dbFile(db), err))
			return false
		}
		dbRetrySleep(250 * time.Millisecond)
	}
	return false
}

// dbValidate is pfb_db_validate: the database exists with its tables.
func (m *pfbUnbound) dbValidate(db int) bool {
	return m.dbRun(db, func(context.Context, *sql.Conn) error { return nil })
}

// validateDbWithRecovery is _validate_db_with_recovery. dbRun swallows every connect or PRAGMA fault and returns false, so
// a false validate is the broken-database case (usually corruption): the file and its WAL and SHM sidecars are removed
// (each remove may fail, a read-only directory for one) and the database validated once more. The whole sequence is one
// step under dbRecoveryMu: else two recoverers could both see a corrupt file and the loser's remove would delete the
// winner's live database while the cached connection kept writing to its unlinked inode (issue #900). Lock order is
// dbRecoveryMu, then dbMu (inside dbRun), never the other way.
func (m *pfbUnbound) validateDbWithRecovery(db int) bool {
	m.dbRecoveryMu.Lock()
	defer m.dbRecoveryMu.Unlock()
	if m.dbValidate(db) {
		return true
	}
	base := m.dbFile(db)
	if base == "" {
		return false
	}
	for _, stale := range []string{base, base + "-wal", base + "-shm"} {
		os.Remove(stale)
	}
	return m.dbValidate(db)
}

// dnsblStatsWanted is _dnsbl_stats_wanted: the Upstream counter (issue #267's forwarding-mode detection) shares the dnsbl
// database with the per-feed blocks, and detection is gated on forwarding alone, so forwarding wants it as well (issue #860).
func (m *pfbUnbound) dnsblStatsWanted(settings *pfbSettings) bool {
	return settings.pythonBlacklist || settings.forwarding
}

// openDnsblStatsDbIfWanted is _open_dnsbl_stats_db_if_wanted: the dnsbl database opens when statistics are newly wanted
// but init left it closed (issues #862, #870), from the swap, the control enable and the control timer's expiry. A no-op
// once open. `settings` are the ones the caller has just made the module's.
func (m *pfbUnbound) openDnsblStatsDbIfWanted(settings *pfbSettings) {
	if !m.sqlite3DnsblCon.Load() && m.dnsblStatsWanted(settings) {
		if m.validateDbWithRecovery(dbDnsbl) {
			m.sqlite3DnsblCon.Store(true)
		} else {
			logErr("[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database after recovery attempt")
		}
	}
}

// dbGroupEpochs is _db_group_epochs: the counter authority of every group, read for the snapshot `s` being built. The
// dnsbl database opens first when statistics are wanted; it is optional, so DNS never depends on it: a database that cannot
// be read turns the accounting off and gives no epochs.
func (m *pfbUnbound) dbGroupEpochs(wanted bool, s *snapshot) map[[2]string]string {
	if !m.sqlite3DnsblCon.Load() && wanted {
		if m.validateDbWithRecovery(dbDnsbl) {
			m.sqlite3DnsblCon.Store(true)
		} else {
			logErr("[pfBlockerNG]: Failed to open pfb_py_dnsbl.sqlite database after recovery attempt")
		}
	}
	epochs := map[[2]string]string{}
	if !m.sqlite3DnsblCon.Load() {
		return epochs
	}
	m.dbMu.Lock()
	err := func() error {
		c, err := m.dbConnLocked(dbDnsbl)
		if err != nil {
			return err
		}
		rows, err := c.con.QueryContext(context.Background(), "SELECT owner, origin, epoch FROM dnsbl_group_epochs")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var owner, origin, epoch string
			if err := rows.Scan(&owner, &origin, &epoch); err != nil {
				return err
			}
			epochs[[2]string{owner, origin}] = epoch
		}
		return rows.Err()
	}()
	if err != nil {
		m.dbCloseLocked(dbDnsbl)
		m.sqlite3DnsblCon.Store(false)
		m.dbMu.Unlock()
		logErr(fmt.Sprintf("[pfBlockerNG]: DNSBL accounting unavailable: %v", err))
		return map[[2]string]string{}
	}
	m.dbMu.Unlock()
	if missing := missingEpochOwners(epochs, s); len(missing) > 0 {
		parts := make([]string, len(missing))
		for i, owner := range missing {
			parts[i] = fmt.Sprintf("(%s, %s)", pysem.Repr(owner[0]), pysem.Repr(owner[1]))
		}
		logErr(fmt.Sprintf("[pfBlockerNG]: DNSBL accounting unavailable for owners: [%s]", strings.Join(parts, ", ")))
	}
	return epochs
}

// missingEpochOwners are the (owner, origin) pairs the snapshot's data, zone and regex rules count into that have no epoch
// row, sorted. A zone entry's TOP1M fallback chain counts too.
func missingEpochOwners(epochs map[[2]string]string, s *snapshot) [][2]string {
	missing := map[[2]string]bool{}
	note := func(owner, origin string) {
		if _, ok := epochs[[2]string{owner, origin}]; owner != "" && !ok {
			missing[[2]string{owner, origin}] = true
		}
	}
	for _, rules := range []map[string]*blockEntry{s.dataDB, s.zoneDB} {
		for _, entry := range rules {
			for rule := entry; rule != nil; rule = rule.top1mFallback {
				origin, owner := "custom", ""
				if rule.hasGroupOrigin {
					origin = rule.groupOrigin
				}
				if rule.hasGroupOwner {
					owner = rule.groupOwner
				} else {
					_, owner = resolveFeedGroup(rule.index, s.feedGroupIndexDB)
				}
				note(owner, origin)
			}
		}
	}
	for _, rules := range []*regexDB{s.regexDB, s.userRegexDB} {
		if rules == nil {
			continue
		}
		for _, name := range rules.names {
			note(rules.byName[name].groupOwner, rules.byName[name].groupOrigin)
		}
	}
	out := make([][2]string, 0, len(missing))
	for owner := range missing {
		out = append(out, owner)
	}
	slices.SortFunc(out, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	return out
}

// dbCapturePrivacyEpochs is _db_capture_privacy_epochs: only init grants client-address authority, from an ini opt-in
// that the database's own opt-in (client_ip = 1) confirms; a reload or reconnect cannot authorize old events. A database
// that cannot be read grants none, and DNS is unaffected.
func (m *pfbUnbound) dbCapturePrivacyEpochs() {
	epochs := map[int]string{}
	if m.pfb.metricsClientIp {
		m.dbMu.Lock()
		for _, d := range []struct {
			db   int
			open bool
		}{{dbResolver, m.sqlite3ResolverCon.Load()}, {dbDnsbl, m.sqlite3DnsblCon.Load()}} {
			if !d.open {
				continue
			}
			err := func() error {
				c, err := m.dbConnLocked(d.db)
				if err != nil {
					return err
				}
				var epoch string
				switch err := c.con.QueryRowContext(context.Background(), "SELECT epoch FROM dns_metric_settings WHERE row=0 AND client_ip=1").Scan(&epoch); {
				case err == nil:
					epochs[d.db] = epoch
				case !errors.Is(err, sql.ErrNoRows):
					return err
				}
				return nil
			}()
			if err != nil {
				logErr(fmt.Sprintf("[pfBlockerNG]: Client metric authority unavailable: %v", err))
			}
		}
		m.dbMu.Unlock()
	}
	m.metricsPrivacyEpochs = epochs
}

// metricClient is _metric_client: the client address to count and the epoch it was granted under, or blanks when this
// process holds no authority for the database.
func (m *pfbUnbound) metricClient(db int, qIP string) (string, string) {
	if epoch := m.metricsPrivacyEpochs[db]; epoch != "" {
		return metricIp(qIP), epoch
	}
	return "", ""
}

// metricTransport is the transport a counter is labelled with: blank for one the listener did not report.
func metricTransport(transport string) string {
	if transport == "Unknown" {
		return ""
	}
	return transport
}

// metricQtype is _metric_qtype: the type name, else the number of the query's type.
func metricQtype(qstate *moduleQstate, qinfo *queryInfo, qType string) string {
	switch {
	case qType != "Unknown":
		return qType
	case qstate != nil:
		return fmt.Sprintf("TYPE%d", qstate.qinfo.qtype)
	case qinfo != nil:
		return fmt.Sprintf("TYPE%d", qinfo.qtype)
	}
	return ""
}

// dbPrivateDetails is _db_private_details: the detail rows of a batch with every client blanked that the policy, read in
// the transaction that writes them, does not grant under the epoch the event was counted under. A retained queue or a
// failed batch can therefore never write an address the owner has since taken back.
func dbPrivateDetails(ctx context.Context, c *sql.Conn, details map[dbEvent]int64) (map[dbEvent]int64, error) {
	var granted bool
	var epoch string
	var enabled int64
	switch err := c.QueryRowContext(ctx, "SELECT client_ip,epoch FROM dns_metric_settings WHERE row=0").Scan(&enabled, &epoch); {
	case err == nil:
		granted = enabled == 1
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	rows := make(map[dbEvent]int64, len(details))
	for key, count := range details {
		if !granted || key.clientEpoch != epoch {
			key.client = ""
		}
		key.clientEpoch = ""
		rows[key] += count
	}
	return rows, nil
}

// dbFlushResolver is _db_flush_resolver: the total and the detail rows of `delta` events in one transaction. It reports
// whether they were written; on false the caller keeps its details.
func (m *pfbUnbound) dbFlushResolver(delta int64, details map[dbEvent]int64) bool {
	if delta == 0 || !m.sqlite3ResolverCon.Load() {
		return true
	}
	return m.dbRun(dbResolver, func(ctx context.Context, c *sql.Conn) error {
		if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		if _, err := c.ExecContext(ctx, "UPDATE resolver SET totalqueries = totalqueries + ? WHERE row = 0", delta); err != nil {
			return err
		}
		if len(details) > 0 {
			rows, err := dbPrivateDetails(ctx, c, details)
			if err != nil {
				return err
			}
			insert, err := c.PrepareContext(ctx, "INSERT INTO dns_metric_queries (qtype,transport,listener_ip,listener_interface,client_ip,count) "+
				"SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM resolver WHERE row = 0) "+
				"ON CONFLICT(qtype,transport,listener_ip,listener_interface,client_ip) DO UPDATE SET count = count + excluded.count")
			if err != nil {
				return err
			}
			defer insert.Close()
			for key, count := range rows {
				if _, err := insert.ExecContext(ctx, key.qtype, key.transport, key.listenerIP, key.listenerInterface, key.client, count); err != nil {
					return err
				}
			}
		}
		_, err := c.ExecContext(ctx, "COMMIT")
		return err
	})
}

// dbFlushDnsbl is _db_flush_dnsbl: per group the counter, the total and, in one transaction with them, the detail rows. A
// group counts only under the epoch of its current incarnation (origin custom or builtin), so a deleted group's late
// events are not written into its successor.
func (m *pfbUnbound) dbFlushDnsbl(deltas map[groupKey]int64, details map[dbEvent]int64) bool {
	if len(deltas) == 0 || !m.sqlite3DnsblCon.Load() {
		return true
	}
	return m.dbRun(dbDnsbl, func(ctx context.Context, c *sql.Conn) error {
		// The writer lock comes first: the authority is checked under it, and all three counters commit together.
		if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		for key, count := range deltas {
			if key.origin != "custom" && key.origin != "builtin" {
				continue
			}
			var one int64
			switch err := c.QueryRowContext(ctx, "SELECT 1 FROM dnsbl_group_epochs WHERE owner=? AND origin=? AND epoch=?", key.owner, key.origin, key.epoch).Scan(&one); {
			case errors.Is(err, sql.ErrNoRows):
				continue
			case err != nil:
				return err
			}
			// Self-heals the counter row a table rebuild removed (issue #858).
			if _, err := c.ExecContext(ctx, "INSERT INTO dnsbl SELECT ?, '', 0, 0 WHERE NOT EXISTS (SELECT 1 FROM dnsbl WHERE groupname=?)", key.group, key.group); err != nil {
				return err
			}
			if _, err := c.ExecContext(ctx, "UPDATE dnsbl SET counter=counter+? WHERE groupname=?", count, key.group); err != nil {
				return err
			}
			if _, err := c.ExecContext(ctx, "INSERT INTO dns_metric_totals VALUES (?, ?, ?, ?) ON CONFLICT(owner,origin,groupname) DO UPDATE SET count=count+excluded.count",
				key.owner, key.origin, key.group, count); err != nil {
				return err
			}
		}
		if len(details) > 0 {
			rows, err := dbPrivateDetails(ctx, c, details)
			if err != nil {
				return err
			}
			insert, err := c.PrepareContext(ctx, "INSERT INTO dns_metric_blocks (owner,origin,groupname,qtype,transport,listener_ip,listener_interface,client_ip,count) "+
				"SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM dnsbl_group_epochs WHERE owner=? AND origin=? AND epoch=?) AND ? IN ('custom','builtin') "+
				"ON CONFLICT(owner,origin,groupname,qtype,transport,listener_ip,listener_interface,client_ip) DO UPDATE SET count=count+excluded.count")
			if err != nil {
				return err
			}
			defer insert.Close()
			for k, count := range rows {
				if _, err := insert.ExecContext(ctx, k.owner, k.origin, k.group, k.qtype, k.transport, k.listenerIP, k.listenerInterface, k.client, count,
					k.owner, k.origin, k.epoch, k.origin); err != nil {
					return err
				}
			}
		}
		_, err := c.ExecContext(ctx, "COMMIT")
		return err
	})
}

// dbApply is _db_apply: the synchronous write of one event, for a module with no worker.
func (m *pfbUnbound) dbApply(event dbEvent) {
	if event.dnsbl {
		m.dbFlushDnsbl(map[groupKey]int64{event.groupKey(): 1}, map[dbEvent]int64{event: 1})
	} else {
		m.dbFlushResolver(1, map[dbEvent]int64{event: 1})
	}
}

// dbEnqueue is pfb_db_enqueue: the event goes to the worker, or is dropped (and counted) when its queue is full, so the DNS
// path is never held; with no worker it is written synchronously.
func (m *pfbUnbound) dbEnqueue(event dbEvent) {
	w := m.dbWorker.Load()
	if w == nil {
		m.dbApply(event)
		return
	}
	select {
	case w.queue <- dbTask{event: event}:
	default:
		m.dbDropped.Add(1)
	}
}

// dbTask is one entry of the worker's queue: an event, or the stop.
type dbTask struct {
	event dbEvent
	stop  bool
}

// dbWorker is pfb_db_worker: it batches the counter writes off the DNS path. Increments accumulate as per-key deltas (they
// commute) and flush on the interval, on a full batch, when the queue runs idle and on the stop.
type dbWorker struct {
	m        *pfbUnbound
	queue    chan dbTask
	done     chan struct{}
	maxBatch int
	// get returns the next task, or false when the flush interval ran out with none; a test replaces it to place an
	// idle interval where it needs one.
	get func() (dbTask, bool)
}

func newDbWorker(m *pfbUnbound, queue chan dbTask) *dbWorker {
	w := &dbWorker{m: m, queue: queue, done: make(chan struct{}), maxBatch: dbMaxBatch}
	w.get = w.next
	return w
}

func (w *dbWorker) next() (dbTask, bool) {
	select {
	case task := <-w.queue:
		return task, true
	default:
	}
	idle := time.NewTimer(dbFlushInterval)
	defer idle.Stop()
	select {
	case task := <-w.queue:
		return task, true
	case <-idle.C:
		return dbTask{}, false
	}
}

func (w *dbWorker) run() {
	defer close(w.done)
	var resolverDelta int64
	deltas := map[groupKey]int64{}
	resolverDetails, dnsblDetails := map[dbEvent]int64{}, map[dbEvent]int64{}
	lastFlush := time.Now()
	accumulate := func(task dbTask) {
		if task.event.dnsbl {
			deltas[task.event.groupKey()]++
			dnsblDetails[task.event]++
		} else {
			resolverDelta++
			resolverDetails[task.event]++
		}
	}
	// A flush that fails keeps its batch: the next one writes it, once.
	flush := func() {
		if resolverDelta != 0 && w.m.dbFlushResolver(resolverDelta, resolverDetails) {
			resolverDelta, resolverDetails = 0, map[dbEvent]int64{}
		}
		if len(deltas) > 0 && w.m.dbFlushDnsbl(deltas, dnsblDetails) {
			deltas, dnsblDetails = map[groupKey]int64{}, map[dbEvent]int64{}
		}
		lastFlush = time.Now()
	}
	for {
		task, ok := w.get()
		stop := ok && task.stop
		if stop {
			for drained := true; drained; {
				select {
				case t := <-w.queue:
					if !t.stop {
						accumulate(t)
					}
				default:
					drained = false
				}
			}
		} else if ok {
			accumulate(task)
		}
		if stop || !ok || int(resolverDelta)+len(deltas) >= w.maxBatch || time.Since(lastFlush) >= dbFlushInterval {
			flush()
		}
		if stop {
			return
		}
	}
}

// startDbWorker starts the worker unless one runs (init_standard, after the privacy epochs are captured).
func (m *pfbUnbound) startDbWorker() {
	if m.dbWorker.Load() != nil {
		return
	}
	w := newDbWorker(m, make(chan dbTask, dbQueueMaxsize))
	m.dbWorker.Store(w)
	go w.run()
}

// stopDbWorker is deinit's stop of the worker: it drains and flushes what is queued, waiting at most dbStopWait for it,
// and later events are written synchronously. A second stop does nothing.
func (m *pfbUnbound) stopDbWorker() {
	w := m.dbWorker.Load()
	if w == nil {
		return
	}
	timeout := time.NewTimer(dbStopWait)
	defer timeout.Stop()
	select {
	case w.queue <- dbTask{stop: true}:
		select {
		case <-w.done:
		case <-timeout.C:
		}
	case <-timeout.C:
	}
	m.dbWorker.Store(nil)
}
