// The stats databases against what the shipped pfb_unbound.py leaves in them for the same steps: every scenario in
// testdata/pfb_unbound_sqlite_oracle.json (gen_pfb_unbound_sqlite_oracle.py) stages a module directory, boots a module,
// replays its queries, direct counter writes, SQL and lifecycle steps with the clock fixed, and after each dump step both
// databases must hold the same tables, columns and rows. A randomblob epoch is compared as one token per distinct value
// and the init-time stamp of the Upstream seed row as "<now>"; the .sqlite bytes are not compared.
package decider

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// countedKey is one [[key...], n] pair of a flush step.
type countedKey struct {
	Key []string
	N   int64
}

func (c *countedKey) UnmarshalJSON(b []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &c.Key); err != nil {
		return err
	}
	return json.Unmarshal(raw[1], &c.N)
}

type sqlTable struct {
	SQL     string
	Columns [][]any
	Rows    [][]any
}

type sqlDump map[string]map[string]sqlTable // "resolver" / "dnsbl" -> table -> contents; nil: no file

type sqlStep struct {
	Op         string
	DB         string
	Statements []string
	Name       string
	Query      string
	Task       []string
	Delta      int64
	Details    []countedKey
	Deltas     []countedKey
	Command    []string
	WithList   bool `json:"with_list"`

	Wire      string
	Qname     string
	Qtype     uint16
	Client    string
	Transport string
	Lip, Lif  string
	Forwards  []string

	MType  string `json:"m_type"`
	Qstate *logQstate
	Qinfo  *logQinfo
	Kwargs map[string]string
	Dnsbl  json.RawMessage
	Epoch  string

	Dump sqlDump
}

type sqlScenario struct {
	Name   string
	Files  map[string]string
	Presql map[string][]string
	Worker bool
	Steps  []sqlStep
}

type sqlOracle struct {
	Python    string
	Stamp     string
	Now       int64
	Constants struct {
		QueueMaxsize  int      `json:"queue_maxsize"`
		FlushInterval float64  `json:"flush_interval"`
		MaxBatch      int      `json:"max_batch"`
		BuiltinOwners []string `json:"builtin_owners"`
	}
	Scenarios []sqlScenario
}

func loadSqlOracle(t *testing.T) *sqlOracle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_sqlite_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o sqlOracle
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	return &o
}

var sqlFileNames = map[string]string{"resolver": "pfb_py_resolver.sqlite", "dnsbl": "pfb_py_dnsbl.sqlite"}

// openSqlFile is a connection of the test's own to a stats database, the way PHP or a test of the Python suite opens one.
func openSqlFile(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func sqlExec(t *testing.T, path string, statements ...string) {
	t.Helper()
	db := openSqlFile(t, path)
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

func sqlValue(t *testing.T, path, query string, args ...any) any {
	t.Helper()
	var value any
	if err := openSqlFile(t, path).QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return value
}

// sqlCell is a value as the oracle's JSON holds it: numbers float64, text string, NULL nil.
func sqlCell(value any) any {
	switch v := value.(type) {
	case int64:
		return float64(v)
	case []byte:
		return string(v)
	}
	return value
}

// cellOrder is the order the generator sorts a row's cells in: NULL, then numbers, then text.
func cellOrder(value any, masked bool) (int, float64, string) {
	if masked {
		return 2, 0, "<epoch>"
	}
	switch v := value.(type) {
	case nil:
		return 0, 0, ""
	case float64:
		return 1, v, ""
	}
	return 2, 0, value.(string)
}

func compareRows(a, b []any, masked []bool) int {
	for i := range a {
		ra, na, sa := cellOrder(a[i], masked[i])
		rb, nb, sb := cellOrder(b[i], masked[i])
		switch {
		case ra != rb:
			return ra - rb
		case na != nb:
			if na < nb {
				return -1
			}
			return 1
		case sa != sb:
			return strings.Compare(sa, sb)
		}
	}
	return 0
}

var (
	epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	stampPattern = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$`)
)

// dumpSqlFiles is the generator's dump_all: both databases, every table sorted by name and its rows by their cells with
// the epochs masked, the epochs then named E1, E2... in the order they first appear.
func dumpSqlFiles(t *testing.T, dir, stamp string) sqlDump {
	t.Helper()
	tokens := map[string]string{}
	out := sqlDump{}
	for _, label := range []string{"resolver", "dnsbl"} {
		path := filepath.Join(dir, sqlFileNames[label])
		if _, err := os.Stat(path); err != nil {
			out[label] = nil
			continue
		}
		db := openSqlFile(t, path)
		names := sqlStrings(t, db, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
		tables := map[string]sqlTable{}
		for _, table := range names {
			var tableSQL string
			if err := db.QueryRow("SELECT sql FROM sqlite_master WHERE name=?", table).Scan(&tableSQL); err != nil {
				t.Fatal(err)
			}
			var columns [][]any
			var masked []bool
			var types []string
			info, err := db.Query("PRAGMA table_info(" + table + ")")
			if err != nil {
				t.Fatal(err)
			}
			for info.Next() {
				var cid, notnull, pk int64
				var name, ctype string
				var dflt any
				if err := info.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
					t.Fatal(err)
				}
				columns = append(columns, []any{name, ctype, float64(notnull), sqlCell(dflt), float64(pk)})
				masked = append(masked, name == "epoch")
				types = append(types, name)
			}
			info.Close()
			rows, err := db.Query("SELECT * FROM " + table)
			if err != nil {
				t.Fatal(err)
			}
			raw := [][]any{}
			for rows.Next() {
				cells := make([]any, len(columns))
				ptrs := make([]any, len(columns))
				for i := range cells {
					ptrs[i] = &cells[i]
				}
				if err := rows.Scan(ptrs...); err != nil {
					t.Fatal(err)
				}
				for i := range cells {
					cells[i] = sqlCell(cells[i])
				}
				raw = append(raw, cells)
			}
			rows.Close()
			slices.SortStableFunc(raw, func(a, b []any) int { return compareRows(a, b, masked) })
			for _, row := range raw {
				for i, value := range row {
					text, isText := value.(string)
					switch {
					case masked[i]:
						if !epochPattern.MatchString(text) {
							t.Fatalf("%s.%s: epoch %v is not 32 hex digits", label, table, value)
						}
						if tokens[text] == "" {
							tokens[text] = fmt.Sprintf("E%d", len(tokens)+1)
						}
						row[i] = tokens[text]
					case types[i] == "timestamp" && isText && stampPattern.MatchString(text) && text != stamp:
						row[i] = "<now>"
					}
				}
			}
			tables[table] = sqlTable{SQL: tableSQL, Columns: columns, Rows: raw}
		}
		out[label] = tables
	}
	return out
}

func sqlStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// sqlDecisionDefaults are the generator's DECISION: what a details_dnsbl step leaves unset.
const sqlDecisionDefaults = `{"is_found":true,"in_whitelist":false,"in_hsts":false,"null_blocking":false,"nxdomain":false,
"log_type":"1","b_type":"DNSBL","p_type":"Python","feed":"Feed","group":"G1","b_eval":"example.com",
"group_owner":"G1","group_origin":"custom"}`

func sqlDecisionOf(t *testing.T, overrides json.RawMessage) *dnsblDecision {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(sqlDecisionDefaults), &fields); err != nil {
		t.Fatal(err)
	}
	var set map[string]json.RawMessage
	if err := json.Unmarshal(overrides, &set); err != nil {
		t.Fatal(err)
	}
	for key, value := range set {
		fields[key] = value
	}
	merged, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return logDnsblOf(t, merged)
}

// sqlEventOf is the tuple pfb_db_enqueue takes: ("resolver", qtype, transport, listener ip, interface, client, epoch) or
// ("dnsbl", group, owner, origin, group epoch, qtype, transport, listener ip, interface, client, epoch).
func sqlEventOf(task []string) dbEvent {
	if task[0] == "resolver" {
		return dbEvent{qtype: task[1], transport: task[2], listenerIP: task[3], listenerInterface: task[4], client: task[5], clientEpoch: task[6]}
	}
	return dbEvent{
		dnsbl: true, group: task[1], owner: task[2], origin: task[3], epoch: task[4], qtype: task[5], transport: task[6],
		listenerIP: task[7], listenerInterface: task[8], client: task[9], clientEpoch: task[10],
	}
}

func TestSqliteStatsMatchPython(t *testing.T) {
	o := loadSqlOracle(t)
	if o.Stamp != "2026-10-18 12:00:00" || o.Now != 1792324800 {
		t.Fatalf("oracle clock = %q / %d: the Go clock below is built from it", o.Stamp, o.Now)
	}
	variable := regexp.MustCompile(`\$(\w+)`)
	dumps := 0
	for _, sc := range o.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			modCaptureLog(t)
			previousSleep := dbRetrySleep
			dbRetrySleep = func(time.Duration) {} // an unusable file is retried at once: Python's pause is not under test
			t.Cleanup(func() { dbRetrySleep = previousSleep })
			dir := t.TempDir()
			for rel, text := range sc.Files {
				target := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(text), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for db, statements := range sc.Presql {
				sqlExec(t, filepath.Join(dir, sqlFileNames[db]), statements...)
			}
			vars := map[string]string{}
			sub := func(s string) string {
				return variable.ReplaceAllStringFunc(s, func(m string) string { return vars[m[1:]] })
			}
			var m *pfbUnbound
			start := func() {
				var err error
				if m, err = boot(dir); err != nil {
					t.Fatal(err)
				}
				m.clock = func() time.Time { return time.Unix(o.Now, 0).UTC() }
				m.logSink = func(string, string) {}
				if !sc.Worker {
					m.stopDbWorker()
				}
			}
			start()
			t.Cleanup(func() { m.closeDb(); m.stopLogging() })
			number := map[string]int{"resolver": dbResolver, "dnsbl": dbDnsbl}
			for i := range sc.Steps {
				step := &sc.Steps[i]
				switch step.Op {
				case "sql":
					statements := make([]string, len(step.Statements))
					for j, statement := range step.Statements {
						statements[j] = sub(statement)
					}
					sqlExec(t, filepath.Join(dir, sqlFileNames[step.DB]), statements...)
				case "let":
					vars[step.Name] = fmt.Sprint(sqlValue(t, filepath.Join(dir, sqlFileNames[step.DB]), step.Query))
				case "dump":
					dumps++
					got := dumpSqlFiles(t, dir, o.Stamp)
					if !reflect.DeepEqual(got, step.Dump) {
						t.Errorf("step %d: the databases differ from Python's:%s", i, describeSqlDumpDiff(got, step.Dump))
					}
				case "reconnect":
					m.dbClose(number[step.DB])
					if !m.dbValidate(number[step.DB]) {
						t.Fatalf("step %d: %s did not reopen", i, step.DB)
					}
				case "remove":
					m.dbClose(number[step.DB])
					for _, suffix := range []string{"", "-wal", "-shm"} {
						os.Remove(filepath.Join(dir, sqlFileNames[step.DB]) + suffix)
					}
				case "reboot":
					m.closeDb()
					m.stopLogging()
					start()
				case "stop":
					m.stopDbWorker()
				case "refresh_epochs":
					snap := m.snapshot.Load()
					for key, epoch := range m.dbGroupEpochs(true, snap) {
						snap.groupEpochs[key] = epoch
					}
				case "enqueue":
					task := make([]string, len(step.Task))
					for j, field := range step.Task {
						task[j] = sub(field)
					}
					m.dbEnqueue(sqlEventOf(task))
				case "flush_resolver":
					details := map[dbEvent]int64{}
					for _, d := range step.Details {
						key := make([]string, len(d.Key))
						for j, field := range d.Key {
							key[j] = sub(field)
						}
						details[sqlEventOf(append([]string{"resolver"}, key...))] += d.N
					}
					m.dbFlushResolver(step.Delta, details)
				case "flush_dnsbl":
					deltas, details := map[groupKey]int64{}, map[dbEvent]int64{}
					for _, d := range step.Deltas {
						deltas[groupKey{sub(d.Key[0]), sub(d.Key[1]), sub(d.Key[2]), sub(d.Key[3])}] += d.N
					}
					for _, d := range step.Details {
						key := make([]string, len(d.Key))
						for j, field := range d.Key {
							key[j] = sub(field)
						}
						details[sqlEventOf(append([]string{"dnsbl"}, key...))] += d.N
					}
					m.dbFlushDnsbl(deltas, details)
				case "control":
					m.pfbApplyControlCommand(step.Command)
				case "control_sleep":
					m.controlSleep()
				case "swap":
					m.rebuildAndSwap(func() (*snapshot, error) {
						next := *m.snapshot.Load()
						next.gen = snapshotGen.Add(1)
						next.dataDB = map[string]*blockEntry{}
						if step.WithList {
							next.dataDB["swapped.example"] = &blockEntry{log: "1"}
						}
						return &next, nil
					}, false)
				case "resolve":
					next := 0
					newFrontend(m).Resolve(mustHex(t, step.Wire), step.Client, func([]byte) []byte {
						if next >= len(step.Forwards) {
							t.Errorf("step %d: the decider asked Unbound %d times, Python %d", i, next+1, len(step.Forwards))
							return nil
						}
						reply := step.Forwards[next]
						next++
						return mustHex(t, reply)
					}, step.Transport, step.Lip, step.Lif)

					if next != len(step.Forwards) {
						t.Errorf("step %d: the decider asked Unbound %d times, Python %d", i, next, len(step.Forwards))
					}
				case "details_reply":
					if err := m.getDetailsReply(step.MType, step.Qinfo.build(), step.Qstate.build(t), nil, logKwargsOf(step.Kwargs)); err != nil {
						t.Fatalf("step %d: %v", i, err)
					}
				case "details_dnsbl":
					decision := sqlDecisionOf(t, step.Dnsbl)
					epoch := step.Epoch
					if epoch == "@snap" {
						epoch = m.snapshot.Load().groupEpochs[[2]string{decision.groupOwner, decision.groupOrigin}]
					} else {
						epoch = sub(epoch)
					}
					m.getDetailsDnsbl("dnsbl", nil, step.Qstate.build(t), logKwargsOf(step.Kwargs), decision, epoch)
				default:
					t.Fatalf("step %d: unknown op %q", i, step.Op)
				}
			}
		})
	}
	if dumps < 35 {
		t.Errorf("the oracle compared %d dumps, want the full set (35 or more)", dumps)
	}
}

// describeSqlDumpDiff names the first tables whose contents differ, with both sides' rows.
func describeSqlDumpDiff(got, want sqlDump) string {
	var out strings.Builder
	shown := 0
	for _, label := range []string{"resolver", "dnsbl"} {
		g, w := got[label], want[label]
		if (g == nil) != (w == nil) {
			fmt.Fprintf(&out, "\n  %s: Go has file = %v, Python has file = %v", label, g != nil, w != nil)
			continue
		}
		names := map[string]bool{}
		for name := range g {
			names[name] = true
		}
		for name := range w {
			names[name] = true
		}
		sorted := make([]string, 0, len(names))
		for name := range names {
			sorted = append(sorted, name)
		}
		slices.Sort(sorted)
		for _, name := range sorted {
			if reflect.DeepEqual(g[name], w[name]) || shown >= 6 {
				continue
			}
			shown++
			gj, _ := json.Marshal(g[name])
			wj, _ := json.Marshal(w[name])
			fmt.Fprintf(&out, "\n  %s.%s\n    go:     %s\n    python: %s", label, name, gj, wj)
		}
	}
	return out.String()
}

// TestSqliteConstantsMatchPython pins the worker's constants and the builtin owner list to the module's.
func TestSqliteConstantsMatchPython(t *testing.T) {
	c := loadSqlOracle(t).Constants
	if dbQueueMaxsize != c.QueueMaxsize {
		t.Errorf("PFB_DB_QUEUE_MAXSIZE = %d in Python, %d here", c.QueueMaxsize, dbQueueMaxsize)
	}
	if dbFlushInterval != time.Duration(c.FlushInterval*float64(time.Second)) {
		t.Errorf("PFB_DB_FLUSH_INTERVAL = %v s in Python, %v here", c.FlushInterval, dbFlushInterval)
	}
	if dbMaxBatch != c.MaxBatch {
		t.Errorf("PFB_DB_MAX_BATCH = %d in Python, %d here", c.MaxBatch, dbMaxBatch)
	}
	owners := make([]string, len(dbBuiltinOwners))
	for i, owner := range dbBuiltinOwners {
		owners[i] = owner.(string)
	}
	if !reflect.DeepEqual(owners, c.BuiltinOwners) {
		t.Errorf("_DNSBL_BUILTIN_OWNERS = %q in Python, %q here", c.BuiltinOwners, owners)
	}
}
