// The upstream observer's reports against what the shipped pfb_unbound.py does with the same datagrams: every scenario in
// testdata/pfb_unbound_observer_oracle.json (gen_pfb_unbound_observer_oracle.py) boots a forwarding module and feeds each
// datagram through the Frontend. For each one the dnsbl.log rows, the lines printed to stderr and the answer to one fixed
// query before and after it must be Python's, and after each dump step both stats databases must hold Python's tables.
// The first malformed report's warning is compared whole where Python's text is the proxy's own; where it is a Python
// library's exception text (a JSON, a decoding or a recursion error) only the class is compared, see observerWarningMatches.
package decider

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type observerStep struct {
	Op          string
	Note        string
	Hex         string
	NewFrontend bool `json:"new_frontend"`
	Rows        [][2]string
	// RowsWtf8 stands for Rows when a row holds a lone surrogate, which JSON cannot hand a Go reader: the row's bytes as
	// Python's surrogatepass codec writes them, in hex.
	RowsWtf8   [][2]string `json:"rows_wtf8"`
	Stderr     []string
	Before     *string
	After      *string
	DB         string
	Statements []string
	Dump       sqlDump

	// the fire step: the shim's fire_query_response with a qstate of the test's own making
	Qname     string
	Qtype     uint16
	Client    string
	Transport string
	Lip, Lif  string
	Flags     uint16
	Opts      [][]any
}

type observerScenario struct {
	Name  string
	Files map[string]string
	Steps []observerStep
}

type observerOracle struct {
	Python    string
	Stamp     string
	Now       int64
	Constants struct {
		MaxReportBytes     int `json:"max_report_bytes"`
		MaxReportOptions   int `json:"max_report_options"`
		MaxReportOptionHex int `json:"max_report_option_hex"`
		MaxReportQname     int `json:"max_report_qname"`
	}
	Probe struct {
		Wire, Reply, Client, Transport string
	}
	Scenarios []observerScenario
}

func loadObserverOracle(t *testing.T) *observerOracle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_observer_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o observerOracle
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	if o.Stamp != "2026-10-18 12:00:00" || o.Now != 1792324800 {
		t.Fatalf("oracle clock = %q / %d: the Go clock is built from it", o.Stamp, o.Now)
	}
	return &o
}

const observerWarningPrefix = "pfb_dns_proxy warning: malformed upstream report from the observer, ignored (further ones silently): "

// observerWarningMatches is whether the decider's stderr line is Python's. The reason after the fixed text is compared
// byte for byte, except where Python prints a library exception whose text carries a position or a codec's detail
// (JSONDecodeError, RecursionError, UnicodeDecodeError): those are matched by class, to the decider's one fixed reason.
func observerWarningMatches(got, want string) bool {
	reason, ok := strings.CutPrefix(want, observerWarningPrefix)
	if !ok {
		return got == want
	}
	if text, ok := strings.CutPrefix(reason, "not a report: "); ok {
		switch {
		case strings.HasPrefix(text, "JSONDecodeError("), strings.HasPrefix(text, "RecursionError("):
			return got == observerWarningPrefix+"not a report: invalid JSON"
		case strings.HasPrefix(text, "UnicodeDecodeError("):
			return got == observerWarningPrefix+"not a report: not text in UTF-8, UTF-16 or UTF-32"
		}
	}
	return got == want
}

func linesOf(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func TestObserverReportsMatchPython(t *testing.T) {
	o := loadObserverOracle(t)
	datagrams, dumps, rowsSeen, malformedFixtures := 0, 0, 0, 0
	for _, sc := range o.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			stderr := modCaptureLog(t)
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
			var rows [][2]string
			collect := func(name, line string) { rows = append(rows, [2]string{name, line}) }
			var m *pfbUnbound
			var frontend *Frontend
			start := func() {
				var err error
				if m, err = boot(dir); err != nil {
					t.Fatal(err)
				}
				m.clock = func() time.Time { return time.Unix(o.Now, 0).UTC() }
				m.logSink = collect
				m.stopDbWorker() // later counters are written synchronously, as in the generator
				frontend = newFrontend(m)
			}
			start()
			t.Cleanup(func() { m.closeDb(); m.stopLogging() })
			// probe is Frontend.resolve's answer to the fixed query; the rows the query itself writes are not the scenario's.
			probe := func() *string {
				mark := len(rows)
				answer := newFrontend(m).resolve(mustHex(t, o.Probe.Wire), o.Probe.Client, func([]byte) []byte {
					return mustHex(t, o.Probe.Reply)
				}, o.Probe.Transport, "", "")
				rows = rows[:mark]
				if answer == nil {
					return nil
				}
				text := fmt.Sprintf("%x", answer)
				return &text
			}
			same := func(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
			// observe runs `act` between two probes and compares what it wrote with Python's.
			observe := func(i int, step observerStep, act func()) {
				datagrams++
				before := probe()
				mark := len(rows)
				stderr.Reset()
				act()
				got := append([][2]string(nil), rows[mark:]...)
				rows = rows[:mark]
				printed := linesOf(stderr.String())
				after := probe()
				rowsSeen += len(got)
				want := step.Rows
				if step.RowsWtf8 != nil {
					want = nil
					for _, row := range step.RowsWtf8 {
						want = append(want, [2]string{row[0], string(mustHex(t, row[1]))})
					}
				}
				if len(got) != len(want) || (len(got) > 0 && !reflect.DeepEqual(got, want)) {
					t.Errorf("step %d (%s): rows\n  go:     %q\n  python: %q", i, step.Note, got, want)
				}
				if len(printed) != len(step.Stderr) {
					t.Errorf("step %d (%s): stderr\n  go:     %q\n  python: %q", i, step.Note, printed, step.Stderr)
				} else {
					for j := range printed {
						if !observerWarningMatches(printed[j], step.Stderr[j]) {
							t.Errorf("step %d (%s): stderr line %d\n  go:     %q\n  python: %q", i, step.Note, j, printed[j], step.Stderr[j])
						}
					}
				}
				if !same(before, step.Before) || !same(after, step.After) || !same(before, after) {
					t.Errorf("step %d (%s): the answer to the fixed query changed or differs from Python's: before %v after %v, python %v / %v",
						i, step.Note, deref(before), deref(after), deref(step.Before), deref(step.After))
				}
			}
			for i, step := range sc.Steps {
				switch step.Op {
				case "datagram":
					if strings.HasPrefix(step.Note, "malformed: ") {
						malformedFixtures++
					}
					if step.NewFrontend {
						frontend = newFrontend(m)
					}
					observe(i, step, func() { frontend.relayUpstreamResponse(mustHex(t, step.Hex)) })
				case "fire":
					qstate := newModuleQstate(queryInfo{step.Qname, step.Qtype, 1}, step.Client, 0, 0, step.Transport, step.Lip, step.Lif)
					for _, opt := range step.Opts {
						qstate.ednsOptsBackInIter = append(qstate.ednsOptsBackInIter, ednsOpt{uint16(opt[0].(float64)), mustHex(t, opt[1].(string))})
					}
					observe(i, step, func() { m.fireQueryResponse(qstate, newDnsMsg(qstate.qinfo, step.Flags, nil, nil, nil)) })
				case "dump":
					dumps++
					got := dumpSqlFiles(t, dir, o.Stamp)
					if !reflect.DeepEqual(got, step.Dump) {
						t.Errorf("step %d: the databases differ from Python's:%s", i, describeSqlDumpDiff(got, step.Dump))
					}
				case "sql":
					sqlExec(t, filepath.Join(dir, sqlFileNames[step.DB]), step.Statements...)
				case "reboot":
					m.closeDb()
					m.stopLogging()
					start()
				case "gate_off":
					m.sqlite3DnsblCon.Store(false)
				case "drop_epoch":
					delete(m.snapshot.Load().groupEpochs, [2]string{"Upstream", "builtin"})
				case "log_raises":
					m.logSink = func(string, string) { panic("boom") }
				case "log_works":
					m.logSink = collect
				default:
					t.Fatalf("step %d: unknown op %q", i, step.Op)
				}
			}
		})
	}
	if datagrams < 359 || dumps < 23 || rowsSeen < 209 || malformedFixtures < 27 {
		t.Errorf("the oracle compared %d datagrams and fires, %d dumps, %d rows, %d malformed fixtures: want the full set (359, 23, 209, 27 or more)",
			datagrams, dumps, rowsSeen, malformedFixtures)
	}
}

func deref(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}

// TestObserverLimitsMatchPython pins the receiver's four caps to the proxy's.
func TestObserverLimitsMatchPython(t *testing.T) {
	c := loadObserverOracle(t).Constants
	for name, pair := range map[string][2]int{
		"MAX_REPORT_BYTES":      {maxReportBytes, c.MaxReportBytes},
		"MAX_REPORT_OPTIONS":    {maxReportOptions, c.MaxReportOptions},
		"MAX_REPORT_OPTION_HEX": {maxReportOptionHex, c.MaxReportOptionHex},
		"MAX_REPORT_QNAME":      {maxReportQname, c.MaxReportQname},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %d here, %d in Python", name, pair[0], pair[1])
		}
	}
}
