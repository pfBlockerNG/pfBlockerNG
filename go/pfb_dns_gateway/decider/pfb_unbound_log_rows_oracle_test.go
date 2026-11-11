// The DNSBL and DNS Reply log rows against what the shipped pfb_unbound.py writes for the same steps: every scenario in
// testdata/pfb_unbound_log_rows_oracle.json (frozen: its generator was removed in #3791, see testdata/README) boots a module from the staged files and
// replays its queries, reply callbacks and direct row-writer calls with the clock fixed; the rows must be the same bytes.
// The tables hold the pure helpers the rows are built from.
package decider

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/dnswire"
)

type logRrset struct {
	Type string
	Data []string
}

func (r *logRrset) UnmarshalJSON(b []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &r.Type); err != nil {
		return err
	}
	return json.Unmarshal(raw[1], &r.Data)
}

type logRep struct {
	Ttl    uint32
	Rrsets []logRrset
	An     *int
}

type logQinfo struct {
	Qname string
	Qtype uint16
}

type logQstate struct {
	Qname       string
	Qtype       uint16
	Client      *string
	Transport   *string
	Lip, Lif    string
	ReturnRcode int `json:"return_rcode"`
	ReturnMsg   *struct {
		Qname string
		Qtype *uint16
		Rep   *logRep
	} `json:"return_msg"`
}

type logStep struct {
	Op        string
	Qname     string
	Qtype     uint16
	Wire      string
	Client    string
	Transport string
	Lip, Lif  string
	Forwards  []*string
	Kind      string
	Qstate    *logQstate
	Rep       *logRep
	MType     string `json:"m_type"`
	Qinfo     *logQinfo
	Kwargs    map[string]string
	Dnsbl     json.RawMessage
	Raises    bool
	QName     string   `json:"q_name"`
	QIP       string   `json:"q_ip"`
	Alert     []string `json:"alert"`
	QType     string   `json:"q_type"`
	Msg       bool
	Authority int
	Relay     bool
	// ReturnRcode is the send op's: the qstate's rcode
	ReturnRcode int `json:"return_rcode"`
	Rows        [][2]string
}

type logScenario struct {
	Name  string
	Files map[string]string
	Mmdb  string
	Steps []logStep
}

type logTables struct {
	LogText []struct{ In, Out string } `json:"log_text"`
	CsvRow  []struct {
		In  []string
		Out string
	} `json:"csv_row"`
	QTransport []struct{ In, Out string }    `json:"q_transport"`
	MetricIp   []struct{ In, Out string }    `json:"metric_ip"`
	QListener  []struct{ In, Out [2]string } `json:"q_listener"`
	Convert    struct {
		Ipv4, Ipv6, Other []struct {
			In    string
			Out   string
			Error bool
		}
	}
}

type logOracle struct {
	Python    string
	Maxminddb string
	Stamp     string
	Now       int64
	Tables    logTables
	Scenarios []logScenario
}

func loadLogOracle(t *testing.T) *logOracle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "pfb_unbound_log_rows_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var o logOracle
	if err := json.Unmarshal(data, &o); err != nil {
		t.Fatal(err)
	}
	return &o
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (r *logRep) build(t *testing.T) *replyInfo {
	if r == nil {
		return nil
	}
	rep := &replyInfo{ttl: r.Ttl}
	for _, set := range r.Rrsets {
		data := &rrSetData{}
		for _, x := range set.Data {
			data.rrData = append(data.rrData, mustHex(t, x))
			data.rrTTL = append(data.rrTTL, r.Ttl)
		}
		data.count = len(data.rrData)
		rep.rrsets = append(rep.rrsets, &rrSet{rrSetKey{set.Type}, rrSetEntry{data}})
	}
	rep.anNumrrsets = len(rep.rrsets)
	if r.An != nil {
		rep.anNumrrsets = *r.An
	}
	return rep
}

func (q *logQstate) build(t *testing.T) *moduleQstate {
	if q == nil {
		return nil
	}
	client, transport := "192.0.2.10", "Unknown"
	if q.Client != nil {
		client = *q.Client
	}
	if q.Transport != nil {
		transport = *q.Transport
	}
	qstate := newModuleQstate(queryInfo{q.Qname, q.Qtype, RR_CLASS_IN}, client, 0, 0, transport, q.Lip, q.Lif)
	qstate.returnRcode = q.ReturnRcode
	if q.ReturnMsg != nil {
		qtype := uint16(1)
		if q.ReturnMsg.Qtype != nil {
			qtype = *q.ReturnMsg.Qtype
		}
		qstate.returnMsg = &dnsMsg{qinfo: queryInfo{q.ReturnMsg.Qname, qtype, RR_CLASS_IN}, rep: q.ReturnMsg.Rep.build(t)}
	}
	return qstate
}

func (q *logQinfo) build() *queryInfo {
	if q == nil {
		return nil
	}
	return &queryInfo{q.Qname, q.Qtype, RR_CLASS_IN}
}

func logKwargsOf(spec map[string]string) *logKwargs {
	if spec == nil {
		return nil
	}
	k := &logKwargs{transport: spec["pfb_transport"], listenerIP: spec["pfb_listener_ip"], listenerInterface: spec["pfb_listener_interface"]}
	if v, ok := spec["pfb_addr"]; ok {
		k.pfbAddr = &v
	}
	if v, ok := spec["repinfo"]; ok {
		k.repinfo = &v
	}
	return k
}

func logDnsblOf(t *testing.T, raw json.RawMessage) *dnsblDecision {
	t.Helper()
	if string(raw) == `"UNSET"` {
		return nil
	}
	spec := struct {
		IsFound, InWhitelist, InHsts, NullBlocking, Nxdomain bool
		LogType, BType, PType, Feed, Group, BEval            string
		IdnAlert                                             *[]string
		GroupOwner, GroupOrigin                              string
	}{IsFound: true, LogType: "1", BType: "DNSBL", PType: "Python", Feed: "Feed", Group: "Group", BEval: "example.com"}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		var target any
		switch key {
		case "is_found":
			target = &spec.IsFound
		case "in_whitelist":
			target = &spec.InWhitelist
		case "in_hsts":
			target = &spec.InHsts
		case "null_blocking":
			target = &spec.NullBlocking
		case "nxdomain":
			target = &spec.Nxdomain
		case "log_type":
			target = &spec.LogType
		case "b_type":
			target = &spec.BType
		case "p_type":
			target = &spec.PType
		case "feed":
			target = &spec.Feed
		case "group":
			target = &spec.Group
		case "b_eval":
			target = &spec.BEval
		case "idn_alert":
			target = &spec.IdnAlert
		case "group_owner":
			target = &spec.GroupOwner
		case "group_origin":
			target = &spec.GroupOrigin
		default:
			t.Fatalf("oracle DnsblDecision field %q is not modelled", key)
		}
		if err := json.Unmarshal(value, target); err != nil {
			t.Fatal(err)
		}
	}
	d := &dnsblDecision{
		isFound: spec.IsFound, inWhitelist: spec.InWhitelist, inHsts: spec.InHsts, nullBlocking: spec.NullBlocking,
		nxdomain: spec.Nxdomain, logType: spec.LogType, bType: spec.BType, pType: spec.PType, feed: spec.Feed,
		group: spec.Group, bEval: spec.BEval, groupOwner: spec.GroupOwner, groupOrigin: spec.GroupOrigin,
	}
	if spec.IdnAlert != nil {
		a := *spec.IdnAlert
		d.idnAlert = &idnAlert{a[0], a[1], a[2]}
	}
	return d
}

func describeStep(s *logStep) string {
	switch s.Op {
	case "resolve":
		return fmt.Sprintf("resolve %q type %d client %q transport %q listener %q/%q", s.Qname, s.Qtype, s.Client, s.Transport, s.Lip, s.Lif)
	case "callback":
		return fmt.Sprintf("callback %s %+v rep %+v", s.Kind, s.Qstate, s.Rep)
	case "details_reply":
		return fmt.Sprintf("get_details_reply %q qstate %+v qinfo %+v rep %+v kwargs %v", s.MType, s.Qstate, s.Qinfo, s.Rep, s.Kwargs)
	case "details_dnsbl":
		return fmt.Sprintf("get_details_dnsbl qstate %+v qinfo %+v dnsbl %s kwargs %v", s.Qstate, s.Qinfo, s.Dnsbl, s.Kwargs)
	}
	return fmt.Sprintf("%s %q", s.Op, s.QName)
}

func TestLogRowsMatchPython(t *testing.T) {
	o := loadLogOracle(t)
	if o.Stamp != "2026-10-18 12:00:00" || o.Now != 1792324800 {
		t.Fatalf("oracle clock = %q / %d: the Go clock below is built from it", o.Stamp, o.Now)
	}
	total := 0
	for _, sc := range o.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			modCaptureLog(t)
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
			previous := maxmindDBPath
			maxmindDBPath = filepath.Join(dir, "no-reader.mmdb")
			if sc.Mmdb != "" {
				maxmindDBPath = filepath.Join("testdata", sc.Mmdb)
			}
			m, err := boot(dir, testLogDir)
			maxmindDBPath = previous
			if err != nil {
				t.Fatal(err)
			}
			stopModule(t, m)
			m.clock = func() time.Time { return time.Unix(o.Now, 0).UTC() }
			var rows [][2]string
			m.logSink = func(name, line string) { rows = append(rows, [2]string{name, line}) }
			f := newFrontend(m)
			for i := range sc.Steps {
				step := &sc.Steps[i]
				rows = nil
				switch step.Op {
				case "resolve":
					next := 0
					f.Resolve(mustHex(t, step.Wire), step.Client, func([]byte) []byte {
						if next >= len(step.Forwards) {
							t.Errorf("step %d: the decider asked Unbound %d times, Python %d", i, next+1, len(step.Forwards))
							return nil
						}
						reply := step.Forwards[next]
						next++
						if reply == nil {
							return nil
						}
						return mustHex(t, *reply)
					}, step.Transport, step.Lip, step.Lif)
					if next != len(step.Forwards) {
						t.Errorf("step %d: the decider asked Unbound %d times, Python %d", i, next, len(step.Forwards))
					}
				case "callback":
					m.fireReplyCallback(step.Kind, step.Qstate.build(t), step.Rep.build(t))
				case "details_reply":
					err := m.getDetailsReply(step.MType, step.Qinfo.build(), step.Qstate.build(t), step.Rep.build(t), logKwargsOf(step.Kwargs))
					if (err != nil) != step.Raises {
						t.Errorf("step %d: get_details_reply error = %v, Python raised = %v", i, err, step.Raises)
					}
				case "details_dnsbl":
					m.getDetailsDnsbl("dnsbl", step.Qinfo.build(), step.Qstate.build(t), logKwargsOf(step.Kwargs), logDnsblOf(t, step.Dnsbl), "")
				case "send":
					query, err := dnswire.Parse(qtypeWire(t, step.Qname, step.Qtype))
					if err != nil {
						t.Fatal(err)
					}
					qstate := newModuleQstate(queryInfo{step.Qname, step.Qtype, RR_CLASS_IN}, step.Client, 0, 0, step.Transport, "", "")
					qstate.returnRcode = step.ReturnRcode
					if step.Msg {
						answer := dnswire.RR{Name: step.Qname, Rtype: dnswire.TYPE_A, Rclass: RR_CLASS_IN, TTL: 300, Rdata: []byte{192, 0, 2, 77}}
						padding := make([]dnswire.RR, step.Authority)
						for j := range padding {
							padding[j] = dnswire.RR{Name: step.Qname, Rtype: dnswire.TYPE_TXT, Rclass: RR_CLASS_IN, TTL: 300, Rdata: append([]byte{255}, bytes.Repeat([]byte("x"), 255)...)}
						}
						qstate.returnMsg = newDnsMsg(queryInfo{step.Qname, step.Qtype, RR_CLASS_IN}, dnswire.QR|dnswire.RA, []dnswire.RR{answer}, padding, nil)
					}
					var relay []byte
					if step.Relay {
						relay = []byte("relayed")
					}
					if _, err := f.send(query, qstate, relay, nil); err != nil {
						t.Fatalf("step %d: send: %v", i, err)
					}
				case "idn_alert":
					m.logIdnAlert(step.QName, step.QIP, idnAlert{step.Alert[0], step.Alert[1], step.Alert[2]}, step.QType, step.Transport, step.Lip, step.Lif)
				default:
					t.Fatalf("step %d: unknown op %q", i, step.Op)
				}
				if !reflect.DeepEqual(rows, step.Rows) && !(len(rows) == 0 && len(step.Rows) == 0) {
					t.Errorf("step %d: %s\n got rows:  %q\nwant rows: %q", i, describeStep(step), rows, step.Rows)
				}
				total += len(step.Rows)
			}
		})
	}
	if total < 700 {
		t.Errorf("the oracle replayed %d rows, want the full set (700 or more)", total)
	}
}

func TestLogTextMatchesPython(t *testing.T) {
	for _, c := range loadLogOracle(t).Tables.LogText {
		if got := logText(c.In); got != c.Out {
			t.Errorf("logText(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestCsvRowMatchesPython(t *testing.T) {
	for _, c := range loadLogOracle(t).Tables.CsvRow {
		if got := csvRow(c.In); got != c.Out {
			t.Errorf("csvRow(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestQTransportMatchesPython(t *testing.T) {
	for _, c := range loadLogOracle(t).Tables.QTransport {
		if got := getQTransport(nil, &logKwargs{transport: c.In}); got != c.Out {
			t.Errorf("get_q_transport(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestMetricIpMatchesPython(t *testing.T) {
	for _, c := range loadLogOracle(t).Tables.MetricIp {
		if got := metricIp(c.In); got != c.Out {
			t.Errorf("_metric_ip(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestQListenerMatchesPython(t *testing.T) {
	for _, c := range loadLogOracle(t).Tables.QListener {
		ip, label := getQListener(nil, &logKwargs{listenerIP: c.In[0], listenerInterface: c.In[1]})
		if got := [2]string{ip, label}; got != c.Out {
			t.Errorf("get_q_listener(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestConvertMatchesPython(t *testing.T) {
	convert := loadLogOracle(t).Tables.Convert
	for _, c := range convert.Ipv4 {
		got, err := convertIpv4(mustHex(t, c.In))
		if (err != nil) != c.Error || got != c.Out {
			t.Errorf("convert_ipv4(%s) = %q, %v; Python %q, raised %v", c.In, got, err, c.Out, c.Error)
		}
	}
	for _, c := range convert.Ipv6 {
		got, err := convertIpv6(mustHex(t, c.In))
		if (err != nil) != c.Error || got != c.Out {
			t.Errorf("convert_ipv6(%s) = %q, %v; Python %q, raised %v", c.In, got, err, c.Out, c.Error)
		}
	}
	for _, c := range convert.Other {
		if got := convertOther(mustHex(t, c.In)); got != c.Out {
			t.Errorf("convert_other(%s) = %q, want %q", c.In, got, c.Out)
		}
	}
}

func TestTimestampIsLocalTimeInTheLogFormat(t *testing.T) {
	m := &pfbUnbound{}
	before := time.Now()
	stamp := m.makeTimestamp()
	after := time.Now()
	got, err := time.ParseInLocation("2006-01-02 15:04:05", stamp, time.Local)
	if err != nil {
		t.Fatalf("make_timestamp() = %q: %v", stamp, err)
	}
	if got.Before(before.Truncate(time.Second)) || got.After(after) {
		t.Errorf("make_timestamp() = %q, not the local time between %v and %v", stamp, before, after)
	}
	m.clock = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 600, time.FixedZone("x", 3600)) }
	if got := m.makeTimestamp(); got != "2026-01-02 03:04:05" {
		t.Errorf("make_timestamp() on a fixed clock = %q, want 2026-01-02 03:04:05: the clock's own zone, fixed-width fields", got)
	}
	if !strings.HasPrefix(stamp, fmt.Sprintf("%04d-", got.Year())) {
		t.Errorf("make_timestamp() = %q, want a four-digit year first", stamp)
	}
}
