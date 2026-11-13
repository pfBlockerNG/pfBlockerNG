package feedparse

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

// Replays testdata/feed.json (schema: testdata/README.md): whole feed files through ParseIPFeed and ParseDNSBLFeed. The PHP runner
// (tests/php/FeedParseFeedCorpusTest.php) replays the same file through the production loops; the two agree case for case.

type feedCorpusFile struct {
	Schema *int             `json:"schema"`
	IP     []ipFeedCaseJSON `json:"ip"`
	DNSBL  []dnsblCaseJSON  `json:"dnsbl"`
}

type ipFeedCaseJSON struct {
	ID          *string `json:"id"`
	Description *string `json:"description"`
	Config      *struct {
		VType       *string `json:"vtype"`
		PFType      *string `json:"pftype"`
		Custom      *bool   `json:"custom"`
		FloorV4     *string `json:"cidr_floor_v4"`
		FloorV6     *string `json:"cidr_floor_v6"`
		Suppression *bool   `json:"suppression"`
		Placeholder *string `json:"placeholder"`
	} `json:"config"`
	feedInput
	Expect *struct {
		Out         *string            `json:"out"`
		OutHex      *string            `json:"out_hex"`
		ParseFail   *int               `json:"parse_fail"`
		Suppressed  *bool              `json:"suppressed"`
		Details     *[]failJSON        `json:"details"`
		Messages    *[]json.RawMessage `json:"messages"`
		Placeholder *string            `json:"placeholder"`
	} `json:"expect"`
}

type dnsblCaseJSON struct {
	ID          *string `json:"id"`
	Description *string `json:"description"`
	Config      *struct {
		DNSBLIP     *bool `json:"dnsbl_ip"`
		Lenient     *bool `json:"lenient"`
		Custom      *bool `json:"custom"`
		Suppression *bool `json:"suppression"`
	} `json:"config"`
	feedInput
	Expect *struct {
		Out           *string     `json:"out"`
		OutHex        *string     `json:"out_hex"`
		IP4           *[]string   `json:"ip4"`
		IP6           *[]string   `json:"ip6"`
		UpdateIP      *bool       `json:"updateip"`
		SchemeSkipped *int        `json:"scheme_skipped"`
		Stop          *bool       `json:"stop"`
		Details       *[]failJSON `json:"details"`
	} `json:"expect"`
}

type ipFeedCase struct {
	id          string
	cfg         IPConfig
	ph          string
	input, out  []byte
	parseFail   int
	suppressed  bool
	details     []FailRecord
	messages    []string
	placeholder string
}

type dnsblFeedCase struct {
	id            string
	cfg           DNSBLConfig
	input, out    []byte
	ip4, ip6      []string
	updateIP      bool
	schemeSkipped int
	stop          bool
	details       []FailRecord
}

func loadFeedCorpus(data []byte) ([]ipFeedCase, []dnsblFeedCase, error) {
	var file feedCorpusFile
	if err := decodeCorpus(data, &file); err != nil {
		return nil, nil, err
	}
	if file.Schema == nil || *file.Schema != 1 || len(file.IP) == 0 || len(file.DNSBL) == 0 {
		return nil, nil, errors.New(`feed.json must be {"schema": 1, "ip": [non-empty list], "dnsbl": [non-empty list]}`)
	}
	ids := corpusIDs{}
	var ips []ipFeedCase
	for i, c := range file.IP {
		if err := ids.add(c.ID, c.Description); err != nil {
			return nil, nil, fmt.Errorf("ip #%d: %w", i, err)
		}
		got, err := c.load()
		if err != nil {
			return nil, nil, fmt.Errorf("case %s: %w", *c.ID, err)
		}
		ips = append(ips, got)
	}
	var dnsbls []dnsblFeedCase
	for i, c := range file.DNSBL {
		if err := ids.add(c.ID, c.Description); err != nil {
			return nil, nil, fmt.Errorf("dnsbl #%d: %w", i, err)
		}
		got, err := c.load()
		if err != nil {
			return nil, nil, fmt.Errorf("case %s: %w", *c.ID, err)
		}
		dnsbls = append(dnsbls, got)
	}
	return ips, dnsbls, nil
}

func (c ipFeedCaseJSON) load() (ipFeedCase, error) {
	k, e := c.Config, c.Expect
	if k == nil || e == nil || k.VType == nil || k.PFType == nil || k.Custom == nil || k.FloorV4 == nil || k.FloorV6 == nil || k.Suppression == nil ||
		k.Placeholder == nil || *k.Placeholder == "" || e.ParseFail == nil || e.Suppressed == nil || e.Messages == nil || e.Placeholder == nil {
		return ipFeedCase{}, errors.New("config and expect need every key")
	}
	if (*k.VType != "_v4" && *k.VType != "_v6") || (*k.PFType != "auto" && *k.PFType != "regex") {
		return ipFeedCase{}, errors.New("vtype is _v4 or _v6, pftype auto or regex")
	}
	for _, floor := range []string{*k.FloorV4, *k.FloorV6} {
		if floor == "" || (floor != "Disabled" && strings.Trim(floor, "0123456789") != "") {
			return ipFeedCase{}, errors.New("a Suppression CIDR Limit is Disabled or a decimal string")
		}
	}
	if *e.Placeholder != "" && *e.Placeholder != PlaceholderEmpty && *e.Placeholder != PlaceholderSuppressed {
		return ipFeedCase{}, errors.New("placeholder is empty, empty or suppressed")
	}
	want := ipFeedCase{
		id:          *c.ID,
		cfg:         IPConfig{VType: *k.VType, PFType: *k.PFType, Custom: *k.Custom, FloorV4: *k.FloorV4, FloorV6: *k.FloorV6, Suppression: *k.Suppression},
		ph:          *k.Placeholder,
		parseFail:   *e.ParseFail,
		suppressed:  *e.Suppressed,
		placeholder: *e.Placeholder,
	}
	var err error
	if want.input, err = c.feedInput.bytes(want.id); err != nil {
		return ipFeedCase{}, err
	}
	if want.out, err = corpusBytes(want.id, "out", e.Out, e.OutHex, true); err != nil {
		return ipFeedCase{}, err
	}
	if want.details, err = failRecords("expect.details", e.Details); err != nil {
		return ipFeedCase{}, err
	}
	for i, m := range *e.Messages {
		msg, err := corpusItem(fmt.Sprintf("expect.messages #%d", i), m)
		if err != nil {
			return ipFeedCase{}, err
		}
		want.messages = append(want.messages, msg)
	}
	return want, nil
}

func (c dnsblCaseJSON) load() (dnsblFeedCase, error) {
	k, e := c.Config, c.Expect
	if k == nil || e == nil || k.DNSBLIP == nil || k.Lenient == nil || k.Custom == nil || k.Suppression == nil || e.IP4 == nil || e.IP6 == nil ||
		e.UpdateIP == nil || e.SchemeSkipped == nil || e.Stop == nil {
		return dnsblFeedCase{}, errors.New("config and expect need every key")
	}
	want := dnsblFeedCase{
		id:            *c.ID,
		cfg:           DNSBLConfig{DNSBLIP: *k.DNSBLIP, Lenient: *k.Lenient, Custom: *k.Custom, Suppression: *k.Suppression},
		ip4:           *e.IP4,
		ip6:           *e.IP6,
		updateIP:      *e.UpdateIP,
		schemeSkipped: *e.SchemeSkipped,
		stop:          *e.Stop,
	}
	for _, list := range [][]string{want.ip4, want.ip6} {
		seen := map[string]bool{}
		for _, ip := range list {
			if ip == "" || seen[ip] {
				return dnsblFeedCase{}, errors.New("ip4 and ip6 are lists of distinct non-empty strings: they are de-duplicated")
			}
			seen[ip] = true
		}
	}
	var err error
	if want.input, err = c.feedInput.bytes(want.id); err != nil {
		return dnsblFeedCase{}, err
	}
	if want.out, err = corpusBytes(want.id, "out", e.Out, e.OutHex, true); err != nil {
		return dnsblFeedCase{}, err
	}
	if want.details, err = failRecords("expect.details", e.Details); err != nil {
		return dnsblFeedCase{}, err
	}
	return want, nil
}

func loadFeedCorpusFile(t *testing.T) ([]ipFeedCase, []dnsblFeedCase) {
	t.Helper()
	data, err := os.ReadFile("testdata/feed.json")
	if err != nil {
		t.Fatal(err)
	}
	ips, dnsbls, err := loadFeedCorpus(data)
	if err != nil {
		t.Fatalf("feed.json: %v", err)
	}
	return ips, dnsbls
}

func recordsShow(rs []FailRecord) string {
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "\n    line %d: %s (raw %s)", r.LineNo, visible(r.Line), visible(r.Raw))
	}
	if b.Len() == 0 {
		return " none"
	}
	return b.String()
}

func TestIPFeedCorpus(t *testing.T) {
	ips, _ := loadFeedCorpusFile(t)
	for _, c := range ips {
		t.Run(c.id, func(t *testing.T) {
			var out bytes.Buffer
			got, err := ParseIPFeed(bytes.NewReader(c.input), c.cfg, c.ph, &out)
			if err != nil {
				t.Fatalf("ParseIPFeed: %v", err)
			}
			if !bytes.Equal(out.Bytes(), c.out) {
				t.Errorf("the entries written differ from the corpus\n%s", lineDiff(c.out, out.Bytes()))
			}
			wantEntries := bytes.Count(c.out, lf)
			if c.placeholder != "" {
				wantEntries = 0 // the placeholder is not an entry
			}
			if got.Entries != wantEntries {
				t.Errorf("Entries = %d, want %d", got.Entries, wantEntries)
			}
			if got.ParseFail != c.parseFail || got.Suppressed != c.suppressed || got.Placeholder != c.placeholder {
				t.Errorf("ParseFail, Suppressed, Placeholder = %d, %v, %q; want %d, %v, %q", got.ParseFail, got.Suppressed, got.Placeholder, c.parseFail, c.suppressed, c.placeholder)
			}
			if !sameRecords(got.Details, c.details) {
				t.Errorf("parse-error records\n  expected:%s\n  actual:  %s", recordsShow(c.details), recordsShow(got.Details))
			}
			if !sameStrings(got.Messages, c.messages) {
				t.Errorf("messages\n  expected: %q\n  actual:   %q", c.messages, got.Messages)
			}
		})
	}
}

func TestDNSBLFeedCorpus(t *testing.T) {
	_, dnsbls := loadFeedCorpusFile(t)
	for _, c := range dnsbls {
		t.Run(c.id, func(t *testing.T) {
			var out bytes.Buffer
			got, err := ParseDNSBLFeed(bytes.NewReader(c.input), c.cfg, &out)
			if err != nil {
				t.Fatalf("ParseDNSBLFeed: %v", err)
			}
			if !bytes.Equal(out.Bytes(), c.out) {
				t.Errorf("the rows written differ from the corpus\n%s", lineDiff(c.out, out.Bytes()))
			}
			if want := bytes.Count(c.out, lf); got.Rows != want {
				t.Errorf("Rows = %d, want %d", got.Rows, want)
			}
			if !sameStrings(got.IP4, c.ip4) || !sameStrings(got.IP6, c.ip6) {
				t.Errorf("IPs found\n  expected: v4 %q v6 %q\n  actual:   v4 %q v6 %q", c.ip4, c.ip6, got.IP4, got.IP6)
			}
			if got.UpdateIP != c.updateIP || got.SchemeSkipped != c.schemeSkipped || got.Stopped != c.stop {
				t.Errorf("UpdateIP, SchemeSkipped, Stopped = %v, %d, %v; want %v, %d, %v", got.UpdateIP, got.SchemeSkipped, got.Stopped, c.updateIP, c.schemeSkipped, c.stop)
			}
			if !sameRecords(got.Details, c.details) {
				t.Errorf("parse-error records\n  expected:%s\n  actual:  %s", recordsShow(c.details), recordsShow(got.Details))
			}
		})
	}
}

// failingWriter accepts n bytes and then fails, as a full disk does.
type failingWriter struct{ n int }

var errDisk = errors.New("disk full")

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errDisk
	}
	k := min(w.n, len(p))
	w.n -= k
	if k < len(p) {
		return k, errDisk
	}
	return k, nil
}

var errRead = errors.New("connection reset")

// A feed that cannot be read to its end or written whole is an error and no result: the caller keeps its last known-good list,
// and no placeholder takes the place of a feed nobody finished reading.
func TestFeedReadAndWriteErrors(t *testing.T) {
	ipCfg := IPConfig{VType: "_v4", PFType: "auto"}
	dnsCfg := DNSBLConfig{DNSBLIP: true, Lenient: true}
	broken := func(good string) *thenError {
		return &thenError{data: good, err: errRead}
	}
	t.Run("IP read error after a line", func(t *testing.T) {
		var out bytes.Buffer
		_, err := ParseIPFeed(broken("1.2.3.4\n"), ipCfg, "127.1.7.7", &out)
		if !errors.Is(err, errRead) {
			t.Fatalf("error = %v, want the read error", err)
		}
	})
	t.Run("IP read error on an empty feed writes no placeholder", func(t *testing.T) {
		var out bytes.Buffer
		_, err := ParseIPFeed(iotest.ErrReader(errRead), ipCfg, "127.1.7.7", &out)
		if !errors.Is(err, errRead) || out.Len() != 0 {
			t.Fatalf("error = %v, wrote %q; want the read error and nothing written", err, out.String())
		}
	})
	t.Run("IP write error", func(t *testing.T) {
		_, err := ParseIPFeed(strings.NewReader("1.2.3.4\n5.6.7.8\n"), ipCfg, "127.1.7.7", &failingWriter{n: 8})
		if !errors.Is(err, errDisk) {
			t.Fatalf("error = %v, want the write error", err)
		}
	})
	t.Run("IP placeholder write error", func(t *testing.T) {
		_, err := ParseIPFeed(strings.NewReader("# nothing\n"), ipCfg, "127.1.7.7", &failingWriter{})
		if !errors.Is(err, errDisk) {
			t.Fatalf("error = %v, want the write error", err)
		}
	})
	t.Run("DNSBL read error after a line", func(t *testing.T) {
		var out bytes.Buffer
		_, err := ParseDNSBLFeed(broken("example.org\n"), dnsCfg, &out)
		if !errors.Is(err, errRead) {
			t.Fatalf("error = %v, want the read error", err)
		}
	})
	t.Run("DNSBL write error", func(t *testing.T) {
		_, err := ParseDNSBLFeed(strings.NewReader("example.org\nexample.net\n"), dnsCfg, &failingWriter{n: 5})
		if !errors.Is(err, errDisk) {
			t.Fatalf("error = %v, want the write error", err)
		}
	})
}

// thenError yields its data, then err.
type thenError struct {
	data string
	err  error
}

func (r *thenError) Read(p []byte) (int, error) {
	if r.data == "" {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// Malformed documents each break one rule of the schema; the runner must refuse every one.
func TestFeedCorpusLoaderIsStrict(t *testing.T) {
	const ip = `{"id": "a", "description": "d", "config": {"vtype": "_v4", "pftype": "auto", "custom": false, "cidr_floor_v4": "Disabled", "cidr_floor_v6": "Disabled", "suppression": false, "placeholder": "127.1.7.7"}, "input": "1.2.3.4\n", "expect": {"out": "1.2.3.4\n", "parse_fail": 0, "suppressed": false, "details": [], "messages": [], "placeholder": ""}}`
	const dn = `{"id": "b", "description": "d", "config": {"dnsbl_ip": true, "lenient": true, "custom": false, "suppression": false}, "input": "a.example\n", "expect": {"out": "[\"d\",\"a.example\"]\n", "ip4": [], "ip6": [], "updateip": false, "scheme_skipped": 0, "stop": false, "details": []}}`
	doc := func(ip, dn string) string { return `{"schema": 1, "ip": [` + ip + `], "dnsbl": [` + dn + `]}` }
	if _, _, err := loadFeedCorpus([]byte(doc(ip, dn))); err != nil {
		t.Fatalf("the well-formed document is refused: %v", err)
	}
	bad := map[string]string{
		"unknown top key":       strings.Replace(doc(ip, dn), `"schema": 1`, `"schema": 1, "x": 1`, 1),
		"schema 2":              strings.Replace(doc(ip, dn), `"schema": 1`, `"schema": 2`, 1),
		"missing schema":        strings.Replace(doc(ip, dn), `"schema": 1, `, ``, 1),
		"empty dnsbl list":      doc(ip, ""),
		"duplicate id":          doc(ip, strings.Replace(dn, `"id": "b"`, `"id": "a"`, 1)),
		"empty description":     doc(strings.Replace(ip, `"description": "d"`, `"description": ""`, 1), dn),
		"unknown case key":      doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input": "1.2.3.4\n", "x": 1,`, 1), dn),
		"input and input_hex":   doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input": "1.2.3.4\n", "input_hex": "ff",`, 1), dn),
		"input_hex is UTF-8":    doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input_hex": "61",`, 1), dn),
		"upper-case hex":        doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input_hex": "FF",`, 1), dn),
		"no input":              doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, ``, 1), dn),
		"unknown config key":    doc(strings.Replace(ip, `"custom": false,`, `"custom": false, "x": 1,`, 1), dn),
		"bad vtype":             doc(strings.Replace(ip, `"_v4"`, `"_v5"`, 1), dn),
		"bad floor":             doc(strings.Replace(ip, `"cidr_floor_v4": "Disabled"`, `"cidr_floor_v4": "x"`, 1), dn),
		"empty placeholder":     doc(strings.Replace(ip, `"127.1.7.7"`, `""`, 1), dn),
		"unknown expect key":    doc(strings.Replace(ip, `"parse_fail": 0,`, `"parse_fail": 0, "x": 1,`, 1), dn),
		"missing expect key":    doc(strings.Replace(ip, `"suppressed": false, `, ``, 1), dn),
		"bad placeholder name":  doc(strings.Replace(ip, `"placeholder": ""}}`, `"placeholder": "x"}}`, 1), dn),
		"out and out_hex":       doc(strings.Replace(ip, `"out": "1.2.3.4\n",`, `"out": "1.2.3.4\n", "out_hex": "ff",`, 1), dn),
		"detail unknown key":    doc(strings.Replace(ip, `"details": []`, `"details": [{"line_no": 1, "line": "a", "raw": "a", "x": 1}]`, 1), dn),
		"detail line_no 0":      doc(strings.Replace(ip, `"details": []`, `"details": [{"line_no": 0, "line": "a", "raw": "a"}]`, 1), dn),
		"detail order":          doc(strings.Replace(ip, `"details": []`, `"details": [{"line_no": 2, "line": "a", "raw": "a"}, {"line_no": 1, "line": "a", "raw": "a"}]`, 1), dn),
		"detail hex is UTF-8":   doc(strings.Replace(ip, `"details": []`, `"details": [{"line_no": 1, "line": {"hex": "61"}, "raw": "a"}]`, 1), dn),
		"unknown dnsbl config":  doc(ip, strings.Replace(dn, `"custom": false,`, `"custom": false, "x": true,`, 1)),
		"dnsbl flag not a bool": doc(ip, strings.Replace(dn, `"lenient": true`, `"lenient": 1`, 1)),
		"dnsbl ip not unique":   doc(ip, strings.Replace(dn, `"ip4": []`, `"ip4": ["1.2.3.4", "1.2.3.4"]`, 1)),
		"dnsbl missing stop":    doc(ip, strings.Replace(dn, `"stop": false, `, ``, 1)),
		"repeat count 0":        doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input_parts": [{"repeat": "a", "count": 0}],`, 1), dn),
		"parts with input":      doc(strings.Replace(ip, `"input": "1.2.3.4\n",`, `"input": "a", "input_parts": ["a"],`, 1), dn),
		"data after the file":   doc(ip, dn) + ` {}`,
	}
	for name, text := range bad {
		if _, _, err := loadFeedCorpus([]byte(text)); err == nil {
			t.Errorf("%s: the malformed document is accepted", name)
		}
	}
}
