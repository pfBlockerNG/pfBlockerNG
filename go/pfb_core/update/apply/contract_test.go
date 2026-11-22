package apply_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// The contract fixture of the version 2 update command, frozen by tests/php/CoreUpdateV2ContractTest.php against the Outpost's
// validator and result writer (issue #4037), run here from Go in both directions (issue #4038):
//   - requests: every accepted row Core can write is written as the row says (byte for byte, or the same normal form), every
//     accepted row Core does not write is named with its reason, and every refused row is refused by Core's writer or cannot
//     be held by its types;
//   - aliases: the alias rule is the Outpost's;
//   - results: every line the Outpost writes is read into the values it holds, and every report the Outpost refuses to write
//     is refused when it arrives as a line.
const contractFixture = "../../../../tests/core/fixtures/apply_contract_v2.json"

type contractRow struct {
	ID             string          `json:"id"`
	Description    string          `json:"description"`
	Request        json.RawMessage `json:"request"`
	Stdin          json.RawMessage `json:"stdin"`
	Accepted       json.RawMessage `json:"accepted"`
	AcceptedCounts map[string]int  `json:"acceptedCounts"`
	Refused        *string         `json:"refused"`
	Report         json.RawMessage `json:"report"`
	ReportJSON     json.RawMessage `json:"reportJSON"`
	Line           json.RawMessage `json:"line"`
	Alias          *string         `json:"alias"`
}

type contractDoc struct {
	Schema   int            `json:"schema"`
	Contract string         `json:"contract"`
	About    []string       `json:"about"`
	Limits   map[string]int `json:"limits"`
	Aliases  []contractRow  `json:"aliases"`
	Requests []contractRow  `json:"requests"`
	Results  []contractRow  `json:"results"`
}

func readContract(t *testing.T) contractDoc {
	t.Helper()
	raw, err := os.ReadFile(contractFixture)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc contractDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Contract != "update-command-version-2" {
		t.Fatalf("not the version 2 contract: schema %d, %q", doc.Schema, doc.Contract)
	}
	return doc
}

// joined is the fixture's bytes: a JSON string, or a list of strings and {repeat, times} parts, each '{i}' the repetition's index.
func joined(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s)
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil {
		t.Fatalf("not bytes: %s", raw)
	}
	var b bytes.Buffer
	for _, p := range parts {
		if json.Unmarshal(p, &s) == nil {
			b.WriteString(s)
			continue
		}
		var r struct {
			Repeat string `json:"repeat"`
			Times  int    `json:"times"`
		}
		if err := json.Unmarshal(p, &r); err != nil {
			t.Fatalf("not a part: %s", p)
		}
		for i := range r.Times {
			b.WriteString(strings.ReplaceAll(r.Repeat, "{i}", strconv.Itoa(i)))
		}
	}
	return b.Bytes()
}

// input is the stdin of a request row: its request as the fixture writes it, or its stdin joined.
func input(t *testing.T, row contractRow) []byte {
	t.Helper()
	if row.Request != nil {
		var b bytes.Buffer
		if err := json.Compact(&b, row.Request); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	return joined(t, row.Stdin)
}

// A request as the fixture holds it. Pointers tell a field that is absent (or null) from one Core would write empty.
type rowRequest struct {
	Version              *int    `json:"version"`
	Trigger              *string `json:"trigger"`
	Scope                *string `json:"scope"`
	PendingToken         *string `json:"pendingToken"`
	PendingOutsideWindow *bool   `json:"pendingOutsideWindow"`
	Resources            []struct {
		ID         *string  `json:"id"`
		Generation *string  `json:"generation"`
		Action     *string  `json:"action"`
		Direction  []string `json:"direction"`
		Entries    *int     `json:"entries"`
	} `json:"resources"`
	Removed []string `json:"removed"`
	DNSBL   *struct {
		Generation *string `json:"generation"`
		Groups     *[]struct {
			Name    *string `json:"name"`
			Entries *int    `json:"entries"`
			Changed *bool   `json:"changed"`
		} `json:"groups"`
	} `json:"dnsbl"`
	Issues []struct {
		Resource *string `json:"resource"`
		Stage    *string `json:"stage"`
		Code     *string `json:"code"`
		Message  *string `json:"message"`
	} `json:"issues"`
}

// asRequest is what Core would be asked to write for the request in stdin, with the validator's reading of it (null is absent,
// scope is both when absent), or the reason Core's types cannot hold it: then Core never writes it.
func asRequest(stdin []byte) (apply.Request, string) {
	dec := json.NewDecoder(bytes.NewReader(stdin))
	dec.DisallowUnknownFields()
	var in rowRequest
	if err := dec.Decode(&in); err != nil {
		return apply.Request{}, "not a request Core's types hold: " + err.Error()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return apply.Request{}, "not one JSON object"
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	gen := func(p *string) (uint64, bool) {
		if p == nil {
			return 0, false
		}
		g, err := strconv.ParseUint(*p, 10, 64)
		return g, err == nil && strconv.FormatUint(g, 10) == *p
	}
	if in.Version == nil || *in.Version != apply.Version {
		return apply.Request{}, "Core writes version 2"
	}
	if in.PendingToken != nil && *in.PendingToken == "" {
		return apply.Request{}, "Core writes no token rather than an empty one"
	}
	r := apply.Request{Trigger: str(in.Trigger), Scope: str(in.Scope), PendingToken: str(in.PendingToken), Removed: in.Removed}
	if r.Scope == "" {
		r.Scope = "both"
	}
	if in.PendingOutsideWindow != nil {
		r.PendingOutsideWindow = *in.PendingOutsideWindow
	}
	for _, res := range in.Resources {
		g, ok := gen(res.Generation)
		if !ok {
			return apply.Request{}, "Core writes a generation as its decimal number"
		}
		id := str(res.ID)
		var entries int
		switch {
		case id == "geo-catalog" && res.Entries != nil:
			return apply.Request{}, "Core writes no entries for the geo-catalog"
		case id != "geo-catalog" && res.Entries == nil:
			return apply.Request{}, "Core writes the entries of every alias resource"
		case res.Entries != nil:
			entries = *res.Entries
		}
		r.Resources = append(r.Resources, apply.Resource{ID: id, Generation: g, Action: str(res.Action), Direction: res.Direction, Entries: entries})
	}
	if in.DNSBL != nil {
		g, ok := gen(in.DNSBL.Generation)
		if !ok {
			return apply.Request{}, "Core writes a generation as its decimal number"
		}
		if in.DNSBL.Groups == nil {
			return apply.Request{}, "Core writes the groups of a DNSBL, an empty list for none"
		}
		r.DNSBL = &apply.DNSBL{Generation: g, Groups: []apply.Group{}}
		for _, grp := range *in.DNSBL.Groups {
			if grp.Name == nil || grp.Entries == nil || grp.Changed == nil {
				return apply.Request{}, "Core writes every field of a group"
			}
			r.DNSBL.Groups = append(r.DNSBL.Groups, apply.Group{Name: *grp.Name, Entries: *grp.Entries, Changed: *grp.Changed})
		}
	}
	for _, is := range in.Issues {
		if is.Resource == nil || is.Stage == nil || is.Code == nil || is.Message == nil {
			return apply.Request{}, "Core writes every field of an issue"
		}
		r.Issues = append(r.Issues, apply.Issue{Resource: *is.Resource, Stage: *is.Stage, Code: *is.Code, Message: *is.Message})
	}
	return r, ""
}

// normalForm is a request Core wrote, in the validator's normal form: defaults filled, each ip-set and ip-aggregate with its
// alias (the alias rule is pinned by TestTheAliasRuleIsTheApplys).
func normalForm(t *testing.T, written []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(written))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("Core wrote what is not one JSON object: %v", err)
	}
	delete(m, "version")
	defaults := map[string]any{"scope": "both", "pendingToken": nil, "pendingOutsideWindow": false, "resources": []any{},
		"removed": []any{}, "dnsbl": nil, "issues": []any{}}
	for k, v := range defaults {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	for _, r := range m["resources"].([]any) {
		r := r.(map[string]any)
		if alias, ok := apply.Alias(r["id"].(string)); ok {
			r["alias"] = alias
		}
	}
	removed := []any{}
	for _, id := range m["removed"].([]any) {
		entry := map[string]any{"id": id}
		if alias, ok := apply.Alias(id.(string)); ok {
			entry["alias"] = alias
		}
		removed = append(removed, entry)
	}
	m["removed"] = removed
	return m
}

func decodeAny(t *testing.T, raw []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The accepted rows Core does not write, each with what Core writes instead or why it refuses: Core writes a subset of what
// the validator accepts. A row joining or leaving this list is a change of what Core writes.
var notWrittenByCore = map[string]string{
	"generation-strings-kept":             "Core writes a generation as its decimal number",
	"generation-of-20-characters":         "Core writes a generation as its decimal number",
	"scope-dnsbl-with-an-ip-set":          "a dnsbl scope lists no resource and no removed id",
	"scope-ip-with-dnsbl":                 "an ip scope carries no dnsbl object",
	"issue-message-as-text":               "an issue's message is",
	"issue-message-cut-on-a-character":    "an issue's message is",
	"issue-message-line-break":            "an issue's message is",
	"issue-message-control-run":           "an issue's message is",
	"issue-message-line-separator":        "an issue's message is",
	"issue-message-format-character":      "an issue's message is",
	"issue-message-cut-after-a-space":     "an issue's message is",
	"issue-message-in-a-request-of-1-mib": "an issue's message is",
}

// The rows Core writes byte for byte as the fixture holds them: the rows of #4038 that show what Core writes.
var writtenByteForByte = []string{"core-writes-scope-ip", "core-writes-scope-dnsbl", "core-writes-dnsbl-without-groups",
	"core-writes-scope-both", "core-writes-nothing-to-apply"}

// WHEN Core writes the request of each accepted row THEN the validator's normal form of it is the row's, or the row is one
// Core does not write, for the reason listed.
func TestCoreWritesWhatTheApplyAccepts(t *testing.T) {
	doc := readContract(t)
	notWritten := map[string]string{}
	byteForByte := 0
	for _, row := range doc.Requests {
		if row.Refused != nil {
			continue
		}
		t.Run(row.ID, func(t *testing.T) {
			stdin := input(t, row)
			req, reason := asRequest(stdin)
			var written []byte
			if reason == "" {
				var err error
				if written, err = apply.Encode(req); err != nil {
					reason = err.Error()
				}
			}
			if reason != "" {
				notWritten[row.ID] = reason
				return
			}
			if len(written) > apply.MaxRequest || !printable(written) {
				t.Fatalf("Core wrote %d bytes, not all printable ASCII within %d", len(written), apply.MaxRequest)
			}
			if bytes.Equal(written, stdin) {
				byteForByte++
			} else if slices.Contains(writtenByteForByte, row.ID) {
				t.Errorf("Core writes\n%s\nthe row holds\n%s", written, stdin)
			}
			if row.AcceptedCounts != nil {
				got := normalForm(t, written).(map[string]any)
				for list, n := range row.AcceptedCounts {
					if c := len(got[list].([]any)); c != n {
						t.Errorf("%s: Core wrote %d entries, the row accepts %d", list, c, n)
					}
				}
				return
			}
			if got, want := normalForm(t, written), decodeAny(t, row.Accepted); !reflect.DeepEqual(got, want) {
				t.Errorf("Core writes %s\nthe validator's normal form of it differs from the row's\n%s", written, row.Accepted)
			}
		})
	}
	for id, reason := range notWritten {
		want, listed := notWrittenByCore[id]
		if !listed || !strings.Contains(reason, want) {
			t.Errorf("%s: Core does not write it (%s); listed: %q", id, reason, want)
		}
	}
	for id := range notWrittenByCore {
		if _, ok := notWritten[id]; !ok {
			t.Errorf("%s is listed as a row Core does not write, but Core writes it", id)
		}
	}
	if byteForByte < len(writtenByteForByte) {
		t.Errorf("%d rows written byte for byte, at least %d expected", byteForByte, len(writtenByteForByte))
	}
	t.Logf("%d accepted rows written byte for byte, %d not written by Core", byteForByte, len(notWritten))
}

// WHEN Core is asked to write the request of each refused row THEN its writer refuses it, or its types cannot hold it.
func TestCoreNeverWritesARequestTheApplyRefuses(t *testing.T) {
	refused := 0
	for _, row := range readContract(t).Requests {
		if row.Refused == nil {
			continue
		}
		refused++
		t.Run(row.ID, func(t *testing.T) {
			req, reason := asRequest(input(t, row))
			if reason != "" {
				return
			}
			if written, err := apply.Encode(req); err == nil {
				t.Errorf("the apply refuses it (%s), Core writes %.300s", *row.Refused, written)
			}
		})
	}
	if refused < 100 {
		t.Errorf("%d refused rows", refused)
	}
}

// WHEN each id of the fixture's alias rows is mapped THEN Core gives the Outpost's alias, or none.
func TestTheAliasRuleIsTheApplys(t *testing.T) {
	rows := readContract(t).Aliases
	if len(rows) < 20 {
		t.Fatalf("%d alias rows", len(rows))
	}
	for _, row := range rows {
		alias, ok := apply.Alias(row.ID)
		want := ""
		if row.Alias != nil {
			want = *row.Alias
		}
		if alias != want || ok != (row.Alias != nil) {
			t.Errorf("%q: Core maps it to %q (%v), the apply to %q", row.ID, alias, ok, want)
		}
	}
}

// requestFor is a request that names every id and alias of a report: each applied id at its generation, each failed id, each
// removed id, and an id for each changed alias that none of those maps to.
func requestFor(report map[string]any) apply.Request {
	var req apply.Request
	named := map[string]bool{}
	resource := func(id string, g uint64) {
		if named[id] {
			return
		}
		named[id] = true
		r := apply.Resource{ID: id, Generation: g}
		if id != "geo-catalog" {
			r.Action = "alias_only"
		}
		req.Resources = append(req.Resources, r)
	}
	if applied, ok := report["applied"].(map[string]any); ok {
		for _, id := range slices.Sorted(maps.Keys(applied)) {
			g, _ := applied[id].(string)
			n, err := strconv.ParseUint(g, 10, 64)
			if err != nil {
				n = 1
			}
			resource(id, n)
		}
	}
	if removed, ok := report["removed"].([]any); ok {
		for _, id := range removed {
			if s, ok := id.(string); ok && !named[s] {
				named[s] = true
				req.Removed = append(req.Removed, s)
			}
		}
	}
	if failed, ok := report["failed"].([]any); ok {
		for _, f := range failed {
			if f, ok := f.(map[string]any); ok {
				if id, ok := f["id"].(string); ok {
					resource(id, 1)
				}
			}
		}
	}
	aggregate := regexp.MustCompile(`^pfB_(Deny|Permit|Match|Native)_Aggregated_v([46])$`)
	set := regexp.MustCompile(`^pfB_(.+)_v([46])$`)
	if aliases, ok := report["changedAliases"].([]any); ok {
		for _, a := range aliases {
			s, _ := a.(string)
			if m := aggregate.FindStringSubmatch(s); m != nil {
				resource("ip-aggregate/"+strings.ToLower(m[1])+"/ipv"+m[2], 1)
			} else if m := set.FindStringSubmatch(s); m != nil {
				resource("ip-set/"+m[1]+"/ipv"+m[2], 1)
			}
		}
	}
	return req
}

func reportOf(t *testing.T, row contractRow) map[string]any {
	t.Helper()
	raw := []byte(row.Report)
	if row.Report == nil {
		raw = joined(t, row.ReportJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// WHEN Core reads each result line the apply writes THEN it holds the values the line holds.
func TestEveryResultLineTheApplyWritesIsRead(t *testing.T) {
	lines := 0
	for _, row := range readContract(t).Results {
		if row.Line == nil {
			continue
		}
		lines++
		t.Run(row.ID, func(t *testing.T) {
			line := joined(t, row.Line)
			var said struct {
				Applied        map[string]string `json:"applied"`
				Removed        []string          `json:"removed"`
				ChangedAliases []string          `json:"changedAliases"`
				IPChanged      bool              `json:"ipChanged"`
				DNSBLChanged   bool              `json:"dnsblChanged"`
				ReloadLaunched bool              `json:"reloadLaunched"`
				Failed         []apply.Failure   `json:"failed"`
			}
			if err := json.Unmarshal(line, &said); err != nil {
				t.Fatal(err)
			}
			want := apply.Result{Removed: said.Removed, ChangedAliases: said.ChangedAliases, IPChanged: said.IPChanged,
				DNSBLChanged: said.DNSBLChanged, ReloadLaunched: said.ReloadLaunched, Failed: said.Failed}
			for id, g := range said.Applied {
				n, err := strconv.ParseUint(g, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				if want.Applied == nil {
					want.Applied = map[string]uint64{}
				}
				want.Applied[id] = n
			}
			got, err := apply.ReadResult(bytes.NewReader(line), requestFor(reportOf(t, row)))
			if err != nil {
				t.Fatalf("the apply writes %.300s, Core refuses it: %v", line, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Core reads %+v\nthe line holds %+v", trim(got), trim(want))
			}
		})
	}
	if lines < 20 {
		t.Errorf("%d result lines", lines)
	}
}

// WHEN a report the apply refuses to write arrives as a line THEN Core refuses it.
func TestEveryReportTheApplyRefusesIsRefusedAsALine(t *testing.T) {
	refused := 0
	for _, row := range readContract(t).Results {
		if row.Refused == nil {
			continue
		}
		refused++
		t.Run(row.ID, func(t *testing.T) {
			report := reportOf(t, row)
			report["version"] = json.Number("2")
			line, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			line = append(line, '\n')
			if got, err := apply.ReadResult(bytes.NewReader(line), requestFor(report)); err == nil {
				t.Errorf("the apply refuses it (%s), Core reads %+v", *row.Refused, trim(got))
			}
		})
	}
	if refused < 30 {
		t.Errorf("%d refused reports", refused)
	}
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// trim keeps a failure message short: a large result prints its size, not megabytes.
func trim(r apply.Result) string {
	s := fmt.Sprintf("%+v", r)
	if len(s) > 600 {
		return fmt.Sprintf("%.600s... (%d bytes)", s, len(s))
	}
	return s
}
