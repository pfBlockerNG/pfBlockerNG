// Package apply is Core's side of the version 2 update command, the Outpost apply's contract (docs/misc/core-api-protocol.md,
// "Update command, version 2"; spec docs/specs/go-updater-pipeline.md section 8): the request the Core Updater writes, the
// result lines it reads back, what the apply's exit status means, the alias of a resource id, and the one spelling of an IP
// set member. The Outpost's side is pfb_core_update_v2_request(), pfb_core_update_v2_result() and
// pfb_outpost_ip_member_valid(); both sides run tests/core/fixtures/apply_contract_v2.json and ip_members.json.
package apply

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	Version    = 2       // the protocol version of the request and of each result line
	MaxRequest = 1 << 20 // the bytes of a request the apply reads
	MaxIDs     = 2048    // the ids of a request's resources and removed together, and of a result's applied, removed and failed
	maxEntries = 4096    // the entries of any one list
	maxMessage = 1024    // the bytes of an issue's message as the apply keeps it
	maxField   = 256     // the bytes of an issue's resource and code
)

// leftOut is the issue Core writes last when it leaves issues out to fit the request: n of them were.
func leftOut(n int) Issue {
	return Issue{Resource: "core-updater", Stage: "apply", Code: "issues_left_out",
		Message: fmt.Sprintf("%d more issues were left out to fit the request", n)}
}

// Request is the version 2 request: what the apply is to load. Core writes it only through Encode, which refuses anything the
// apply would refuse and the narrower forms Core never writes (the scope rule, below), except issues and the pending token:
// Encode writes issues in the form the apply keeps and leaves out what does not fit, and the token as it is.
type Request struct {
	Trigger              string          // "scheduled", "manual", "apply" or "retry"
	Scope                string          // "ip", "dnsbl" or "both": a dnsbl scope lists no resource or removal, an ip scope no DNSBL
	PendingToken         json.RawMessage // the settings store's token, written verbatim and never looked inside; nil or empty for none
	PendingOutsideWindow bool
	Resources            []Resource
	Removed              []string // the ids whose resources left the configuration
	DNSBL                *DNSBL
	Issues               []Issue
}

// Resource is one resource to load at its generation. The geo-catalog takes only its id and generation; an ip-set or an
// ip-aggregate takes its action, its direction unless the action is alias_only, and its member count.
type Resource struct {
	ID         string
	Generation uint64
	Action     string   // "deny", "permit", "match" or "alias_only" (every ip-aggregate)
	Direction  []string // "ingress", "egress" or both, each once
	Entries    int
}

// DNSBL is the published DNSBL data the apply writes statistics for.
type DNSBL struct {
	Generation uint64
	Groups     []Group
}

type Group struct {
	Name    string `json:"name"` // letters, digits and underscores, 1 to 128
	Entries int    `json:"entries"`
	Changed bool   `json:"changed"`
}

// Issue is one problem the Updater met, which the apply files as a notice. Encode writes its resource and code as 1 to 256
// printable ASCII characters, any other byte as "?" and an empty one as "unknown", and its message as BoundedText.
type Issue struct {
	Resource string `json:"resource"`
	Stage    string `json:"stage"` // "download", "script", "parse", "dedup" or "apply"
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type wireRequest struct {
	Version              int             `json:"version"`
	Trigger              string          `json:"trigger"`
	Scope                string          `json:"scope"`
	PendingToken         json.RawMessage `json:"pendingToken,omitempty"`
	PendingOutsideWindow bool            `json:"pendingOutsideWindow,omitempty"`
	Resources            []wireResource  `json:"resources,omitempty"`
	Removed              []string        `json:"removed,omitempty"`
	DNSBL                *wireDNSBL      `json:"dnsbl,omitempty"`
	Issues               []Issue         `json:"issues,omitempty"`
}

type wireResource struct {
	ID         string   `json:"id"`
	Generation string   `json:"generation"`
	Action     string   `json:"action,omitempty"`
	Direction  []string `json:"direction,omitempty"`
	Entries    *int     `json:"entries,omitempty"`
}

type wireDNSBL struct {
	Generation string  `json:"generation"`
	Groups     []Group `json:"groups"`
}

// Alias is the alias the apply loads for a resource id (pfb_core_update_v2_alias()): ip-set/<group>/ipv4|ipv6 is
// pfB_<group>_v4|_v6, ip-aggregate/<class>/<family> is pfB_<Class>_Aggregated_v4|_v6 of the class deny, permit, match or
// native. ok is false for any other id, for a group of anything but letters, digits and underscores, for an alias over 31
// characters (the longest pf table name), and for an ip-set that would take an aggregate's alias.
func Alias(id string) (alias string, ok bool) {
	kind, rest, _ := strings.Cut(id, "/")
	name, family, _ := strings.Cut(rest, "/")
	var v string
	switch family {
	case "ipv4":
		v = "4"
	case "ipv6":
		v = "6"
	default:
		return "", false
	}
	switch kind {
	case "ip-aggregate":
		if !slices.Contains([]string{"deny", "permit", "match", "native"}, name) {
			return "", false
		}
		return "pfB_" + strings.ToUpper(name[:1]) + name[1:] + "_Aggregated_v" + v, true
	case "ip-set":
		alias = "pfB_" + name + "_v" + v
		reserved := slices.Contains([]string{"Deny_Aggregated", "Permit_Aggregated", "Match_Aggregated", "Native_Aggregated"}, name)
		if !word(name) || len(alias) > 31 || reserved {
			return "", false
		}
		return alias, true
	}
	return "", false
}

// SetID is the id of the ip-set a group publishes for family ("ipv4" or "ipv6"), the group being the alias name without pfB_
// and the family suffix. ok is false when that id maps to no alias (Alias): such a group cannot be published.
func SetID(group, family string) (id string, ok bool) {
	id = "ip-set/" + group + "/" + family
	if _, ok := Alias(id); !ok {
		return "", false
	}
	return id, true
}

// Encode is the request as the apply reads it on stdin: one JSON object, every field the apply needs and none it would refuse,
// except the pending token, which it writes as the settings read gave it without looking inside (the token is the platform's).
// It refuses a request the apply would refuse, one outside the scope rule, one whose token is not a JSON value, and one whose
// resources, DNSBL, token and other fields alone are over 1 MiB. Issues are informational and never refuse it: each is written in the form the apply
// keeps; when they are over 4096 or push the request over 1 MiB, the first ones that fit beside everything else are kept and
// one last issue (leftOut) says how many more of those given were left out; only the first 4096 are ever normalised or encoded; when even that one does not fit, no issue is written. An issue with a stage outside the contract's refuses the request (check).
func Encode(r Request) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	w := wireRequest{Version: Version, Trigger: r.Trigger, Scope: r.Scope, PendingToken: r.PendingToken,
		PendingOutsideWindow: r.PendingOutsideWindow, Removed: r.Removed}
	for _, res := range r.Resources {
		wr := wireResource{ID: res.ID, Generation: strconv.FormatUint(res.Generation, 10), Action: res.Action, Direction: res.Direction}
		if res.ID != "geo-catalog" {
			wr.Entries = &res.Entries
		}
		w.Resources = append(w.Resources, wr)
	}
	if r.DNSBL != nil {
		w.DNSBL = &wireDNSBL{Generation: strconv.FormatUint(r.DNSBL.Generation, 10), Groups: r.DNSBL.Groups}
		if w.DNSBL.Groups == nil {
			w.DNSBL.Groups = []Group{}
		}
	}
	out, err := w.encode()
	if err != nil {
		return nil, err
	}
	if len(out) > MaxRequest {
		return nil, fmt.Errorf("the request is %d bytes without its issues, over the %d the apply reads", len(out), MaxRequest)
	}
	issues := make([]Issue, min(len(r.Issues), maxEntries)) // at most the first maxEntries are normalised: more never fit
	for i, is := range r.Issues[:len(issues)] {
		issues[i] = Issue{Resource: field(is.Resource), Stage: is.Stage, Code: field(is.Code), Message: BoundedText(is.Message)}
	}
	w.Issues = issues
	if out := w.mustEncode(); len(r.Issues) <= maxEntries && len(out) <= MaxRequest {
		return out, nil
	}
	// the first n issues and the count of the rest: the request grows with n, so the largest n that fits is found by bisection
	with := func(n int) []byte {
		w.Issues = append(slices.Clip(issues[:n]), leftOut(len(r.Issues)-n))
		return w.mustEncode()
	}
	if n := sort.Search(min(len(issues), maxEntries-1)+1, func(n int) bool { return len(with(n)) > MaxRequest }) - 1; n >= 0 {
		return with(n), nil
	}
	w.Issues = nil
	return w.mustEncode(), nil
}

// encode is w as one line of JSON, markup in a message as written, as the apply's json_encode() writes it. It fails only on a
// token that is not a JSON value: everything else w holds is strings, numbers, booleans and lists of them.
func (w wireRequest) encode() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// mustEncode is encode once w has been encoded with the same token: it cannot fail.
func (w wireRequest) mustEncode() []byte {
	out, err := w.encode()
	if err != nil {
		panic(err)
	}
	return out
}

// BoundedText is text as the apply keeps it unchanged (pfb_core_update_v2_message() is the identity on it). It is the ASCII-only
// form: a run of non-ASCII bytes becomes one space, where the apply itself would keep valid UTF-8; what it guarantees is that
// the apply leaves the result unchanged. Each run of bytes outside printable ASCII is made one space, spaces trimmed at both ends, cut to 1024 bytes and trimmed again.
func BoundedText(s string) string {
	b := make([]byte, 0, min(len(s), maxMessage+1))
	run := false // within a run of other bytes, already one space
	for i := 0; i < len(s) && len(b) <= maxMessage; i++ {
		switch c := s[i]; {
		case len(b) == 0 && (c <= 0x20 || c > 0x7e): // trimmed at the start: the cut counts from the first character
		case c >= 0x20 && c <= 0x7e:
			b, run = append(b, c), false
		case !run:
			b, run = append(b, ' '), true
		}
	}
	return strings.TrimRight(string(b[:min(len(b), maxMessage)]), " ")
}

// field is an issue's resource or code as the apply takes it: 1 to 256 printable ASCII characters.
func field(s string) string {
	if s == "" {
		return "unknown"
	}
	b := []byte(s[:min(len(s), maxField)])
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}

// check refuses what the apply would refuse. An issue's stage is Core's own word and must be one of the contract's stages: an unknown stage is a programming error and
// refuses the request, while issue text never does.
func (r Request) check() error {
	switch {
	case !slices.Contains([]string{"scheduled", "manual", "apply", "retry"}, r.Trigger):
		return fmt.Errorf("the trigger %q is not one of scheduled, manual, apply, retry", r.Trigger)
	case !slices.Contains([]string{"ip", "dnsbl", "both"}, r.Scope):
		return fmt.Errorf("the scope %q is not one of ip, dnsbl, both", r.Scope)
	case r.Scope == "dnsbl" && (len(r.Resources) > 0 || len(r.Removed) > 0):
		return errors.New("a dnsbl scope lists no resource and no removed id")
	case r.Scope == "ip" && r.DNSBL != nil:
		return errors.New("an ip scope carries no dnsbl object")
	case len(r.Resources) > maxEntries || len(r.Removed) > maxEntries || len(r.Resources)+len(r.Removed) > MaxIDs:
		return fmt.Errorf("resources and removed hold more than %d ids together", MaxIDs)
	}
	seen := map[string]bool{}
	claim := func(id string) error {
		if !handled(id) {
			return fmt.Errorf("%q is not an id the apply loads", id)
		}
		if seen[id] {
			return fmt.Errorf("%q appears twice in resources and removed", id)
		}
		seen[id] = true
		return nil
	}
	for _, res := range r.Resources {
		if err := claim(res.ID); err != nil {
			return err
		}
		if err := res.check(); err != nil {
			return fmt.Errorf("%s: %w", res.ID, err)
		}
	}
	for _, id := range r.Removed {
		if err := claim(id); err != nil {
			return err
		}
	}
	if r.DNSBL != nil {
		if len(r.DNSBL.Groups) > maxEntries {
			return fmt.Errorf("the DNSBL holds more than %d groups", maxEntries)
		}
		names := map[string]bool{}
		for _, g := range r.DNSBL.Groups {
			if len(g.Name) > 128 || !word(g.Name) || names[g.Name] {
				return fmt.Errorf("the DNSBL group %q is not a distinct name of 1 to 128 letters, digits and underscores", g.Name)
			}
			if g.Entries < 0 {
				return fmt.Errorf("the DNSBL group %q has a negative count", g.Name)
			}
			names[g.Name] = true
		}
	}
	for _, is := range r.Issues {
		if !slices.Contains([]string{"download", "script", "parse", "dedup", "apply"}, is.Stage) {
			return fmt.Errorf("an issue's stage %q is not one of download, script, parse, dedup, apply", is.Stage)
		}
	}
	return nil
}

func (res Resource) check() error {
	if res.ID == "geo-catalog" {
		if res.Action != "" || res.Direction != nil || res.Entries != 0 {
			return errors.New("the geo-catalog takes no action, direction or entries")
		}
		return nil
	}
	switch {
	case !slices.Contains([]string{"deny", "permit", "match", "alias_only"}, res.Action):
		return fmt.Errorf("the action %q is not one of deny, permit, match, alias_only", res.Action)
	case strings.HasPrefix(res.ID, "ip-aggregate/") && res.Action != "alias_only":
		return errors.New("an ip-aggregate is alias_only")
	case res.Action == "alias_only" && len(res.Direction) > 0:
		return errors.New("an alias_only resource takes no direction")
	case res.Action != "alias_only" && !slices.ContainsFunc([][]string{{"ingress"}, {"egress"}, {"ingress", "egress"}, {"egress", "ingress"}},
		func(d []string) bool { return slices.Equal(d, res.Direction) }):
		return errors.New("the direction is not a non-empty list of distinct ingress, egress")
	case res.Entries < 0:
		return errors.New("the count is negative")
	}
	return nil
}

// handled reports whether id is one a request may name: the geo-catalog, or an id that maps to an alias.
func handled(id string) bool {
	_, ok := Alias(id)
	return id == "geo-catalog" || ok
}

// word reports whether s is one or more letters, digits and underscores.
func word(s string) bool {
	return s != "" && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") == ""
}

// printableASCII reports whether every byte of s is from low to 0x7e.
func printableASCII(s string, low byte) bool {
	for i := range len(s) {
		if s[i] < low || s[i] > 0x7e {
			return false
		}
	}
	return true
}
