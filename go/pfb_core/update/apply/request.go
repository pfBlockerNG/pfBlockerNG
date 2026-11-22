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
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

const (
	Version    = 2       // the protocol version of the request and of each result line
	MaxRequest = 1 << 20 // the bytes of a request the apply reads
	MaxIDs     = 2048    // the ids of a request's resources and removed together, and of a result's applied, removed and failed
	maxEntries = 4096    // the entries of any one list
	maxMessage = 1024    // the bytes of an issue's message as the apply keeps it
	maxField   = 256     // the bytes of an issue's resource and code
)

// Request is the version 2 request: what the apply is to load. Core writes it only through Encode, which refuses anything the
// apply would refuse and the narrower forms Core never writes (the scope rule, below).
type Request struct {
	Trigger              string // "scheduled", "manual", "apply" or "retry"
	Scope                string // "ip", "dnsbl" or "both": a dnsbl scope lists no resource or removal, an ip scope no DNSBL
	PendingToken         string // the marker's token from the snapshot, "" when there is no marker (ValidToken)
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

// Issue is one problem the Updater met, which the apply files as a notice. Every field is printable ASCII: resource and code
// 1 to 256 bytes, message at most 1024 bytes without white space at either end (the apply's bounded text of it is itself).
type Issue struct {
	Resource string `json:"resource"`
	Stage    string `json:"stage"` // "download", "script", "parse", "dedup" or "apply"
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type wireRequest struct {
	Version              int            `json:"version"`
	Trigger              string         `json:"trigger"`
	Scope                string         `json:"scope"`
	PendingToken         string         `json:"pendingToken,omitempty"`
	PendingOutsideWindow bool           `json:"pendingOutsideWindow,omitempty"`
	Resources            []wireResource `json:"resources,omitempty"`
	Removed              []string       `json:"removed,omitempty"`
	DNSBL                *wireDNSBL     `json:"dnsbl,omitempty"`
	Issues               []Issue        `json:"issues,omitempty"`
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

// ValidToken reports whether a pending marker's token is one the apply takes: 1 to 64 printable ASCII characters other than
// the space.
func ValidToken(token string) bool {
	return len(token) >= 1 && len(token) <= 64 && printableASCII(token, 0x21)
}

// Alias is the alias the apply loads for a resource id (pfb_core_update_v2_alias()): ip-set/<group>/ipv4|ipv6 is
// pfB_<group>_v4|_v6, ip-aggregate/<class>/<family> is pfB_<Class>_Aggregated_v4|_v6 of the class deny, permit, match or
// native. ok is false for any other id, for a group of anything but letters, digits and underscores, for an alias over 31
// characters (the longest pf table name), and for an ip-set that would take an aggregate's alias.
func Alias(id string) (alias string, ok bool) {
	kind, rest, _ := strings.Cut(id, "/")
	name, family, _ := strings.Cut(rest, "/")
	v, known := map[string]string{"ipv4": "4", "ipv6": "6"}[family]
	if !known {
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
		if name == "" || strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != "" || len(alias) > 31 || reserved {
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

// Encode is the request as the apply reads it on stdin: one JSON object of printable ASCII, every field the apply needs and
// none it would refuse. It refuses a request the apply would refuse, one outside the scope rule, and one over 1 MiB.
func Encode(r Request) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	w := wireRequest{Version: Version, Trigger: r.Trigger, Scope: r.Scope, PendingToken: r.PendingToken,
		PendingOutsideWindow: r.PendingOutsideWindow, Removed: r.Removed, Issues: r.Issues}
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
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // markup in a message stays as written, as the apply's json_encode() writes it
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	if len(out) > MaxRequest {
		return nil, fmt.Errorf("the request is %d bytes, over the %d the apply reads", len(out), MaxRequest)
	}
	return out, nil
}

func (r Request) check() error {
	switch {
	case !slices.Contains([]string{"scheduled", "manual", "apply", "retry"}, r.Trigger):
		return fmt.Errorf("the trigger %q is not one of scheduled, manual, apply, retry", r.Trigger)
	case !slices.Contains([]string{"ip", "dnsbl", "both"}, r.Scope):
		return fmt.Errorf("the scope %q is not one of ip, dnsbl, both", r.Scope)
	case r.PendingToken != "" && !ValidToken(r.PendingToken):
		return errors.New("the pending token is not 1 to 64 printable ASCII characters other than the space")
	case r.Scope == "dnsbl" && (len(r.Resources) > 0 || len(r.Removed) > 0):
		return errors.New("a dnsbl scope lists no resource and no removed id")
	case r.Scope == "ip" && r.DNSBL != nil:
		return errors.New("an ip scope carries no dnsbl object")
	case len(r.Resources) > maxEntries || len(r.Removed) > maxEntries || len(r.Resources)+len(r.Removed) > MaxIDs:
		return fmt.Errorf("resources and removed hold more than %d ids together", MaxIDs)
	case len(r.Issues) > maxEntries:
		return fmt.Errorf("issues hold more than %d entries", maxEntries)
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
			if len(g.Name) > 128 || g.Name == "" || strings.Trim(g.Name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != "" || names[g.Name] {
				return fmt.Errorf("the DNSBL group %q is not a distinct name of 1 to 128 letters, digits and underscores", g.Name)
			}
			if g.Entries < 0 {
				return fmt.Errorf("the DNSBL group %q has a negative count", g.Name)
			}
			names[g.Name] = true
		}
	}
	for _, is := range r.Issues {
		field := func(s string) bool { return len(s) >= 1 && len(s) <= maxField && printableASCII(s, 0x20) }
		switch {
		case !field(is.Resource) || !field(is.Code):
			return fmt.Errorf("an issue's resource %q or code %q is not 1 to 256 printable ASCII characters", is.Resource, is.Code)
		case !slices.Contains([]string{"download", "script", "parse", "dedup", "apply"}, is.Stage):
			return fmt.Errorf("an issue's stage %q is not one of download, script, parse, dedup, apply", is.Stage)
		case len(is.Message) > maxMessage || !printableASCII(is.Message, 0x20) || strings.TrimSpace(is.Message) != is.Message:
			return errors.New("an issue's message is not at most 1024 printable ASCII characters without white space at either end")
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
	return id == "geo-catalog" || ok && resources.ValidID(id)
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
