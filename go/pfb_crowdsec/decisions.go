package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_crowdsec/spoa"
)

type family int

const (
	inet family = iota
	inet6
)

var ipTypes = [2]string{"ipv4", "ipv6"}

// decision is the LAPI's Decision object; fields the bouncer does not use are ignored.
type decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
}

// streamResponse is the LAPI's DecisionsStreamResponse.
type streamResponse struct {
	New     []decision `json:"new"`
	Deleted []decision `json:"deleted"`
}

// decodeStream reads exactly one JSON object; anything else fails the pull.
func decodeStream(r io.Reader) (*streamResponse, error) {
	dec := json.NewDecoder(r)
	var resp *streamResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decisions stream: %w", err)
	}
	if resp == nil {
		return nil, errors.New("decisions stream: the body is null")
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("decisions stream: %w", err)
		}
		return nil, errors.New("decisions stream: trailing data after the JSON object")
	}
	return resp, nil
}

// ban is one enforceable value: an address or a masked prefix, keyed by its normal form.
type ban struct {
	key    string
	fam    family
	single bool         // a single address (a /32 or /128 counts as one)
	addr   netip.Addr   // set when single
	prefix netip.Prefix // normalized masked prefix
}

// parseAddressPrefix parses a decision value into a normalized ban entry.
func parseAddressPrefix(value string) (ban, error) {
	var prefix netip.Prefix
	if addr, aerr := netip.ParseAddr(value); aerr == nil {
		if addr.Zone() != "" {
			return ban{}, errors.New("zoned address")
		}
		prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
	} else if p, perr := netip.ParsePrefix(value); perr == nil {
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			if !p.IsValid() {
				return ban{}, errors.New("invalid prefix")
			}
		}
		prefix = p.Masked()
	} else {
		return ban{}, errors.New("not an address or prefix")
	}
	b := ban{fam: inet, prefix: prefix}
	if prefix.Addr().Is6() {
		b.fam = inet6
	}
	if prefix.IsSingleIP() {
		b.single, b.addr, b.key = true, prefix.Addr(), prefix.Addr().String()
	} else {
		b.key = prefix.String()
	}
	return b, nil
}

// parseBan maps a decision to a ban. use is false for decisions the bouncer does not enforce (types other than ban,
// scopes other than ip and range); err is set for a ban whose value is not an address or prefix.
func parseBan(d decision) (b ban, use bool, err error) {
	if !strings.EqualFold(d.Type, "ban") || !(strings.EqualFold(d.Scope, "ip") || strings.EqualFold(d.Scope, "range")) {
		return ban{}, false, nil
	}
	b, err = parseAddressPrefix(d.Value)
	if err != nil {
		return ban{}, false, err
	}
	return b, true, nil
}

type decisionMeta struct {
	origin   string
	scenario string
}

type banEntry struct {
	ban
	ids map[int64]decisionMeta // decision id -> origin + scenario
}

// lowestMeta returns the origin and scenario of the entry's lowest-numbered decision.
func (e *banEntry) lowestMeta() decisionMeta {
	first := true
	var low int64
	for id := range e.ids {
		if first || id < low {
			low, first = id, false
		}
	}
	return e.ids[low]
}

// origin is the origin of the entry's lowest-numbered decision.
func (e *banEntry) origin() string { return e.lowestMeta().origin }

// banSet is the daemon's view of the active bans (and optional captcha decisions for SPOA): per value, the decisions that cover it.
type banSet struct {
	entries  map[string]*banEntry
	captchas map[string]*banEntry
}

func newBanSet() *banSet {
	return &banSet{entries: map[string]*banEntry{}, captchas: map[string]*banEntry{}}
}

// applyResult is the net change of one pull, per family and sorted, plus what was not used.
type applyResult struct {
	add, del [2][]ban
	skipped  int      // decisions of another type or scope
	invalid  []string // ban values that did not parse, in arrival order
}

// apply applies deleted, then new. A value is added when its first decision arrives and deleted when its last goes;
// the result is the net change, so a value deleted and banned again in one pull is not touched.
func (s *banSet) apply(r *streamResponse) applyResult {
	var res applyResult
	type touched struct {
		ban
		was bool // present before this pull
	}
	seen := map[string]touched{}
	touch := func(d decision) (ban, bool) {
		b, use, err := parseBan(d)
		if err != nil {
			res.invalid = append(res.invalid, d.Value)
			return ban{}, false
		}
		if !use {
			res.skipped++
			return ban{}, false
		}
		if _, ok := seen[b.key]; !ok {
			_, was := s.entries[b.key]
			seen[b.key] = touched{b, was}
		}
		return b, true
	}
	for _, d := range r.Deleted {
		if strings.EqualFold(d.Type, "captcha") && (strings.EqualFold(d.Scope, "ip") || strings.EqualFold(d.Scope, "range")) {
			if b, err := parseAddressPrefix(d.Value); err == nil {
				if e := s.captchas[b.key]; e != nil {
					delete(e.ids, d.ID)
					if len(e.ids) == 0 {
						delete(s.captchas, b.key)
					}
				}
			}
			res.skipped++
			continue
		}
		b, ok := touch(d)
		if !ok {
			continue
		}
		if e := s.entries[b.key]; e != nil {
			delete(e.ids, d.ID)
			if len(e.ids) == 0 {
				delete(s.entries, b.key)
			}
		}
	}
	for _, d := range r.New {
		if strings.EqualFold(d.Type, "captcha") && (strings.EqualFold(d.Scope, "ip") || strings.EqualFold(d.Scope, "range")) {
			if b, err := parseAddressPrefix(d.Value); err == nil {
				e := s.captchas[b.key]
				if e == nil {
					e = &banEntry{ban: b, ids: map[int64]decisionMeta{}}
					s.captchas[b.key] = e
				}
				e.ids[d.ID] = decisionMeta{origin: d.Origin, scenario: d.Scenario}
			}
			res.skipped++
			continue
		}
		b, ok := touch(d)
		if !ok {
			continue
		}
		e := s.entries[b.key]
		if e == nil {
			e = &banEntry{ban: b, ids: map[int64]decisionMeta{}}
			s.entries[b.key] = e
		}
		e.ids[d.ID] = decisionMeta{origin: d.Origin, scenario: d.Scenario}
	}
	for key, t := range seen {
		_, now := s.entries[key]
		switch {
		case now && !t.was:
			res.add[t.fam] = append(res.add[t.fam], t.ban)
		case t.was && !now:
			res.del[t.fam] = append(res.del[t.fam], t.ban)
		}
	}
	for f := range 2 {
		slices.SortFunc(res.add[f], func(a, b ban) int { return strings.Compare(a.key, b.key) })
		slices.SortFunc(res.del[f], func(a, b ban) int { return strings.Compare(a.key, b.key) })
	}
	return res
}

// keys returns the family's values, sorted.
func (s *banSet) keys(f family) []string {
	var out []string
	for key, e := range s.entries {
		if e.fam == f {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// origins counts the family's values per origin.
func (s *banSet) origins(f family) map[string]int {
	out := map[string]int{}
	for _, e := range s.entries {
		if e.fam == f {
			out[e.origin()]++
		}
	}
	return out
}

// spoaDecision is the immutable remediation record stored in the SPOA radix tree.
type spoaDecision struct {
	Remediation string // "ban" or "captcha"
	Origin      string
	Scenario    string
}

// buildSPOATree constructs an immutable radix tree of active captcha and ban decisions (ban wins over captcha on the same prefix).
func (s *banSet) buildSPOATree(secret string) *spoa.RadixTree[spoaDecision] {
	b := spoa.NewRadixBuilder[spoaDecision]()
	redact := func(origin string) string {
		if secret != "" && strings.Contains(origin, secret) {
			return "(hidden)"
		}
		return origin
	}
	for _, e := range s.captchas {
		m := e.lowestMeta()
		b.Insert(e.prefix, spoaDecision{
			Remediation: "captcha",
			Origin:      redact(m.origin),
			Scenario:    m.scenario,
		}, false)
	}
	for _, e := range s.entries {
		m := e.lowestMeta()
		b.Insert(e.prefix, spoaDecision{
			Remediation: "ban",
			Origin:      redact(m.origin),
			Scenario:    m.scenario,
		}, true)
	}
	return b.Build()
}
