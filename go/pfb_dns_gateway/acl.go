package main

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// ACLAction is what the gateway does with a client before asking the decider.
type ACLAction int

const (
	ACLForward ACLAction = iota // let Unbound decide (every action but deny/refuse, and a config that cannot load)
	ACLDrop                     // Unbound `deny`: send nothing
	ACLRefuse                   // Unbound `refuse`, or no row names the client: answer REFUSED
)

func (a ACLAction) String() string {
	switch a {
	case ACLDrop:
		return "drop"
	case ACLRefuse:
		return "refuse"
	}
	return "forward"
}

// Only deny and refuse act; the gateway must never be stricter than Unbound, so any other known action forwards.
var aclActions = map[string]ACLAction{
	"deny": ACLDrop, "refuse": ACLRefuse,
	"allow": ACLForward, "allow_snoop": ACLForward, "allow_setrd": ACLForward, "allow_cookie": ACLForward,
	"deny_non_local": ACLForward, "refuse_non_local": ACLForward,
}

// Unbound inserts these `allow` rows beneath the config's (acl_list_apply_cfg), so a broader deny or
// refuse never reaches localhost; being stricter than that would cut off local clients.
var unboundLocalhost = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

type aclRules struct {
	entries      int // distinct prefixes read from the config, not counting the localhost defaults
	byPrefix     map[netip.Prefix]ACLAction
	bits4, bits6 []int // distinct prefix lengths present, longest first
}

// aclSnapshot is one load of the config: the rules, and every file and glob they came from.
type aclSnapshot struct {
	deps   aclDeps
	rules  aclRules
	broken bool // Unbound would not start on this config: the gateway forwards everything
}

// ACL mirrors the client part of Unbound's access-control list: the rows of its config file and of every file the
// config includes, which is where pfSense's access_lists.conf, pfBlockerNG's marked clause and an admin's custom
// options all end up.
type ACL struct {
	path string
	logf func(format string, args ...any)
	mu   sync.Mutex // serialises Refresh
	snap atomic.Pointer[aclSnapshot]
}

// NewACL loads the config at path immediately; one Unbound could not load is logged and forwards everything.
func NewACL(path string, logf func(format string, args ...any)) *ACL {
	a := &ACL{path: path, logf: logf}
	a.Refresh()
	return a
}

// Refresh reloads when any file or glob the rules came from changed (mtime, size, inode, matches) and reports
// whether it did.
func (a *ACL) Refresh() (changed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev := a.snap.Load(); prev != nil && !prev.deps.changed() {
		return false
	}
	a.snap.Store(a.load())
	return true
}

// Lookup returns the action of the most specific row matching client, Refuse when none does (Unbound's default);
// safe alongside Refresh.
func (a *ACL) Lookup(client netip.Addr) ACLAction {
	snap := a.snap.Load()
	if !client.IsValid() || snap.broken {
		return ACLForward
	}
	return snap.rules.lookup(client.Unmap()) // Addr.Prefix drops any zone
}

func (r *aclRules) lookup(client netip.Addr) ACLAction {
	bits := r.bits6
	if client.Is4() {
		bits = r.bits4
	}
	for _, b := range bits {
		p, _ := client.Prefix(b)
		if action, ok := r.byPrefix[p]; ok {
			return action
		}
	}
	return ACLRefuse
}

// load never fails: on any trouble it logs and returns a broken snapshot tied to the files it saw, so an unchanged
// broken config is not retried (and logged) every tick.
func (a *ACL) load() *aclSnapshot {
	w := newConfWalker()
	if err := w.file(a.path, 0); err != nil {
		a.logf("acl: %v; forwarding every query", err)
		return &aclSnapshot{deps: w.deps, broken: true}
	}
	w.allowImplicit()
	rules := newACLRules(w.rows)
	a.logf("acl: loaded %d entries from %d files starting at %s", rules.entries, w.opened, a.path)
	return &aclSnapshot{deps: w.deps, rules: rules}
}

// newACLRules adds Unbound's localhost defaults to rows (of identical prefixes the last row read won, as in Unbound:
// it builds the list by prepending and keeps the first tree insert) and indexes them by prefix length.
func newACLRules(rows map[netip.Prefix]ACLAction) aclRules {
	rules := aclRules{entries: len(rows), byPrefix: rows}
	for _, p := range unboundLocalhost {
		if _, listed := rows[p]; !listed {
			rows[p] = ACLForward
		}
	}
	var has4, has6 [129]bool
	for p := range rows {
		if p.Addr().Is4() {
			has4[p.Bits()] = true
		} else {
			has6[p.Bits()] = true
		}
	}
	for b := 128; b >= 0; b-- {
		if has4[b] {
			rules.bits4 = append(rules.bits4, b)
		}
		if has6[b] {
			rules.bits6 = append(rules.bits6, b)
		}
	}
	return rules
}

// aclWords splits a row after its comment: Unbound's lexer splits on space and tab only. Only the part before the
// comment must be UTF-8; the comment is Unbound's to skip.
func aclWords(line string) ([]string, bool) {
	line, _, _ = strings.Cut(line, "#")
	if !utf8.ValidString(line) {
		return nil, false
	}
	return strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' }), true
}

// unquote strips one pair of matching quotes: Unbound's lexer takes a double- or single-quoted word wherever a word goes.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// parseACLLine accepts `access-control: <netblock> <action>`; a netblock glued to the keyword counts too, as Unbound 1.26.1 reads it.
func parseACLLine(line string) (netip.Prefix, ACLAction, bool) {
	f, ok := aclWords(line)
	if !ok || len(f) == 0 {
		return netip.Prefix{}, 0, false
	}
	if netblock, glued := strings.CutPrefix(f[0], "access-control:"); glued && netblock != "" {
		f = append([]string{"access-control:", netblock}, f[1:]...)
	}
	if len(f) != 3 || f[0] != "access-control:" {
		return netip.Prefix{}, 0, false
	}
	action, known := aclActions[unquote(f[2])]
	if !known {
		return netip.Prefix{}, 0, false
	}
	prefix, ok := parseNetblock(unquote(f[1]))
	return prefix, action, ok
}

// implicitAllowRows make Unbound allow their netblock when no access-control row names the same netblock.
var implicitAllowRows = map[string]bool{
	"access-control-view:": true, "access-control-tag:": true,
	"access-control-tag-action:": true, "access-control-tag-data:": true,
}

// parseImplicitRow reads the netblock of an implicit-allow row.
func parseImplicitRow(line string) (netip.Prefix, bool) {
	f, ok := aclWords(line)
	if !ok || len(f) < 2 || !implicitAllowRows[f[0]] {
		return netip.Prefix{}, false
	}
	return parseNetblock(unquote(f[1]))
}

// parseNetblock masks host bits and turns a bare address into a host prefix; zones are rejected.
func parseNetblock(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// sameFile reports whether b is still the file (inode, mtime, size) a was.
func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}
