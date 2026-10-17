package main

import (
	"bytes"
	"io"
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
	ACLForward ACLAction = iota // let Unbound decide (every action but deny/refuse, and no match)
	ACLDrop                     // Unbound `deny`: send nothing
	ACLRefuse                   // Unbound `refuse`: answer REFUSED
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

const (
	maxACLFile = 16 << 20 // larger is treated as unreadable
	maxACLLine = 4096     // real `access-control:` rows are far shorter
)

// Only deny and refuse act; the gateway must never be stricter than Unbound, so any other known action forwards.
var aclActions = map[string]ACLAction{
	"deny": ACLDrop, "refuse": ACLRefuse,
	"allow": ACLForward, "allow_snoop": ACLForward, "allow_setrd": ACLForward, "allow_cookie": ACLForward,
	"deny_non_local": ACLForward, "refuse_non_local": ACLForward,
}

// Unbound inserts these `allow` rows beneath the file's (acl_list_apply_cfg), so a broader deny or
// refuse never reaches localhost; being stricter than that would cut off local clients.
var unboundLocalhost = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

type aclRules struct {
	entries      int // distinct prefixes read from the file, not counting the localhost defaults
	byPrefix     map[netip.Prefix]ACLAction
	bits4, bits6 []int // distinct prefix lengths present, longest first
}

type aclSnapshot struct {
	info  os.FileInfo // identity of the file the rules came from; nil when the file is missing
	rules aclRules
}

// ACL mirrors the client part of Unbound's access-control list from pfSense's access_lists.conf.
type ACL struct {
	path string
	logf func(format string, args ...any)
	mu   sync.Mutex // serialises Refresh
	snap atomic.Pointer[aclSnapshot]
}

// NewACL loads path immediately; a missing or unreadable file is logged and forwards everything.
func NewACL(path string, logf func(format string, args ...any)) *ACL {
	a := &ACL{path: path, logf: logf}
	a.Refresh()
	return a
}

// Refresh reloads when the file's (mtime, size, inode) changed and reports whether it did.
func (a *ACL) Refresh() (changed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.snap.Load()
	fi, err := os.Stat(a.path)
	if err != nil {
		if prev != nil && prev.info == nil {
			return false
		}
		a.logf("acl: %s: %v; forwarding every query", a.path, err)
		a.snap.Store(&aclSnapshot{})
		return true
	}
	if prev != nil && prev.info != nil && os.SameFile(prev.info, fi) &&
		prev.info.ModTime().Equal(fi.ModTime()) && prev.info.Size() == fi.Size() {
		return false
	}
	a.snap.Store(a.load(fi))
	return true
}

// Lookup returns the action of the most specific entry matching client; safe alongside Refresh.
func (a *ACL) Lookup(client netip.Addr) ACLAction {
	if !client.IsValid() {
		return ACLForward
	}
	return a.snap.Load().rules.lookup(client.Unmap()) // Addr.Prefix drops any zone
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
	return ACLForward
}

// load never fails: on any trouble it logs and returns empty rules tied to the file it saw, so an
// unchanged broken file is not retried (and logged) every tick.
func (a *ACL) load(stat os.FileInfo) *aclSnapshot {
	data, info, err := readCapped(a.path)
	if info == nil {
		info = stat
	}
	if err != nil {
		a.logf("acl: %s: %v; forwarding every query", a.path, err)
		return &aclSnapshot{info: info}
	}
	rules := parseACL(data)
	a.logf("acl: loaded %d entries from %s", rules.entries, a.path)
	return &aclSnapshot{info: info, rules: rules}
}

// readCapped returns the identity taken BEFORE the read: a writer racing the read then changes
// (mtime, size) against it, so the next Refresh reloads instead of trusting a torn read.
func readCapped(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Size() > maxACLFile {
		return nil, info, errTooLarge
	}
	buf := make([]byte, info.Size()+1) // one spare byte: a file that grew stops at this snapshot
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, info, err
	}
	return buf[:n], info, nil
}

type aclError string

func (e aclError) Error() string { return string(e) }

const errTooLarge = aclError("file too large (over 16 MiB)")

// parseACL reads complete lines only: file_put_contents truncates then writes, so an unterminated tail
// may be a cut-off action (`refuse_non_local` read as `refuse`).
func parseACL(data []byte) aclRules {
	rules := aclRules{byPrefix: map[netip.Prefix]ACLAction{}}
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		line := data[:i]
		data = data[i+1:]
		if len(line) > maxACLLine || !utf8.Valid(line) {
			continue
		}
		if prefix, action, ok := parseACLLine(string(line)); ok {
			rules.byPrefix[prefix] = action // of identical prefixes the last line wins, as in Unbound
		}
	}
	rules.entries = len(rules.byPrefix)
	for _, p := range unboundLocalhost {
		if _, listed := rules.byPrefix[p]; !listed {
			rules.byPrefix[p] = ACLForward
		}
	}
	var has4, has6 [129]bool
	for p := range rules.byPrefix {
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

// parseACLLine accepts `access-control: <netblock> <action>`; Unbound's lexer splits on space and tab only.
func parseACLLine(line string) (netip.Prefix, ACLAction, bool) {
	line, _, _ = strings.Cut(line, "#")
	f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' })
	if len(f) != 3 || f[0] != "access-control:" {
		return netip.Prefix{}, 0, false
	}
	action, known := aclActions[f[2]]
	if !known {
		return netip.Prefix{}, 0, false
	}
	block := f[1]
	if len(block) >= 2 && block[0] == '"' && block[len(block)-1] == '"' {
		block = block[1 : len(block)-1]
	}
	prefix, ok := parseNetblock(block)
	return prefix, action, ok
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
