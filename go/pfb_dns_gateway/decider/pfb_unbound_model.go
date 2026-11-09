// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the matcher's data model and lookups:
// _top1m_listed (5571-5574); iter_domain_suffixes .. hsts_check_domain with the whiteDB entry helpers
// (6829-6970); DnsblDecision, UNSET, Decision, _decision_for, _LruCache, the PRIO_* bands and _block_entry_band
// (6971-7127); whitelist_lookup_band (7264-7289); evaluate_noaaaa (7778-7781).
//
// Python dict payloads become the structs below; a key Python reads with .get(key, default) keeps a has* flag so
// "absent" stays distinct from the zero value. A Python dict whose iteration order reaches a decision (the regex
// DBs: the first matching rule wins) is a regexDB, which keeps insertion order.
package decider

import (
	"container/list"
	"iter"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// ADR-07: the 6-band precedence scale. Highest wins; a block wins iff block_prio > allow_prio (no ties: block in
// {1,3,5}, allow in {2,4,6}).
const (
	PRIO_FEED_BLOCK           = 1
	PRIO_FEED_ALLOW           = 2
	PRIO_FEED_BLOCK_IMPORTANT = 3
	PRIO_FEED_ALLOW_IMPORTANT = 4
	PRIO_USER_BLOCK           = 5
	PRIO_USER_ALLOW           = 6
)

func blockPriority(important, user bool) int {
	if user {
		return PRIO_USER_BLOCK
	}
	if important {
		return PRIO_FEED_BLOCK_IMPORTANT
	}
	return PRIO_FEED_BLOCK
}

func allowPriority(important, user bool) int {
	if user {
		return PRIO_USER_ALLOW
	}
	if important {
		return PRIO_FEED_ALLOW_IMPORTANT
	}
	return PRIO_FEED_ALLOW
}

// blockEntry is a dataDB / zoneDB payload: {"log", "index", "important", "band"} plus, for a zone,
// "group_owner", "group_origin", "top1m" and "top1m_fallback".
type blockEntry struct {
	log                           string
	index                         int
	important                     bool
	band                          int
	groupOwner, groupOrigin       string
	hasGroupOwner, hasGroupOrigin bool
	// top1m is the one immutable name set every zone of a TOP1M-filtered Group shares.
	top1m         map[string]struct{}
	hasTop1m      bool
	top1mFallback *blockEntry // nil = Python None
}

func blockEntryBand(entry *blockEntry) int {
	return entry.band
}

// whiteEntry is a whiteDB value: a Python bare bool (legacy, the bool is the wildcard flag) or
// {"wildcard", "important", "band"[, "index"]}.
type whiteEntry struct {
	legacy    bool
	wildcard  bool
	important bool
	band      int
	hasBand   bool
	index     int
	hasIndex  bool
}

type feedGroup struct{ feed, group string }

// rejectTally is Python's RejectTally: (feed, group) -> bucket -> count.
type rejectTally map[[2]string]map[string]int

// regexEntry is a regexDB / allowRegexDB / userRegexDB / userAllowRegexDB payload.
type regexEntry struct {
	re        *regexp.Regexp
	important bool
	band      int
}

// regexDB is an insertion-ordered dict[str, regexEntry]; re-assigning a key keeps its position, as in Python.
// A nil *regexDB is an empty dict.
type regexDB struct {
	names  []string
	byName map[string]*regexEntry
}

func (d *regexDB) set(name string, entry *regexEntry) {
	if d.byName == nil {
		d.byName = map[string]*regexEntry{}
	}
	if _, ok := d.byName[name]; !ok {
		d.names = append(d.names, name)
	}
	d.byName[name] = entry
}

func (d *regexDB) get(name string) (*regexEntry, bool) {
	if d == nil {
		return nil, false
	}
	entry, ok := d.byName[name]
	return entry, ok
}

func (d *regexDB) len() int {
	if d == nil {
		return 0
	}
	return len(d.names)
}

func (d *regexDB) items() iter.Seq2[string, *regexEntry] {
	return func(yield func(string, *regexEntry) bool) {
		if d == nil {
			return
		}
		for _, name := range d.names {
			if !yield(name, d.byName[name]) {
				return
			}
		}
	}
}

// dnsblDecision is Python's DnsblDecision. Python's Any-typed log_type is False when nothing matched; it is "" here,
// since every reader compares it against the "0".."6" flag strings.
type dnsblDecision struct {
	isFound      bool
	inWhitelist  bool
	inHsts       bool
	nullBlocking bool
	// issue #31: NXDOMAIN block shape (log_type "3"/"4"), distinct from null_blocking (0.0.0.0/::) and VIP.
	nxdomain bool
	logType  string
	bType    string
	pType    string
	feed     string
	group    string
	bEval    string
	// ADR-08: a Confusable-mode ALERT does not block but must be surfaced; nil = Python None.
	idnAlert    *idnAlert
	groupOwner  string
	groupOrigin string
}

// idnAlert is the (feed, group, b_eval) tuple of an ADR-08 alert.
type idnAlert struct{ feed, group, bEval string }

type unsetType struct{ _ byte } // non-zero size, so every &unsetType{} would still be one distinct pointer

// UNSET marks a Decision axis that has not been evaluated yet, distinct from an evaluated allow / no-match.
var UNSET any = &unsetType{}

// decision is the single per-domain verdict across every axis operate() decides, filled lazily and cached in
// decisionDB. Python mutates the axes under the GIL; here each axis is guarded by mu, so concurrent queries that
// share a memo are race-free. snapGen is immutable.
type decision struct {
	mu         sync.Mutex
	dnsbl      any // *dnsblDecision once evaluated
	noaaaa     any // bool (AAAA only): true = block, false = allow
	safesearch any // the matched safeSearchDB entry, or nil = no match
	// issue #1074: snapshot.gen this Decision was computed against. 0 (no real generation) never matches.
	snapGen int64
}

func newDecision(snapGen int64) *decision {
	return &decision{dnsbl: UNSET, noaaaa: UNSET, safesearch: UNSET, snapGen: snapGen}
}

func (d *decision) getDnsbl() any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dnsbl
}

func (d *decision) setDnsbl(v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dnsbl = v
}

func (d *decision) getNoaaaa() any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.noaaaa
}

func (d *decision) setNoaaaa(v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.noaaaa = v
}

func (d *decision) getSafesearch() any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.safesearch
}

func (d *decision) setSafesearch(v any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.safesearch = v
}

// decisionFor gets or creates the one decision entry for a name; the caller fills the axes. issue #1074: a memo is
// only valid for the generation that produced it, so a foreign-generation entry is replaced, never extended.
func decisionFor(decisionDB *lruCache[*decision], name string, snapGen int64) *decision {
	dec, ok := decisionDB.get(name)
	if ok && dec.snapGen > snapGen {
		// An older-generation straggler neither evicts the newer entry nor extends it: it writes into a throwaway
		// decision no reader will ever see (gen advances monotonically, so its verdict can never become current).
		return newDecision(snapGen)
	}
	if !ok || dec.snapGen != snapGen {
		dec = newDecision(snapGen)
		decisionDB.set(name, dec)
	}
	return dec
}

type lruItem[V any] struct {
	key   string
	value V
}

// lruCache is the bounded, LRU-evicting store for decisionDB. Recency is bumped on both get and set; once maxsize
// is exceeded the least-recently-used entry is evicted (maxsize <= 0: unbounded). Python takes the lock only when
// the module runs threaded; an uncontended sync.Mutex costs nothing, so every operation takes it.
type lruCache[V any] struct {
	mu      sync.Mutex
	maxsize int
	items   map[string]*list.Element // Value is *lruItem[V]
	order   *list.List               // front = least recently used
}

func newLruCache[V any](maxsize int) *lruCache[V] {
	return &lruCache[V]{maxsize: maxsize, items: map[string]*list.Element{}, order: list.New()}
}

func (c *lruCache[V]) get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToBack(element)
	return element.Value.(*lruItem[V]).value, true
}

func (c *lruCache[V]) set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.items[key]; ok {
		element.Value.(*lruItem[V]).value = value
		c.order.MoveToBack(element)
	} else {
		c.items[key] = c.order.PushBack(&lruItem[V]{key: key, value: value})
	}
	if 0 < c.maxsize && c.maxsize < len(c.items) {
		oldest := c.order.Front()
		c.order.Remove(oldest)
		delete(c.items, oldest.Value.(*lruItem[V]).key)
	}
}

func (c *lruCache[V]) contains(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.items[key]
	return ok
}

// delete reports whether key was present; Python's `del cache[key]` raises KeyError instead.
func (c *lruCache[V]) delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.items[key]
	if ok {
		c.order.Remove(element)
		delete(c.items, key)
	}
	return ok
}

func (c *lruCache[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *lruCache[V]) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.items)
	c.order.Init()
}

// setMaxsize stands in for Python's `decisionDB.maxsize = n`; it evicts nothing until the next set.
func (c *lruCache[V]) setMaxsize(maxsize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxsize = maxsize
}

// top1mListed reports whether TOP1M names name: the listed domain itself or its www. form, never a deeper
// subdomain (#1542).
func top1mListed(name string, top1m map[string]struct{}) bool {
	if _, ok := top1m[name]; ok {
		return true
	}
	rest, found := strings.CutPrefix(name, "www.")
	if !found {
		return false
	}
	_, ok := top1m[rest]
	return ok
}

// dropFirstLabel is Python's q.split(".", 1)[-1]: everything after the first dot, or q itself when it has none.
func dropFirstLabel(q string) string {
	if _, rest, found := strings.Cut(q, "."); found {
		return rest
	}
	return q
}

func iterDomainSuffixes(name string) iter.Seq[string] {
	return func(yield func(string) bool) {
		q := name
		for range strings.Count(name, ".") + 1 {
			if !yield(q) {
				return
			}
			q = dropFirstLabel(q)
		}
	}
}

// zoneEntryFor is the zone payload that blocks qName (issue #3648): an entry last written by a TOP1M-filtered Group
// yields, for a name TOP1M lists, to the key's last unfiltered writer, or blocks nothing (nil) when there is none.
func zoneEntryFor(qName string, entry *blockEntry) *blockEntry {
	if entry.hasTop1m && top1mListed(qName, entry.top1m) {
		return entry.top1mFallback
	}
	return entry
}

// findZoneMatch returns the matching zone key and its payload; a nil payload is Python's (None, None).
func findZoneMatch(qName string, zoneDB map[string]*blockEntry) (string, *blockEntry) {
	for q := range iterDomainSuffixes(qName) {
		if entry := zoneDB[q]; entry != nil {
			if entry = zoneEntryFor(qName, entry); entry != nil {
				return q, entry
			}
		}
	}
	return "", nil
}

// findNoaaaaWildcardParent walks the parents only (never qName itself, never the bare TLD); a false value is falsy.
func findNoaaaaWildcardParent(qName string, noaaaaDB map[string]bool) (string, bool) {
	q := dropFirstLabel(qName)
	for range strings.Count(q, ".") {
		if noaaaaDB[q] {
			return q, true
		}
		q = dropFirstLabel(q)
	}
	return "", false
}

// whiteEntryWildcard is the wildcard flag of a whiteDB value, tolerant of both shapes: a bare bool IS the flag.
func whiteEntryWildcard(e whiteEntry) bool {
	return e.wildcard
}

// whiteEntryImportant is the sovereignty flag; a bare-bool legacy entry is never important.
func whiteEntryImportant(e whiteEntry) bool {
	return !e.legacy && e.important
}

// whiteEntryBand is the numeric band: an explicit band, else derived from important (a user allow, band 6); a
// bare-bool legacy entry is a feed allow, band 2.
func whiteEntryBand(e whiteEntry) int {
	if e.legacy {
		return PRIO_FEED_ALLOW
	}
	if e.hasBand {
		return e.band
	}
	if e.important {
		return PRIO_USER_ALLOW
	}
	return PRIO_FEED_ALLOW
}

// whiteWidenEntry is the user-allow collision merge: broadest wildcard, any important, max band. It drops the feed
// index; the permit/ABP insert paths keep their own band-monotonic merge.
func whiteWidenEntry(existing, newEntry whiteEntry) whiteEntry {
	return whiteEntry{
		wildcard:  whiteEntryWildcard(existing) || whiteEntryWildcard(newEntry),
		important: whiteEntryImportant(existing) || whiteEntryImportant(newEntry),
		band:      max(whiteEntryBand(existing), whiteEntryBand(newEntry)),
		hasBand:   true,
	}
}

// whitelistLookupDomain resolves a whitelist hit to (matched, important): exact, then www.-strip, then a
// parent-suffix walk gated by tldSeg that only honours WILDCARD entries.
func whitelistLookupDomain(name string, whiteDB map[string]whiteEntry, tldSeg int64) (bool, bool) {
	if entry, ok := whiteDB[name]; ok {
		return true, whiteEntryImportant(entry)
	}
	if rest, found := strings.CutPrefix(name, "www."); found {
		if entry, ok := whiteDB[rest]; ok {
			return true, whiteEntryImportant(entry)
		}
	}
	q := dropFirstLabel(name)
	for x := int64(strings.Count(q, ".") + 1); x > 0; x-- {
		if x >= tldSeg {
			if entry, ok := whiteDB[q]; ok && whiteEntryWildcard(entry) {
				return true, whiteEntryImportant(entry)
			}
		}
		q = dropFirstLabel(q)
	}
	return false, false
}

func whitelistCheckDomain(name string, whiteDB map[string]whiteEntry, tldSeg int64) bool {
	matched, _ := whitelistLookupDomain(name, whiteDB, tldSeg)
	return matched
}

func resolveFeedGroup(index int, feedGroupIndexDB map[int]feedGroup) (string, string) {
	if fg, ok := feedGroupIndexDB[index]; ok {
		return fg.feed, fg.group
	}
	return "Unknown", "Unknown"
}

func hstsCheckDomain(name string, hstsDB map[string]struct{}, hstsTlds []string, tld string) (bool, string) {
	if slices.Contains(hstsTlds, tld) {
		return true, "HSTS_TLD"
	}
	q := name
	// issue #713: this walk must check EVERY parent suffix; skipping levels serves the block page over the wrong
	// cert for an HSTS-preloaded parent.
	for range strings.Count(q, ".") + 1 {
		if _, ok := hstsDB[q]; ok {
			return true, "HSTS"
		}
		q = dropFirstLabel(q)
	}
	return false, "Python"
}

// whitelistLookupBand is the highest whiteDB allow band that matches name (exact, www.-strip, then the wildcard
// suffix walk gated by tldSeg); 0 if none matches. All matching entries compete, so an exact feed allow cannot hide
// a higher-band user wildcard (#3648).
func whitelistLookupBand(name string, whiteDB map[string]whiteEntry, tldSeg int64) int {
	best := 0
	if entry, ok := whiteDB[name]; ok {
		best = whiteEntryBand(entry)
		if best == PRIO_USER_ALLOW {
			return best
		}
	}
	if rest, found := strings.CutPrefix(name, "www."); found {
		if entry, ok := whiteDB[rest]; ok {
			best = max(best, whiteEntryBand(entry))
			if best == PRIO_USER_ALLOW {
				return best
			}
		}
	}
	q := dropFirstLabel(name)
	for x := int64(strings.Count(q, ".") + 1); x > 0; x-- {
		if x >= tldSeg {
			if entry, ok := whiteDB[q]; ok && whiteEntryWildcard(entry) {
				best = max(best, whiteEntryBand(entry))
			}
		}
		q = dropFirstLabel(q)
	}
	return best
}

func evaluateNoaaaa(qName string, noaaaaDB map[string]bool) bool {
	if _, ok := noaaaaDB[qName]; ok {
		return true
	}
	_, ok := findNoaaaaWildcardParent(qName, noaaaaDB)
	return ok
}
