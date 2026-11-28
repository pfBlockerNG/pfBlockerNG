package main

import (
	"bufio"
	"context"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/spoa"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// ipMatch is the attribution metadata stored per prefix in pfb-core's SPOA radix tree.
type ipMatch struct {
	Alias  string
	Feed   string
	Action string
}

type spoaSnapshot struct {
	global     *spoa.RadixTree[ipMatch]
	byAlias    map[string]*spoa.RadixTree[ipMatch]
	generation uint64
	loadedAt   time.Time
	aliases    []string
	entriesV4  int
	entriesV6  int
}

// spoaEngine serves HAProxy SPOP lookups against pfBlockerNG IP lists with atomic hot-swap on updates.
type spoaEngine struct {
	listen  string
	dbDir   string
	store   *settings.Store
	aliases map[string]bool // empty = all deny aliases
	logf    func(string, ...any)

	reloadMu sync.Mutex
	gen      uint64
	snap     atomic.Pointer[spoaSnapshot]
	srv      *spoa.Server

	hitsMu  sync.Mutex
	byAlias map[string]uint64
	byFeed  map[string]uint64
}

func newSPOAEngine(listen, dbDir string, store *settings.Store, aliasesCSV string, logf func(string, ...any)) *spoaEngine {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	aliasFilter := map[string]bool{}
	for part := range strings.SplitSeq(aliasesCSV, ",") {
		if t := strings.TrimSpace(part); t != "" {
			aliasFilter[t] = true
		}
	}
	e := &spoaEngine{
		listen:  listen,
		dbDir:   dbDir,
		store:   store,
		aliases: aliasFilter,
		logf:    logf,
		byAlias: map[string]uint64{},
		byFeed:  map[string]uint64{},
	}
	e.snap.Store(&spoaSnapshot{
		global:  spoa.NewRadixBuilder[ipMatch]().Build(),
		byAlias: map[string]*spoa.RadixTree[ipMatch]{},
	})
	return e
}

type feedMeta struct {
	alias  string
	feed   string
	action string
}

// feedCatalog builds a lookup from "<class>/<stem>" -> (alias, feed, action) using Core's settings snapshot.
func (e *spoaEngine) feedCatalog() map[string]feedMeta {
	out := map[string]feedMeta{}
	if e.store == nil {
		return out
	}
	snap, err := e.store.Get([]string{"feeds/ipv4", "feeds/ipv6", "feeds/geoip"})
	if err != nil || !snap.Initialized {
		return out
	}
	byID := map[string]map[string]any{}
	for _, p := range snap.Projections {
		byID[strings.TrimPrefix(p.ResourceID, "settings/")] = p.Value
	}
	for _, fam := range []struct {
		proj, suffix string
	}{{"feeds/ipv4", "_v4"}, {"feeds/ipv6", "_v6"}} {
		sec := byID[fam.proj]
		groups, _ := sec["groups"].([]any)
		for _, raw := range groups {
			g, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			action, _ := g["action"].(string)
			class := actionClass(action)
			if class == "" {
				continue
			}
			name, _ := g["name"].(string)
			if name == "" {
				continue
			}
			alias := "pfB_" + name + fam.suffix
			out[class+"/"+alias+"_custom"] = feedMeta{alias: alias, feed: name + "_custom", action: class}
			feeds, _ := g["feeds"].([]any)
			for _, fraw := range feeds {
				f, ok := fraw.(map[string]any)
				if !ok {
					continue
				}
				state, _ := f["state"].(string)
				if state == "disabled" {
					continue
				}
				header, _ := f["header"].(string)
				if header == "" {
					continue
				}
				out[class+"/"+header+fam.suffix] = feedMeta{alias: alias, feed: header, action: class}
				out[class+"/"+header] = feedMeta{alias: alias, feed: header, action: class}
			}
		}
	}
	return out
}

func actionClass(action string) string {
	switch {
	case strings.HasPrefix(action, "Deny_"), action == "Alias_Deny":
		return "deny"
	case strings.HasPrefix(action, "Permit_"), action == "Alias_Permit":
		return "permit"
	case strings.HasPrefix(action, "Match_"), action == "Alias_Match":
		return "match"
	case action == "Alias_Native":
		return "native"
	default:
		return ""
	}
}

// Reload scans configured IP list files under dbDir, builds a fresh immutable radix tree, and swaps it atomically.
func (e *spoaEngine) Reload() *spoaSnapshot {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	catalog := e.feedCatalog()
	globalBuilder := spoa.NewRadixBuilder[ipMatch]()
	aliasBuilders := map[string]*spoa.RadixBuilder[ipMatch]{}

	classes := []string{"deny"}
	if len(e.aliases) > 0 {
		classes = []string{"deny", "permit", "match", "native"}
	}

	if e.dbDir != "" {
		for _, class := range classes {
			dir := filepath.Join(e.dbDir, class)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			names := make([]string, 0, len(entries))
			for _, de := range entries {
				if !de.IsDir() && strings.HasSuffix(de.Name(), ".txt") {
					names = append(names, de.Name())
				}
			}
			slices.Sort(names)
			for _, name := range names {
				stem := strings.TrimSuffix(name, ".txt")
				meta, ok := catalog[class+"/"+stem]
				if !ok {
					alias := stem
					if !strings.HasPrefix(alias, "pfB_") && !strings.HasPrefix(alias, "DNSBLIP") {
						alias = "pfB_" + alias
					}
					meta = feedMeta{alias: alias, feed: stem, action: class}
				}
				if len(e.aliases) > 0 && !e.aliases[meta.alias] && !e.aliases[meta.feed] && !e.aliases[stem] {
					continue
				}
				ab := aliasBuilders[meta.alias]
				if ab == nil {
					ab = spoa.NewRadixBuilder[ipMatch]()
					aliasBuilders[meta.alias] = ab
				}
				match := ipMatch{Alias: meta.alias, Feed: meta.feed, Action: meta.action}
				if err := loadPrefixFile(filepath.Join(dir, name), match, globalBuilder, ab); err != nil && !os.IsNotExist(err) {
					e.logf("spoa: reading %s: %v", filepath.Join(dir, name), err)
				}
			}
		}
	}

	globalTree := globalBuilder.Build()
	byAlias := make(map[string]*spoa.RadixTree[ipMatch], len(aliasBuilders))
	aliasNames := make([]string, 0, len(aliasBuilders))
	for alias, ab := range aliasBuilders {
		byAlias[alias] = ab.Build()
		aliasNames = append(aliasNames, alias)
	}
	slices.Sort(aliasNames)
	v4, v6 := globalTree.Counts()
	e.gen++
	snap := &spoaSnapshot{
		global:     globalTree,
		byAlias:    byAlias,
		generation: e.gen,
		loadedAt:   time.Now().UTC(),
		aliases:    aliasNames,
		entriesV4:  v4,
		entriesV6:  v6,
	}
	e.snap.Store(snap)
	return snap
}

func loadPrefixFile(path string, match ipMatch, builders ...*spoa.RadixBuilder[ipMatch]) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if idx := strings.IndexAny(line, " \t#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		var prefix netip.Prefix
		if addr, err := netip.ParseAddr(line); err == nil {
			if addr.Zone() != "" {
				continue
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else if p, err := netip.ParsePrefix(line); err == nil {
			prefix = p.Masked()
		} else {
			continue
		}
		for _, b := range builders {
			b.Insert(prefix, match, false)
		}
	}
	return sc.Err()
}

// Handle evaluates one SPOP NOTIFY frame against pfb-core's in-memory radix tree.
func (e *spoaEngine) Handle(_ context.Context, msgs []spoa.Message) ([]spoa.Action, bool, error) {
	var ip netip.Addr
	var aliasOverride string
	foundIP := false
	for _, m := range msgs {
		if v, ok := m.Arg("src-ip"); ok {
			if addr, ok := v.ParseIP(); ok {
				ip, foundIP = addr, true
			}
		} else if v, ok := m.Arg("ip"); ok {
			if addr, ok := v.ParseIP(); ok {
				ip, foundIP = addr, true
			}
		}
		if v, ok := m.Arg("alias"); ok {
			if s, ok := v.AsString(); ok && s != "" {
				aliasOverride = s
			}
		}
		if foundIP {
			break
		}
	}
	if !foundIP {
		return []spoa.Action{spoa.SetTxnVar("blocked", spoa.BoolValue(false))}, false, nil
	}

	snap := e.snap.Load()
	tree := snap.global
	if aliasOverride != "" {
		tree = snap.byAlias[aliasOverride]
	}
	if m, ok := tree.Lookup(ip); ok {
		e.recordHit(m.Alias, m.Feed)
		return []spoa.Action{
			spoa.SetTxnVar("blocked", spoa.BoolValue(true)),
			spoa.SetTxnVar("alias", spoa.StringValue(m.Alias)),
			spoa.SetTxnVar("feed", spoa.StringValue(m.Feed)),
			spoa.SetTxnVar("action", spoa.StringValue(m.Action)),
		}, true, nil
	}
	return []spoa.Action{spoa.SetTxnVar("blocked", spoa.BoolValue(false))}, false, nil
}

func (e *spoaEngine) recordHit(alias, feed string) {
	e.hitsMu.Lock()
	e.byAlias[alias]++
	e.byFeed[feed]++
	e.hitsMu.Unlock()
}

type spoaStatusResp struct {
	Enabled    bool              `json:"enabled"`
	Listen     string            `json:"listen"`
	Generation uint64            `json:"generation"`
	LoadedAt   int64             `json:"loadedAt"`
	EntriesV4  int               `json:"entriesV4"`
	EntriesV6  int               `json:"entriesV6"`
	Aliases    []string          `json:"aliases"`
	Lookups    uint64            `json:"lookups"`
	Blocked    uint64            `json:"blocked"`
	Errors     uint64            `json:"errors"`
	ByAlias    map[string]uint64 `json:"byAlias"`
	ByFeed     map[string]uint64 `json:"byFeed"`
}

func (e *spoaEngine) status() spoaStatusResp {
	if e == nil {
		return spoaStatusResp{Enabled: false, Aliases: []string{}, ByAlias: map[string]uint64{}, ByFeed: map[string]uint64{}}
	}
	snap := e.snap.Load()
	var loadedAt int64
	if !snap.loadedAt.IsZero() {
		loadedAt = snap.loadedAt.Unix()
	}
	resp := spoaStatusResp{
		Enabled:    true,
		Listen:     e.listen,
		Generation: snap.generation,
		LoadedAt:   loadedAt,
		EntriesV4:  snap.entriesV4,
		EntriesV6:  snap.entriesV6,
		Aliases:    slices.Clone(snap.aliases),
		ByAlias:    map[string]uint64{},
		ByFeed:     map[string]uint64{},
	}
	if resp.Aliases == nil {
		resp.Aliases = []string{}
	}
	if e.srv != nil {
		m := e.srv.Metrics()
		resp.Lookups = m.Lookups
		resp.Blocked = m.Blocked
		resp.Errors = m.Errors
	}
	e.hitsMu.Lock()
	for k, v := range e.byAlias {
		resp.ByAlias[k] = v
	}
	for k, v := range e.byFeed {
		resp.ByFeed[k] = v
	}
	e.hitsMu.Unlock()
	return resp
}

func spoaMethods(e *spoaEngine) map[string]method {
	return map[string]method{
		"GetSPOAStatus": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			return e.status(), nil
		}},
		"ReloadSPOA": {mutating: true, call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				RequestID string `json:"requestId"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			if e == nil {
				return spoaStatusResp{Enabled: false, Aliases: []string{}, ByAlias: map[string]uint64{}, ByFeed: map[string]uint64{}}, nil
			}
			e.Reload()
			return e.status(), nil
		}},
	}
}

func parseOptionalGID(v string, dst *int, set *bool) error {
	gid, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return err
	}
	if gid > 1<<31-1 {
		return fs.ErrInvalid
	}
	*dst, *set = int(gid), true
	return nil
}
