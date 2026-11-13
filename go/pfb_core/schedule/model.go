package schedule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Model is the scheduler's view of the config: the default schedule and every feed and Extras job in config order.
type Model struct {
	ConfigHash string
	Scheduled  bool
	Default    Schedule
	Entries    []Entry
}

// BL is the extra:bl job; DCC and BL together are what RuntimeModel takes as the Extras.
type BL struct {
	Enabled bool
	Cadence string
}

type Extras struct {
	DCC bool
	BL  BL
}

var (
	tokenRe    = regexp.MustCompile(`^(?:0|[1-9][0-9]*)$`)
	aliasRe    = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	headerRe   = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	identityRe = regexp.MustCompile(`^[a-zA-Z0-9,_-]+$`)
	families   = []string{"ipv4", "ipv6", "dnsbl"}
	ipActions  = []string{
		"Disabled", "Deny_Inbound", "Deny_Outbound", "Deny_Both", "Permit_Inbound", "Permit_Outbound", "Permit_Both",
		"Match_Inbound", "Match_Outbound", "Match_Both", "Alias_Deny", "Alias_Permit", "Alias_Match", "Alias_Native",
	}
)

// token reads a canonical unsigned decimal string within [lo, hi].
func token(v any, lo, hi int) (int, bool) {
	s, ok := v.(string)
	if !ok || !tokenRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= lo && n <= hi
}

// readSchedule reads <prefix>weekday/hour/minute from a config array.
func readSchedule(src map[string]any, prefix string) (Schedule, bool) {
	weekday, okW := token(src[prefix+"weekday"], 1, 7)
	hour, okH := token(src[prefix+"hour"], 0, 23)
	minute, okM := token(src[prefix+"minute"], 0, 45)
	return Schedule{weekday, hour, minute}, okW && okH && okM && minute%15 == 0
}

// asArray reads a PHP array: an object is its own keys, a list has no string key.
func asArray(v any) (map[string]any, bool) {
	switch a := v.(type) {
	case map[string]any:
		return a, true
	case []any:
		return nil, true
	}
	return nil, false
}

// groupActionValid reports whether a group's action belongs to its family (ipv4, ipv6 or dnsbl).
func groupActionValid(action, family string) bool {
	if family == "dnsbl" {
		return action == "Disabled" || action == "unbound"
	}
	return slices.Contains(ipActions, action)
}

type projEntry struct {
	Cadence  string    `json:"cadence"`
	Enabled  bool      `json:"enabled"`
	Override *Schedule `json:"override"`
}

// configHash is the sha256 of PHP's json_encode of the hash projection (entries sorted by id in byte order, and an empty
// list encoded as []). Ids and cadences are [A-Za-z0-9_:], so Marshal's escaping never differs from PHP's.
func configHash(scheduled bool, def Schedule, entries []Entry) string {
	byID := map[string]projEntry{}
	for _, e := range entries {
		byID[e.ID] = projEntry{e.Cadence, e.Enabled, e.Override}
	}
	var shape any = byID
	if len(byID) == 0 {
		shape = []any{}
	}
	b, _ := json.Marshal(struct {
		Scheduled bool     `json:"scheduled"`
		Default   Schedule `json:"default"`
		Entries   any      `json:"entries"`
	}{scheduled, def, shape})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RuntimeModel builds the scheduler's model from the General settings and the ipv4, ipv6 and dnsbl group lists as
// config.xml holds them (values as encoding/json decodes into any; only a []any is a list), plus the Extras, in the order
// the PHP checks run. A rejection's error text is the reason PHP logs.
func RuntimeModel(general, sections map[string]any, extras *Extras) (Model, error) {
	reject := func(format string, args ...any) (Model, error) { return Model{}, fmt.Errorf(format, args...) }
	for _, f := range families {
		if _, ok := sections[f]; !ok {
			return reject("sections: expected exactly the ipv4, ipv6 and dnsbl sections")
		}
	}
	if len(sections) != len(families) {
		return reject("sections: expected exactly the ipv4, ipv6 and dnsbl sections")
	}
	updates, ok := general["pfb_scheduled_feed_updates"].(string)
	if !ok || (updates != "on" && updates != "") {
		return reject("general: pfb_scheduled_feed_updates is neither \"on\" nor empty")
	}
	def, ok := readSchedule(general, "pfb_schedule_")
	if !ok {
		return reject("general: default schedule weekday/hour/minute is out of range")
	}
	var entries []Entry
	seen := map[string]bool{}
	for _, family := range families {
		groups, ok := sections[family].([]any)
		if !ok {
			return reject("%s: section is not a list of groups", family)
		}
		suffix := map[string]string{"ipv4": "_v4", "ipv6": "_v6"}[family]
		for index, raw := range groups {
			group, ok := asArray(raw)
			if !ok {
				return reject("%s group #%d: not an array", family, index)
			}
			label := fmt.Sprintf("%s group #%d", family, index)
			if alias, _ := group["aliasname"].(string); aliasRe.MatchString(alias) {
				label = fmt.Sprintf("%s alias \"%s\"", family, alias)
			}
			rows, hasRows := group["row"]
			if !hasRows {
				rows = []any{}
			}
			action, ok := group["action"].(string)
			if !ok {
				return reject("%s: 'action' is missing or not a string", label)
			}
			cron, ok := group["cron"].(string)
			if _, known := cadenceHours[cron]; !ok || !known {
				return reject("%s: 'cron' is not one of the known cadences", label)
			}
			rowList, ok := rows.([]any)
			if !ok {
				return reject("%s: 'row' is present but is not a list", label)
			}
			if v, has := group["srcint"]; has {
				if _, ok := v.(string); !ok {
					return reject("%s: 'srcint' is not a string", label)
				}
			}
			override := ""
			if v := group["schedule_override"]; v != nil {
				if override, ok = v.(string); !ok || (override != "on" && override != "") {
					return reject("%s: 'schedule_override' is neither \"on\" nor empty", label)
				}
			}
			var overrideSchedule *Schedule
			if override == "on" {
				s, ok := readSchedule(group, "schedule_")
				if !ok {
					return reject("%s: schedule override weekday/hour/minute is out of range", label)
				}
				overrideSchedule = &s
			}
			enabled := updates == "on" && groupActionValid(action, family) && action != "Disabled" && cron != "Never"
			for rowIndex, rawRow := range rowList {
				at := fmt.Sprintf("%s row #%d", label, rowIndex)
				row, ok := asArray(rawRow)
				if !ok {
					return reject("%s: not an array", at)
				}
				if v, has := row["format"]; has {
					if _, ok := v.(string); !ok {
						return reject("%s: 'format' is not a string", at)
					}
				}
				if v, has := row["url"]; has {
					if _, ok := v.(string); !ok {
						return reject("%s: 'url' is not a string", at)
					}
				}
				if url, _ := row["url"].(string); url == "" {
					continue
				}
				if v, has := row["state"]; has {
					state, ok := v.(string)
					if !ok || !slices.Contains([]string{"Enabled", "Flex", "Hold", "Disabled"}, state) {
						return reject("%s: 'state' is not one of Enabled/Flex/Hold/Disabled", at)
					}
					if state == "Disabled" {
						continue
					}
				}
				header, _ := row["header"].(string)
				if !headerRe.MatchString(header) {
					return reject("%s: 'header' is missing or is not [A-Za-z0-9_]", at)
				}
				id := family + ":" + header + suffix
				if seen[id] {
					return reject("%s: duplicate feed id \"%s\"", at, id)
				}
				seen[id] = true
				entries = append(entries, Entry{ID: id, Cadence: cron, Enabled: enabled, Override: overrideSchedule})
			}
		}
	}
	if extras != nil {
		if extras.BL.Cadence != "EveryDay" && extras.BL.Cadence != "Weekly" {
			return reject("extras: 'bl' enabled/cadence is missing or invalid")
		}
		entries = append(entries,
			Entry{ID: extraPrefix + "dcc", Cadence: "EveryDay", Enabled: extras.DCC},
			Entry{ID: extraPrefix + "bl", Cadence: extras.BL.Cadence, Enabled: extras.BL.Enabled})
	}
	scheduled := updates == "on"
	return Model{ConfigHash: configHash(scheduled, def, entries), Scheduled: scheduled, Default: def, Entries: entries}, nil
}

// phpEmpty is PHP's empty() on a decoded value.
func phpEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == "" || x == "0"
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// identityValid is the blacklist identity rule: a token of [A-Za-z0-9,_-] that is not "0".
func identityValid(s string) bool { return s != "0" && identityRe.MatchString(s) }

// BlacklistExtra derives the extra:bl job from the Blacklist section (a decoded config array): enabled when the blacklist is
// on and an item is selected, with a cadence of Weekly only when its frequency is Weekly. The frequency being neither
// EveryDay nor Weekly disables it. A rejection's error text is the reason PHP logs.
func BlacklistExtra(section map[string]any) (BL, error) {
	freq, _ := section["blacklist_freq"].(string) // absent or not a string is never EveryDay or Weekly, like PHP's 'Never'
	v := section["blacklist_selected"]
	selected, isString := v.(string)
	if (v != nil && !isString) || (selected != "" && !identityValid(selected)) {
		return BL{}, errors.New("blacklist: blacklist_selected is not a valid identity list")
	}
	chosen := strings.Split(selected, ",")
	items, isList := section["item"].([]any)
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		xml, xmlOK := item["xml"].(string)
		_, titleOK := item["title"].(string)
		_, feedOK := item["feed"].(string)
		if !xmlOK || xml == "" || strings.Contains(xml, ",") || !identityValid(xml) || !titleOK || !feedOK {
			return BL{}, errors.New("blacklist: an item carries an invalid xml/title/feed field")
		}
	}
	enabled := false
	if enable := section["blacklist_enable"]; !phpEmpty(enable) && enable != "Disable" && isList {
		for _, raw := range items {
			item := raw.(map[string]any)
			if slices.Contains(chosen, item["xml"].(string)) && !phpEmpty(item["selected"]) &&
				item["title"] != "Shallalist" && item["feed"] != "" {
				enabled = true
				break
			}
		}
	}
	bl := BL{Enabled: enabled && (freq == "EveryDay" || freq == "Weekly"), Cadence: "EveryDay"}
	if freq == "Weekly" {
		bl.Cadence = "Weekly"
	}
	return bl, nil
}
