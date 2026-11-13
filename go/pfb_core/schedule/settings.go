package schedule

import (
	"errors"
	"fmt"
	"strconv"
)

// feedStates are the feeds projection's states as the config.xml rows spell them.
var feedStates = map[string]string{"enabled": "Enabled", "disabled": "Disabled", "hold": "Hold", "flex": "Flex"}

// ModelFromSettings builds the scheduler's model from Core's settings instead of config.xml: sched is the value of settings/schedule
// and feeds the values of settings/feeds/ipv4, settings/feeds/ipv6 and settings/feeds/dnsbl (keyed by that projection id), as
// decoded JSON or as the settings store holds them (int64 or int integers). It is RuntimeModel over the same inputs the
// adapter reads them from, and the Blacklist job is BlacklistExtra's rule over the projection: enabled when the updates are on
// and a selected provider has categories, and the frequency is EveryDay or Weekly. Weekly is its cadence only for Weekly. A value
// the settings never serve is an error.
//
// Core's feeds are the ones the adapter projects: a group or feed it leaves out (a name or header the download path refuses) is
// not scheduled, where RuntimeModel over config.xml would still carry it or reject the config.
func ModelFromSettings(sched map[string]any, feeds map[string]map[string]any) (Model, error) {
	updates, ok := sched["scheduledUpdates"].(bool)
	if !ok {
		return Model{}, errors.New("schedule: scheduledUpdates is not a bool")
	}
	general := map[string]any{"pfb_scheduled_feed_updates": ""}
	if updates {
		general["pfb_scheduled_feed_updates"] = "on"
	}
	for key, field := range map[string]string{"pfb_schedule_weekday": "weekday", "pfb_schedule_hour": "hour", "pfb_schedule_minute": "minute"} {
		n, ok := intOf(sched[field])
		if !ok {
			return Model{}, fmt.Errorf("schedule: %s is not a whole number", field)
		}
		general[key] = strconv.Itoa(n)
	}
	overrides, err := overridesOf(sched["groups"])
	if err != nil {
		return Model{}, err
	}
	sections := map[string]any{}
	for _, family := range families {
		groups, err := groupsOf(feeds["feeds/"+family], family, overrides)
		if err != nil {
			return Model{}, err
		}
		sections[family] = groups
	}
	bl, err := blacklistOf(sched)
	if err != nil {
		return Model{}, err
	}
	return RuntimeModel(general, sections, &Extras{DCC: true, BL: bl})
}

func intOf(v any) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case int:
		return n, true
	case float64:
		return int(n), n == float64(int(n))
	}
	return 0, false
}

// overridesOf is the schedule's groups that override the default slot, by id, as the config.xml keys RuntimeModel reads.
func overridesOf(v any) (map[string]map[string]any, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New("schedule: groups is not a list")
	}
	overrides := map[string]map[string]any{}
	for i, raw := range list {
		g, ok := raw.(map[string]any)
		id, idOK := g["id"].(string)
		override, overrideOK := g["override"].(bool)
		if !ok || !idOK || !overrideOK {
			return nil, fmt.Errorf("schedule: groups[%d] is not a group", i)
		}
		if !override {
			continue
		}
		slot := map[string]any{"schedule_override": "on"}
		for key, field := range map[string]string{"schedule_weekday": "weekday", "schedule_hour": "hour", "schedule_minute": "minute"} {
			n, ok := intOf(g[field])
			if !ok {
				return nil, fmt.Errorf("schedule: groups[%d].%s is not a whole number", i, field)
			}
			slot[key] = strconv.Itoa(n)
		}
		overrides[id] = slot
	}
	return overrides, nil
}

// groupsOf is the groups of one feeds projection as RuntimeModel's section: config.xml's keys for what the model reads.
func groupsOf(projection map[string]any, family string, overrides map[string]map[string]any) ([]any, error) {
	list, ok := projection["groups"].([]any)
	if !ok {
		return nil, fmt.Errorf("feeds/%s: groups is not a list", family)
	}
	groups := make([]any, 0, len(list))
	for i, raw := range list {
		g, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("feeds/%s: groups[%d] is not a group", family, i)
		}
		group := map[string]any{"aliasname": g["name"], "action": g["action"], "cron": g["updateFrequency"], "schedule_override": ""}
		if name, ok := g["name"].(string); ok {
			for k, v := range overrides[family+"/"+name] {
				group[k] = v
			}
		}
		feedList, ok := g["feeds"].([]any)
		if !ok {
			return nil, fmt.Errorf("feeds/%s: groups[%d].feeds is not a list", family, i)
		}
		rows := make([]any, 0, len(feedList))
		for j, rawFeed := range feedList {
			f, ok := rawFeed.(map[string]any)
			stateName, _ := f["state"].(string)
			state, known := feedStates[stateName]
			if !ok || !known {
				return nil, fmt.Errorf("feeds/%s: groups[%d].feeds[%d] is not a feed with a known state", family, i, j)
			}
			rows = append(rows, map[string]any{"header": f["header"], "url": f["url"], "state": state})
		}
		group["row"] = rows
		groups = append(groups, group)
	}
	return groups, nil
}

// blacklistOf is the extra:bl job from the schedule projection's Blacklist fields.
func blacklistOf(sched map[string]any) (BL, error) {
	updates, updatesOK := sched["categoryUpdates"].(bool)
	freq, freqOK := sched["categoryFrequency"].(string)
	providers, providersOK := sched["categoryProviders"].([]any)
	if !updatesOK || !freqOK || !providersOK || (freq != "Never" && freq != "EveryDay" && freq != "Weekly") {
		return BL{}, errors.New("schedule: categoryUpdates, categoryFrequency or categoryProviders is not what the settings serve")
	}
	chosen := false
	for i, raw := range providers {
		p, ok := raw.(map[string]any)
		selected, selectedOK := p["selected"].(bool)
		categories, categoriesOK := p["categories"].(string)
		if !ok || !selectedOK || !categoriesOK {
			return BL{}, fmt.Errorf("schedule: categoryProviders[%d] is not a provider", i)
		}
		chosen = chosen || (selected && !phpEmpty(categories))
	}
	bl := BL{Enabled: updates && chosen && (freq == "EveryDay" || freq == "Weekly"), Cadence: "EveryDay"}
	if freq == "Weekly" {
		bl.Cadence = "Weekly"
	}
	return bl, nil
}
