package coreinput

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNoSettings: Core holds no settings yet (an uninitialized Core).
var ErrNoSettings = errors.New("core holds no settings")

// IniFile is the module directory's file SyncSettings keeps the settings in.
const IniFile = "pfb_unbound.ini"

// SyncSettings brings dir's pfb_unbound.ini to the settings/dns and settings/policy/dnsbl Core serves, written in the
// shape pfb_unbound_python_ini() gives (settingsIni), and reports whether the file changed. Settings Core does not hold,
// cannot serve or that do not read whole keep the ini as it is, which is what a start without Core loads.
func SyncSettings(ctx context.Context, c *Client, dir string) (bool, error) {
	resp, err := c.post(ctx, "GetSettings", map[string]any{"projectionIds": []string{"dns", "policy/dnsbl"}})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var reply struct {
		Initialized bool
		Projections []struct {
			ResourceID string `json:"resourceId"`
			Value      map[string]any
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&reply); err != nil {
		return false, fmt.Errorf("GetSettings: %w", err)
	}
	if !reply.Initialized {
		return false, ErrNoSettings
	}
	values := map[string]map[string]any{}
	for _, p := range reply.Projections {
		values[p.ResourceID] = p.Value
	}
	text, err := settingsIni(values["settings/dns"], values["settings/policy/dnsbl"])
	if err != nil {
		return false, fmt.Errorf("GetSettings: %w", err)
	}
	path := filepath.Join(dir, IniFile)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, text) && Owned(path) {
		return false, nil
	}
	if err := writeFile(path, text); err != nil {
		return false, err
	}
	return true, syncDir(dir)
}

// fields reads one projection's values, keeping the first fault.
type fields struct {
	where string
	v     map[string]any
	err   error
}

func (f *fields) fail(name, want string) {
	if f.err == nil {
		f.err = fmt.Errorf("%s.%s is not %s", f.where, name, want)
	}
}

func (f *fields) flag(name string) bool {
	b, ok := f.v[name].(bool)
	if !ok {
		f.fail(name, "a bool")
	}
	return b
}

// text is a string value: one without a line break, which would end the ini line.
func (f *fields) text(name string) string {
	s, ok := f.v[name].(string)
	if !ok || strings.ContainsAny(s, "\r\n") {
		f.fail(name, "a single-line string")
	}
	return s
}

func (f *fields) count(name string) int64 {
	switch n := f.v[name].(type) {
	case int: // a value given in Go, not decoded
		return int64(n)
	case float64:
		if n == float64(int64(n)) {
			return int64(n)
		}
	}
	f.fail(name, "an integer")
	return 0
}

// list is the key of each item of a list value.
func (f *fields) list(name, key string) []string {
	items, ok := f.v[name].([]any)
	if !ok {
		f.fail(name, "a list")
	}
	var out []string
	for _, item := range items {
		m, _ := item.(map[string]any)
		s, ok := m[key].(string)
		if !ok || strings.ContainsAny(s, "\r\n") {
			f.fail(name, "a list of single-line "+key+" items")
		}
		out = append(out, s)
	}
	return out
}

// settingsIni is pfb_unbound.ini as pfb_unbound_python_ini() writes it for these settings, with three departures: no
// creation time, so that the same settings give the same bytes; no forwarding, which is the gateway's --observer; and a %
// in a value configparser interpolates is written %%, so that it reads back as written instead of failing the ini.
// python_enable, python_blocking and python_tld_seg are the constants today's writer gives on a box where pfB-DNS hosts
// DNSBL.
func settingsIni(dns, policy map[string]any) ([]byte, error) {
	if dns == nil || policy == nil {
		return nil, errors.New("the dns or policy/dnsbl projection is missing")
	}
	d, p := &fields{where: "dns", v: dns}, &fields{where: "policy/dnsbl", v: policy}
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	escape := func(s string) string { return strings.ReplaceAll(s, "%", "%%") }
	idnMode := d.text("idnMode")
	storedIdn := idnMode
	if idnMode == "off" {
		storedIdn = ""
	}
	control := d.flag("control")
	var tldList []string
	for _, bucket := range []string{"tldAllowGtld", "tldAllowCctld", "tldAllowItld", "tldAllowBgtld"} {
		tldList = append(tldList, p.list(bucket, "tld")...)
	}
	tldAllow := p.flag("tldAllow") && len(tldList) > 0
	if !tldAllow {
		tldList = nil
	}

	var b strings.Builder
	b.WriteString("; pfBlockerNG DNSBL settings, written by pfB-DNS from Core's settings/dns and settings/policy/dnsbl\n[MAIN]\n")
	for _, kv := range [][2]string{
		{"python_enable", "on"},
		{"metrics_client_ip", onOff(d.flag("metricsClientIp"))},
		{"python_reply", onOff(d.flag("replyLogging"))},
		{"python_blocking", "on"},
		{"python_tld_wildcard", onOff(d.flag("tldWildcard"))},
		{"psl_include_private", onOff(d.flag("pslIncludePrivate"))},
		{"psl_allow_private", onOff(d.flag("pslAllowPrivate"))},
		{"psl_feed_private_policy", escape(d.text("pslFeedPrivatePolicy"))},
		{"psl_feed_icann_policy", escape(d.text("pslFeedIcannPolicy"))},
		{"python_idn", onOff(idnMode == "on")},
		{"idn_mode", escape(storedIdn)},
		{"python_idn_block_malicious", onOff(d.flag("idnBlockMalicious"))},
		{"python_idn_escalate_suspicious", onOff(d.flag("idnEscalateSuspicious"))},
		{"python_tld_seg", "1"},
		{"decisiondb_max", strconv.FormatInt(d.count("decisionCacheMax"), 10)},
		{"tld_allow", onOff(tldAllow)},
		{"tld_allow_list", escape(strings.Join(tldList, ","))},
		{"python_cname", onOff(d.flag("cnameValidation"))},
		{"python_control", onOff(control)},
		{"python_control_legacy", onOff(control && d.flag("controlLegacy"))},
		{"regex_cap", onOff(d.flag("regexCap"))},
	} {
		b.WriteString(kv[0] + "\t= " + kv[1] + "\n")
	}
	// The regex list is read raw: its value is base64, as the DNSBL page stores it.
	if patterns := p.list("regexList", "pattern"); p.flag("regex") && len(patterns) > 0 {
		b.WriteString("regex_list = " + base64.StdEncoding.EncodeToString([]byte(strings.Join(patterns, "\n"))) + "\n")
	}
	// [noAAAA] is read with interpolation, [GP_Bypass_List] raw; a leading dot is the wildcard flag.
	if domains := d.list("noAaaaList", "domain"); d.flag("noAaaa") && len(domains) > 0 {
		b.WriteString("\n[noAAAA]\n")
		for i, domain := range domains {
			flag := "0"
			name, wildcard := strings.CutPrefix(domain, ".")
			if wildcard {
				flag = "1"
			}
			fmt.Fprintf(&b, "%d = %s,%s\n", i, escape(name), flag)
		}
	}
	if cidrs := d.list("groupPolicyBypassList", "cidr"); d.flag("groupPolicy") && len(cidrs) > 0 {
		b.WriteString("\n[GP_Bypass_List]\n")
		for i, cidr := range cidrs {
			fmt.Fprintf(&b, "%d = %s\n", i, cidr)
		}
	}
	if err := cmp.Or(d.err, p.err); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
