package coreinput

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/coretest"
)

// section is the rows of the ini section name in text, "" when it has none: what follows the header up to the next one.
func section(text, name string) string {
	_, rest, ok := strings.Cut(text, "\n["+name+"]\n")
	if !ok {
		return ""
	}
	rows, _, _ := strings.Cut(rest, "\n[")
	return rows
}

// [MAIN] carries what pfb_unbound_python_ini() writes for the same values, but forwarding (the gateway's --observer) and a
// literal % in a value, which today's writer leaves for configparser to interpolate.
func TestSettingsIniMainIsWhatTodaysWriterGives(t *testing.T) {
	dns, policy := coretest.Settings()
	for k, v := range map[string]any{
		"replyLogging": false, "tldWildcard": true, "pslIncludePrivate": false, "pslAllowPrivate": true,
		"pslFeedPrivatePolicy": "apex", "pslFeedIcannPolicy": "ignore", "idnMode": "on", "idnBlockMalicious": false,
		"idnEscalateSuspicious": true, "decisionCacheMax": 0, "cnameValidation": true, "control": true, "controlLegacy": true,
		"regexCap": true, "metricsClientIp": true,
		"noAaaa": true, "noAaaaList": []any{map[string]any{"domain": ".a.example"}, map[string]any{"domain": "b.example"}},
		"groupPolicy": true, "groupPolicyBypassList": []any{map[string]any{"cidr": "10.0.0.0/8"}, map[string]any{"cidr": "192.168.1.5"}},
	} {
		dns[k] = v
	}
	for k, v := range map[string]any{
		"tldAllow": true, "tldAllowGtld": []any{map[string]any{"tld": "com"}, map[string]any{"tld": "net"}},
		"tldAllowBgtld": []any{map[string]any{"tld": "x%y"}},
		"regex":         true, "regexList": []any{map[string]any{"pattern": `^ads\.`}, map[string]any{"pattern": "(track) # why"}},
	} {
		policy[k] = v
	}
	text, err := settingsIni(dns, policy)
	if err != nil {
		t.Fatalf("settingsIni: %v", err)
	}
	want := strings.Join([]string{
		"; pfBlockerNG DNSBL settings, written by pfB-DNS from Core's settings/dns and settings/policy/dnsbl",
		"[MAIN]",
		"python_enable\t= on",
		"metrics_client_ip\t= on",
		"python_reply\t= off",
		"python_tld_wildcard\t= on",
		"psl_include_private\t= off",
		"psl_allow_private\t= on",
		"psl_feed_private_policy\t= apex",
		"psl_feed_icann_policy\t= ignore",
		"idn_mode\t= on",
		"python_idn_block_malicious\t= off",
		"python_idn_escalate_suspicious\t= on",
		"decisiondb_max\t= 0",
		"tld_allow\t= on",
		"tld_allow_list\t= com,net,x%%y",
		"python_cname\t= on",
		"python_control\t= on",
		"python_control_legacy\t= on",
		"regex_cap\t= on",
		"regex_list = " + base64.StdEncoding.EncodeToString([]byte("^ads\\.\n(track) # why")),
		"",
		"[noAAAA]",
		"0 = a.example,1",
		"1 = b.example,0",
		"",
		"[GP_Bypass_List]",
		"0 = 10.0.0.0/8",
		"1 = 192.168.1.5",
		"",
	}, "\n")
	if string(text) != want {
		t.Errorf("ini =\n%s\nwant\n%s", text, want)
	}

	// Off: what the writer gives for the defaults. IDN Off is stored as "", the control legacy needs control, and the
	// sections and the regex list are left out with their switch off, whatever the lists hold.
	dns, policy = coretest.Settings()
	dns["controlLegacy"] = true
	dns["noAaaaList"] = []any{map[string]any{"domain": "a.example"}}
	policy["tldAllowGtld"] = []any{map[string]any{"tld": "com"}}
	policy["regexList"] = []any{map[string]any{"pattern": "x"}}
	text, err = settingsIni(dns, policy)
	if err != nil {
		t.Fatalf("settingsIni: %v", err)
	}
	for _, line := range []string{"idn_mode\t= \n", "python_control_legacy\t= off\n", "tld_allow\t= off\n", "tld_allow_list\t= \n"} {
		if !strings.Contains(string(text), line) {
			t.Errorf("ini lacks %q:\n%s", line, text)
		}
	}
	for _, s := range []string{"regex_list", "[noAAAA]", "forwarding"} {
		if strings.Contains(string(text), s) {
			t.Errorf("ini holds %q:\n%s", s, text)
		}
	}
}

func TestSettingsIniRefusesAValueOfTheWrongShape(t *testing.T) {
	for name, spoil := range map[string]func(dns, policy map[string]any){
		"a missing switch":    func(dns, _ map[string]any) { delete(dns, "control") },
		"a string for a bool": func(dns, _ map[string]any) { dns["tldWildcard"] = "on" },
		"a fraction":          func(dns, _ map[string]any) { dns["decisionCacheMax"] = 1.5 },
		"a list item":         func(_, policy map[string]any) { policy["tldAllowGtld"] = []any{"com"} },
		"a line break": func(dns, _ map[string]any) {
			dns["groupPolicyBypassList"] = []any{map[string]any{"cidr": "10.0.0.1\nx = y"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dns, policy := coretest.Settings()
			spoil(dns, policy)
			if text, err := settingsIni(dns, policy); err == nil {
				t.Errorf("settingsIni = %q, want an error", text)
			}
		})
	}
}

func TestSyncSettingsWritesTheIniWhenTheSettingsChange(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, nil)
	c := New(srv.Socket)
	ini := filepath.Join(dir, "pfb_unbound.ini")

	// An uninitialized Core holds no settings: nothing is written.
	if changed, err := SyncSettings(context.Background(), c, dir); !errors.Is(err, ErrNoSettings) || changed {
		t.Fatalf("SyncSettings = %v, %v; want ErrNoSettings", changed, err)
	}
	if _, err := os.Lstat(ini); !os.IsNotExist(err) {
		t.Fatalf("ini: %v, want none", err)
	}

	dns, policy := coretest.Settings()
	srv.SetSettings(dns, policy)
	if changed, err := SyncSettings(context.Background(), c, dir); err != nil || !changed {
		t.Fatalf("SyncSettings = %v, %v; want a change", changed, err)
	}
	want, _ := settingsIni(dns, policy)
	if got, err := os.ReadFile(ini); err != nil || string(got) != string(want) {
		t.Fatalf("ini = %q, %v; want %q", got, err, want)
	}
	if info, _ := os.Stat(ini); info.Mode().Perm()&0o022 != 0 {
		t.Errorf("ini mode %v: others may write it", info.Mode())
	}
	if !Owned(ini) {
		t.Error("Owned = false for the ini SyncSettings wrote")
	}

	// The same settings at a new revision: no change.
	srv.SetSettings(dns, policy)
	if changed, err := SyncSettings(context.Background(), c, dir); err != nil || changed {
		t.Fatalf("SyncSettings = %v, %v; want no change", changed, err)
	}

	dns["noAaaa"] = true
	dns["noAaaaList"] = []any{map[string]any{"domain": "a.example"}}
	srv.SetSettings(dns, policy)
	if changed, err := SyncSettings(context.Background(), c, dir); err != nil || !changed {
		t.Fatalf("SyncSettings = %v, %v; want a change", changed, err)
	}
	if got, _ := os.ReadFile(ini); section(string(got), "noAAAA") != "0 = a.example,0\n" {
		t.Errorf("ini = %q, want the new noAAAA list", got)
	}

	// Settings that cannot be written, a Core that holds none and a Core that is down keep the ini.
	kept, _ := os.ReadFile(ini)
	delete(dns, "control")
	srv.SetSettings(dns, policy)
	if changed, err := SyncSettings(context.Background(), c, dir); err == nil || changed {
		t.Errorf("SyncSettings = %v, %v; want an error", changed, err)
	}
	srv.SetSettings(nil, nil)
	if changed, err := SyncSettings(context.Background(), c, dir); !errors.Is(err, ErrNoSettings) || changed {
		t.Errorf("SyncSettings = %v, %v; want ErrNoSettings", changed, err)
	}
	if changed, err := SyncSettings(context.Background(), New(filepath.Join(t.TempDir(), "none.sock")), dir); err == nil || changed {
		t.Errorf("SyncSettings = %v, %v; want an error", changed, err)
	}
	if got, _ := os.ReadFile(ini); string(got) != string(kept) {
		t.Errorf("ini = %q, want it kept: %q", got, kept)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %d entries, want the ini alone", len(entries))
	}
}

// An ini that is not pfB-DNS's own is written again, whatever it holds.
func TestSyncSettingsReplacesAnIniThatIsNotItsOwn(t *testing.T) {
	dir := t.TempDir()
	srv := coretest.Start(t, nil)
	dns, policy := coretest.Settings()
	srv.SetSettings(dns, policy)
	ini := filepath.Join(dir, "pfb_unbound.ini")
	want, _ := settingsIni(dns, policy)
	if err := os.WriteFile(ini, want, 0o666); err != nil {
		t.Fatal(err)
	}
	os.Chmod(ini, 0o666)
	if Owned(ini) {
		t.Fatal("Owned = true for a world-writable ini")
	}
	if changed, err := SyncSettings(context.Background(), New(srv.Socket), dir); err != nil || !changed {
		t.Fatalf("SyncSettings = %v, %v; want the ini written again", changed, err)
	}
	if !Owned(ini) {
		t.Error("the ini is still not pfB-DNS's own")
	}
}
