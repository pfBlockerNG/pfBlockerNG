package main

import (
	"context"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// pfctl -vvs Tables on pfSense CE: one flags+name line per table, then its statistics.
const tablesSample = `-pa-r--	LAN__NETWORK
	Addresses:   1
	Cleared:     Thu Nov 19 06:40:12 2026
	References:  [ Anchors: 0                  Rules: 4                  ]
	Evaluations: [ NoMatch: 0                  Match: 0                  ]
	In/Block:    [ Packets: 0                  Bytes: 0                  ]
-pa-r--	crowdsec_v4
	Addresses:   3
	Cleared:     Thu Nov 19 06:41:00 2026
	References:  [ Anchors: 0                  Rules: 2                  ]
	Evaluations: [ NoMatch: 12                 Match: 1                  ]
	In/Block:    [ Packets: 1                  Bytes: 60                 ]
--a-r--	virusprot
	Addresses:   0
	Cleared:     Thu Nov 19 06:40:12 2026
`

func TestParseTablesReadsTheCounts(t *testing.T) {
	got := parseTables([]byte(tablesSample))
	want := map[string]int{"LAN__NETWORK": 1, "crowdsec_v4": 3, "virusprot": 0}
	if !maps.Equal(got, want) {
		t.Fatalf("parseTables = %v; want %v", got, want)
	}
}

func TestParseTablesIgnoresAnchorTablesAndJunk(t *testing.T) {
	got := parseTables([]byte("-pa----\tcrowdsec_v4\tsome/anchor\n\tAddresses:   9\nnot a table line\n\n"))
	if len(got) != 0 {
		t.Fatalf("parseTables = %v; want an anchor's table and junk ignored", got)
	}
}

// pfctl -s states (pfSense prints the interface first): IPv4 addr:port, IPv6 addr[port], NAT translations in parentheses, ICMP, portless protocols.
const statesSample = `all tcp 192.168.1.1:22 <- 198.51.100.10:50122       ESTABLISHED:ESTABLISHED
vtnet0 udp 192.168.1.10:5353 -> 203.0.113.5:53       MULTIPLE:SINGLE
vtnet0 tcp 10.0.0.2:5000 (192.0.2.1:6000) -> 198.51.100.77:443       ESTABLISHED:ESTABLISHED
vtnet0 tcp 2001:db8::10[443] <- 2001:db8:dead::1[51515]       ESTABLISHED:ESTABLISHED
vtnet0 icmp 192.168.1.1:31234 -> 192.0.2.53:31234       0:0
vtnet0 gre 192.0.2.200 -> 192.0.2.201       MULTIPLE:MULTIPLE
`

func TestParseStatesCollectsEveryAddress(t *testing.T) {
	got := parseStates([]byte(statesSample))
	var keys []string
	for a := range got {
		keys = append(keys, a.String())
	}
	slices.Sort(keys)
	want := []string{
		"10.0.0.2", "192.0.2.1", "192.0.2.200", "192.0.2.201", "192.0.2.53", "192.168.1.1", "192.168.1.10",
		"198.51.100.10", "198.51.100.77", "2001:db8::10", "2001:db8:dead::1", "203.0.113.5",
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("parseStates = %v; want %v", keys, want)
	}
}

// pfctl -v -s rules: the inbound rule of each table, one per interface when the rule names several, with one label or with
// pfBlockerNG's second, descr= label (#4159).
const rulesSample = `block drop in quick on em0 inet from <crowdsec_v4> to any label "CrowdSec IPv4" ridentifier 1000
  [ Evaluations: 1519      Packets: 16        Bytes: 4096        States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]
block drop in quick on em1 inet from <crowdsec_v4> to any label "CrowdSec IPv4" label "descr=CrowdSec IPv4" ridentifier 177400401
  [ Evaluations: 20        Packets: 4         Bytes: 240         States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]
block drop out quick on em0 inet from any to <crowdsec_v4> label "CrowdSec IPv4 out"
  [ Evaluations: 900       Packets: 99        Bytes: 9900        States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]
block drop in log quick inet6 from <crowdsec_v6> to any label "CrowdSec IPv6" tag CS
  [ Evaluations: 914       Packets: 8         Bytes: 2048        States: 0     ]
  [ Inserted: uid 0 pid 14219 State Creations: 0     ]
block drop in quick inet from <bogons> to any label "Block bogon networks"
  [ Evaluations: 5         Packets: 5         Bytes: 500         States: 0     ]
pass in quick on em0 inet from <crowdsec_v4> to any label "not a block rule"
  [ Evaluations: 5         Packets: 7         Bytes: 700         States: 0     ]
`

func TestParseCountersSumsTheInboundBlockRulesOfEachTable(t *testing.T) {
	got := parseCounters([]byte(rulesSample), []string{"crowdsec_v4", "crowdsec_v6"})
	want := map[string]counter{
		"crowdsec_v4": {Packets: 20, Bytes: 4336},
		"crowdsec_v6": {Packets: 8, Bytes: 2048},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("parseCounters = %v; want %v", got, want)
	}
}

func TestParseCountersReportsNothingForATableWithoutRules(t *testing.T) {
	got := parseCounters([]byte(rulesSample), []string{"crowdsec_other"})
	if len(got) != 0 {
		t.Fatalf("parseCounters = %v; want nothing for a table no rule uses", got)
	}
}

// The address file pfctl reads is mode 0600, holds one address per line, and is gone after the call.
func TestLoadPassesAPrivateAddressFile(t *testing.T) {
	pf := newFakePF()
	dir := t.TempDir()
	p := &pfctl{r: pf, tmpDir: dir}
	if err := p.load(context.Background(), "crowdsec_v4", "add", []string{"198.51.100.10", "203.0.113.0/24"}); err != nil {
		t.Fatalf("load = %v", err)
	}
	calls := pf.takeCalls()
	if len(calls) != 1 {
		t.Fatalf("calls = %v; want one", callStrings(calls))
	}
	c := calls[0]
	if want := []string{"-t", "crowdsec_v4", "-T", "add", "-f", c.file}; !slices.Equal(c.args, want) {
		t.Fatalf("args = %q; want %q", c.args, want)
	}
	if filepath.Dir(c.file) != dir {
		t.Errorf("file %s is not in the daemon's temp directory %s", c.file, dir)
	}
	if c.mode != 0o600 {
		t.Errorf("file mode = %o; want 600", c.mode)
	}
	if c.content != "198.51.100.10\n203.0.113.0/24\n" {
		t.Errorf("file content = %q", c.content)
	}
	if _, err := os.Stat(c.file); !os.IsNotExist(err) {
		t.Errorf("address file %s left behind (stat err %v)", c.file, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("temp directory holds %d leftovers", len(entries))
	}
}

func TestLoadRemovesTheFileWhenPfctlFails(t *testing.T) {
	pf := newFakePF()
	pf.failOn = func([]string) error { return os.ErrPermission }
	dir := t.TempDir()
	p := &pfctl{r: pf, tmpDir: dir}
	if err := p.load(context.Background(), "crowdsec_v4", "add", []string{"198.51.100.10"}); err == nil {
		t.Fatal("load = nil; want pfctl's error")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("temp directory holds %d leftovers after a failed call", len(entries))
	}
}

func TestCreateTableFlushAndKillUseTheDocumentedCommands(t *testing.T) {
	pf := newFakePF()
	p := &pfctl{r: pf, tmpDir: t.TempDir()}
	ctx := context.Background()
	if err := p.createTable(ctx, "crowdsec_v4"); err != nil {
		t.Fatal(err)
	}
	if err := p.flush(ctx, "crowdsec_v4"); err != nil {
		t.Fatal(err)
	}
	if err := p.killStates(ctx, netip.MustParseAddr("198.51.100.10")); err != nil {
		t.Fatal(err)
	}
	if err := p.killStates(ctx, netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-t crowdsec_v4 -T add -f /dev/null",
		"-t crowdsec_v4 -T flush",
		"-k 198.51.100.10",
		"-k 0.0.0.0/0 -k 198.51.100.10",
		"-k 2001:db8::1",
		"-k ::/0 -k 2001:db8::1",
	}
	if got := callStrings(pf.takeCalls()); !slices.Equal(got, want) {
		t.Fatalf("calls = %q; want %q", got, want)
	}
}

// execRunner runs the program with an argument vector (no shell), and an error carries pfctl's stderr.
func TestExecRunnerPassesArgumentsVerbatim(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "args")
	script := filepath.Join(dir, "pfctl")
	body := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + out + "\n" +
		"case \"$1\" in fail) echo 'pfctl: Table does not exist.' >&2; exit 1;; esac\necho stdout-text\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	r := execRunner{path: script, timeout: time.Minute}
	hostile := "a b;$(touch " + filepath.Join(dir, "x") + ")"
	got, err := r.run(context.Background(), "-t", hostile, "-T", "show")
	if err != nil {
		t.Fatalf("run = %v", err)
	}
	if string(got) != "stdout-text\n" {
		t.Errorf("stdout = %q", got)
	}
	args, _ := os.ReadFile(out)
	if string(args) != "-t\n"+hostile+"\n-T\nshow\n" {
		t.Errorf("argv seen by the program = %q", args)
	}
	if _, err := os.Stat(filepath.Join(dir, "x")); err == nil {
		t.Error("an argument was evaluated by a shell")
	}
	_, err = r.run(context.Background(), "fail")
	if err == nil || !strings.Contains(err.Error(), "Table does not exist") {
		t.Fatalf("run(fail) error = %v; want pfctl's stderr in it", err)
	}
}
