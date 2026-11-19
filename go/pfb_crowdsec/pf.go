package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// runner runs pfctl with an argument vector and returns its stdout.
type runner interface {
	run(ctx context.Context, args ...string) ([]byte, error)
}

// execRunner runs the real program; no shell is involved.
type execRunner struct {
	path    string
	timeout time.Duration
}

func (e execRunner) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// pfctl is the daemon's whole interface to pf.
type pfctl struct {
	r      runner
	tmpDir string // where the address files go; "" is os.TempDir()
}

// createTable creates the table, persistent and empty, when it does not exist; it is a no-op when it does.
func (p *pfctl) createTable(ctx context.Context, table string) error {
	_, err := p.r.run(ctx, "-t", table, "-T", "add", "-f", "/dev/null")
	return err
}

func (p *pfctl) flush(ctx context.Context, table string) error {
	_, err := p.r.run(ctx, "-t", table, "-T", "flush")
	return err
}

// load runs `pfctl -t <table> -T <op> -f <file>` with the addresses in a mode-0600 file that is removed afterwards.
// Every address has been through net/netip.
func (p *pfctl) load(ctx context.Context, table, op string, addrs []string) error {
	f, err := os.CreateTemp(p.tmpDir, "pfb_crowdsec-*.txt")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name) // os.CreateTemp made it mode 0600
	w := bufio.NewWriter(f)
	for _, a := range addrs {
		w.WriteString(a)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = p.r.run(ctx, "-t", table, "-T", op, "-f", name)
	return err
}

// tables returns each table's address count.
func (p *pfctl) tables(ctx context.Context) (map[string]int, error) {
	out, err := p.r.run(ctx, "-vvs", "Tables")
	if err != nil {
		return nil, err
	}
	return parseTables(out), nil
}

// parseTables reads `pfctl -vvs Tables`: a `<flags>\t<name>[\t<anchor>]` line per table, then indented statistics.
// Tables in anchors are ignored. pfctl lists only tables that exist.
func parseTables(out []byte) map[string]int {
	tables := map[string]int{}
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		if line[0] == '\t' || line[0] == ' ' {
			rest, found := strings.CutPrefix(strings.TrimSpace(line), "Addresses:")
			if n, err := strconv.Atoi(strings.TrimSpace(rest)); found && err == nil && current != "" {
				tables[current] = n
			}
			continue
		}
		current = ""
		fields := strings.Split(line, "\t")
		if len(fields) != 2 || len(fields[0]) != 7 || strings.Trim(fields[0], "-cpairhC") != "" || fields[1] == "" {
			continue
		}
		current = fields[1]
		tables[current] = 0
	}
	return tables
}

func (p *pfctl) stateAddrs(ctx context.Context) (map[netip.Addr]bool, error) {
	out, err := p.r.run(ctx, "-s", "states")
	if err != nil {
		return nil, err
	}
	return parseStates(out), nil
}

// parseStates collects every address in `pfctl -s states`: `a.b.c.d:port`, `v6[port]`, portless addresses, and
// NAT translations in parentheses.
func parseStates(out []byte) map[netip.Addr]bool {
	addrs := map[netip.Addr]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i := 2; i < len(fields); i++ {
			if a, ok := stateAddr(strings.Trim(fields[i], "()")); ok {
				addrs[a] = true
			}
		}
	}
	return addrs
}

func stateAddr(s string) (netip.Addr, bool) {
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = s[:i]
	} else if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// killStates kills the states from and to addr, as the official bouncer does.
func (p *pfctl) killStates(ctx context.Context, addr netip.Addr) error {
	everywhere := "0.0.0.0/0"
	if addr.Is6() {
		everywhere = "::/0"
	}
	if _, err := p.r.run(ctx, "-k", addr.String()); err != nil {
		return err
	}
	_, err := p.r.run(ctx, "-k", everywhere, "-k", addr.String())
	return err
}

type counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func (p *pfctl) counters(ctx context.Context, tables []string) (map[string]counter, error) {
	out, err := p.r.run(ctx, "-v", "-s", "rules")
	if err != nil {
		return nil, err
	}
	return parseCounters(out, tables), nil
}

var (
	inboundRule  = regexp.MustCompile(`^block .* from <([^ >]+)> .* label "`)
	ruleCounters = regexp.MustCompile(`Packets:\s*(\d+)\s+Bytes:\s*(\d+)`)
)

// parseCounters sums the packet and byte counters of each table's inbound block rules in `pfctl -v -s rules`
// (pf expands a rule naming several interfaces into one rule per interface).
func parseCounters(out []byte, tables []string) map[string]counter {
	sums := map[string]counter{}
	lines := strings.Split(string(out), "\n")
	for i := 0; i+1 < len(lines); i++ {
		m := inboundRule.FindStringSubmatch(lines[i])
		if m == nil || !slices.Contains(tables, m[1]) {
			continue
		}
		c := ruleCounters.FindStringSubmatch(lines[i+1])
		if c == nil {
			continue
		}
		packets, perr := strconv.ParseUint(c[1], 10, 64)
		octets, berr := strconv.ParseUint(c[2], 10, 64)
		if perr != nil || berr != nil {
			continue
		}
		sum := sums[m[1]]
		sum.Packets += packets
		sum.Bytes += octets
		sums[m[1]] = sum
	}
	return sums
}
