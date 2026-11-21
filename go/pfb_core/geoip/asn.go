package geoip

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ASNTable is `pfblockerng.sh asn_table`: IPinfo's asn.csv becomes pfblockerng_asn.txt, the AS choices the IP page's ASN
// field offers, one "AS<number> [ <name> ]" line per AS number.
type ASNTable struct {
	CSV   string    // asn.csv ($pathasncsv)
	Table string    // pfblockerng_asn.txt ($pathasntable)
	Now   time.Time // the Extras log line's time
	Log   io.Writer // the Extras log
}

// Run converts asn.csv when it is a file, and publishes the table whole: false leaves the previous table in place, where
// today's shell truncates it first. It is today's pipeline over every line after the first,
//
//	cut -d ',' -f3-4 | cut -c 3- | sort -nu | tr -d '"' | sed -e 's/,/ [ /g' -e 's/$/ ]/g' -e 's/^/AS/'
//
// read byte by byte, as the C locale reads it: the first two bytes come off, not the first two characters, and a number
// has no thousands separator. The table is a new file of mode 0644 renamed over the path, where the shell's > keeps the
// old file's mode and writes through a symbolic link.
func (a ASNTable) Run(ctx context.Context) bool {
	if info, err := os.Stat(a.CSV); err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(a.CSV)
	if err != nil {
		return false
	}
	defer f.Close()
	first := map[sortNumber][]byte{} // sort -nu keeps the first line of each value, in file order
	r := bufio.NewReader(f)
	for n := 0; ; n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			return false
		}
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return false
		}
		if len(line) == 0 {
			break
		}
		if n > 0 {
			row := asnRow(bytes.TrimSuffix(line, []byte("\n")))
			key := readNumber(row)
			if _, seen := first[key]; !seen { // an empty row is a line like any other
				first[key] = row
			}
		}
	}
	keys := slices.SortedFunc(maps.Keys(first), sortNumber.cmp)
	var out bytes.Buffer
	for _, k := range keys {
		out.WriteString("AS")
		out.Write(bytes.ReplaceAll(bytes.ReplaceAll(first[k], []byte(`"`), nil), []byte(","), []byte(" [ ")))
		out.WriteString(" ]\n")
	}
	if !a.publish(ctx, out.Bytes()) {
		return false
	}
	if a.Log != nil {
		io.WriteString(a.Log, "ASN Lookup Table has been updated [ "+a.Now.Format(time.DateTime)+" ]\n")
	}
	return true
}

// publish writes the table beside the live one and renames it over it.
func (a ASNTable) publish(ctx context.Context, body []byte) bool {
	tmp, err := os.CreateTemp(filepath.Dir(a.Table), "."+filepath.Base(a.Table)+".*")
	if err != nil {
		return false
	}
	_, werr := tmp.Write(body)
	err = errors.Join(werr, tmp.Chmod(0o644), tmp.Sync(), tmp.Close(), ctx.Err())
	if err == nil {
		err = rename(tmp.Name(), a.Table)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return false
	}
	return true
}

// asnRow is `cut -d ',' -f3-4 | cut -c 3-`: a line holding no comma passes whole, one of fewer than three fields is
// empty, and so is a result of two bytes or fewer.
func asnRow(line []byte) []byte {
	if bytes.IndexByte(line, ',') >= 0 {
		fields := bytes.SplitN(line, []byte(","), 5)
		if len(fields) < 3 {
			return nil
		}
		line = bytes.Join(fields[2:min(4, len(fields))], []byte(","))
	}
	if len(line) <= 2 {
		return nil
	}
	return line[2:]
}

// sortNumber is the value `sort -n` reads at the start of a line: blanks, a minus sign, digits, then a point and digits.
// The digits are kept as text, so a value of any length compares exactly; zero is never negative.
type sortNumber struct {
	neg         bool
	whole, frac string // whole without its leading zeros, frac without its trailing ones
}

func readNumber(b []byte) sortNumber {
	digits := func(i int) int {
		for i < len(b) && '0' <= b[i] && b[i] <= '9' {
			i++
		}
		return i
	}
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	var n sortNumber
	if i < len(b) && b[i] == '-' {
		n.neg = true
		i++
	}
	end := digits(i)
	n.whole = strings.TrimLeft(string(b[i:end]), "0")
	if end < len(b) && b[end] == '.' {
		n.frac = strings.TrimRight(string(b[end+1:digits(end+1)]), "0")
	}
	n.neg = n.neg && (n.whole != "" || n.frac != "")
	return n
}

func (x sortNumber) cmp(y sortNumber) int {
	if x.neg != y.neg {
		if x.neg {
			return -1
		}
		return 1
	}
	c := cmp.Or(cmp.Compare(len(x.whole), len(y.whole)), strings.Compare(x.whole, y.whole), strings.Compare(x.frac, y.frac))
	if x.neg {
		return -c
	}
	return c
}
