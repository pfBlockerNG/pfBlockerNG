package feedfetch

// The two per-feed formats pfb_download() hands to pfblockerng.sh: ET IQRisk (processet(), a feed whose URL holds
// "iprepdata.txt") and xlsx (processxlsx(), a zip whose lexicographically smallest top-level workbook is used).

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var maxXLSXAddresses = 10_000_000

const xlsxAddressChunk = 1 << 18

var (
	errInvalidETConfiguration = errors.New("invalid ET configuration")
	errTooManyXLSXAddresses   = errors.New("xlsx_too_many_addresses")
)

// etCategories are the ET IQRisk categories by number, named as processet() names the files it splits them into; ""
// is a number ET does not use.
var etCategories = [...]string{1: "ET_Cnc", "ET_Bot", "ET_Spam", "ET_Drop", "ET_Spywarecnc", "ET_Onlinegaming",
	"ET_Drivebysrc", "", "ET_Chatserver", "ET_Tornode", "", "", "ET_Compromised", "", "ET_P2P", "ET_Proxy", "ET_Ipcheck",
	"", "ET_Utility", "ET_DDostarget", "ET_Scanner", "", "ET_Brute", "ET_Fakeav", "ET_Dyndns", "ET_Undesireable",
	"ET_Abusedtld", "ET_Selfsignedssl", "ET_Blackhole", "ET_RAS", "ET_P2Pcnc", "", "ET_Parking", "ET_VPN", "ET_Exesource",
	"", "ET_Mobilecnc", "ET_Mobilespyware", "ET_Skypenode", "ET_Bitcoin", "ET_DDosattack"}

// iqrisk is processet() on the finished ET IQRisk CSV at body ("IP,category,score" rows): each category's addresses
// are split into ETDir (the ET_* files of the former split removed first), the ETMatch categories' written to
// ETMatchFile, and the ETBlock categories', in the order the split lists, staged beside the published copy. An empty
// body has nothing to split and fails, as in processet().
func (f *Fetcher) iqrisk(ctx context.Context, feed Feed, body string) (string, error) {
	if f.ETDir == "" || (len(f.ETMatch) > 0 && f.ETMatchFile == "") {
		return "", errInvalidETConfiguration
	}
	in, err := os.Open(body)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if info, err := in.Stat(); err != nil || info.Size() == 0 {
		return "", errors.New("no ET IQRisk rows")
	}
	old, _ := filepath.Glob(filepath.Join(f.ETDir, "ET_*"))
	for _, p := range old {
		if err := os.RemoveAll(p); err != nil {
			return "", err
		}
	}
	if err := f.etSplit(ctx, in); err != nil {
		return "", err
	}
	// The accumulations read the split back in the order `ls` lists it, each file's last record terminated (awk 1).
	entries, err := os.ReadDir(f.ETDir)
	if err != nil {
		return "", err
	}
	var block, match []string
	for _, e := range entries {
		list := strings.Replace(e.Name(), ".txt", "", 1)
		if slices.Contains(f.ETBlock, list) {
			block = append(block, filepath.Join(f.ETDir, list+".txt"))
		}
		if slices.Contains(f.ETMatch, list) {
			match = append(match, filepath.Join(f.ETDir, list+".txt"))
		}
	}
	if len(f.ETMatch) > 0 {
		staged, err := stageRecords(filepath.Dir(f.ETMatchFile), match)
		if err != nil {
			return "", err
		}
		if err := os.Rename(staged, f.ETMatchFile); err != nil {
			os.Remove(staged)
			return "", err
		}
	}
	return stageRecords(feed.Dir, block)
}

// etSplit is processet()'s `grep ",<n>," | cut -d, -f1` for every category at once: a row names its category between
// commas, and its address is what precedes the first.
func (f *Fetcher) etSplit(ctx context.Context, in io.Reader) error {
	type split struct {
		needle []byte
		f      *os.File
		w      *bufio.Writer
	}
	var splits []split
	defer func() {
		for _, s := range splits {
			s.f.Close()
		}
	}()
	for n, name := range etCategories {
		if name == "" {
			continue
		}
		out, err := os.Create(filepath.Join(f.ETDir, name+".txt"))
		if err != nil {
			return err
		}
		splits = append(splits, split{fmt.Appendf(nil, ",%d,", n), out, bufio.NewWriter(out)})
	}
	r := bufio.NewReaderSize(ctxReader{ctx, in}, 64<<10)
	for long := false; ; {
		line, err := r.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			long = true // shortcut: a row past 64 KiB is no address row and is skipped; grep would read it whole
			continue
		case err != nil && err != io.EOF:
			return err
		case long:
			long = false
		default:
			for _, s := range splits {
				if bytes.Contains(line, s.needle) {
					ip, _, _ := bytes.Cut(line, []byte(","))
					s.w.Write(ip)
					s.w.WriteByte('\n')
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	for _, s := range splits {
		if err := s.w.Flush(); err != nil {
			return err
		}
	}
	for _, s := range splits {
		if err := s.f.Close(); err != nil {
			return err
		}
	}
	splits = nil
	return nil
}

// stageRecords concatenates the files named, each one's last record terminated (awk 1), into a new file staged in dir:
// 0644 and synced, as pfb_stage_publish() leaves it. It returns the file's name.
func stageRecords(dir string, files []string) (string, error) {
	out, err := os.CreateTemp(dir, ".pfbstage_")
	if err != nil {
		return "", err
	}
	w := bufio.NewWriter(out)
	for _, name := range files {
		if err = appendRecords(w, name); err != nil {
			break
		}
	}
	if err == nil {
		err = w.Flush()
	}
	return finishStaged(out, err)
}

func appendRecords(w *bufio.Writer, name string) error {
	src, err := os.Open(name)
	if err != nil {
		return err
	}
	defer src.Close()
	_, err = io.Copy(w, src)
	return err
}

// finishStaged ends a file staged by out after err: 0644, synced and closed, or removed when anything failed.
func finishStaged(out *os.File, err error) (string, error) {
	if cerr := out.Chmod(0o644); err == nil {
		err = cerr
	}
	if cerr := out.Sync(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

// isWorkbookZip tells that the last member of the zip at path names a workbook: pfb_download() looks for ".xlsx" in
// the last line `tar -tf` lists.
func isWorkbookZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	zr, err := openZip(f)
	return err == nil && len(zr.File) > 0 && strings.Contains(zr.File[len(zr.File)-1].Name, ".xlsx")
}

// xlsx is processxlsx() on the zip at raw: the IPv4 addresses (grep -oEw) of the shared strings of its first workbook at
// the top level (the glob *.[xX][lL][sS][xX]), sorted and unique (LC_ALL=C sort -u), staged beside the published copy.
// A workbook without shared strings or without an address in them is refused (#2682), and one past the per-file
// ceiling, under which tar -xf writes it.
func (f *Fetcher) xlsx(ctx context.Context, feed Feed, raw string) (string, error) {
	in, err := os.Open(raw)
	if err != nil {
		return "", err
	}
	defer in.Close()
	zr, err := openZip(in)
	if err != nil {
		return "", err
	}
	var book *zip.File
	for _, zf := range zr.File {
		name := zf.Name
		if !strings.Contains(name, "/") && !strings.HasPrefix(name, ".") && len(name) > len(".xlsx") &&
			strings.EqualFold(name[len(name)-len(".xlsx"):], ".xlsx") && (book == nil || name < book.Name) {
			book = zf
		}
	}
	if book == nil {
		return "", errors.New("no workbook")
	}
	// A workbook is a zip itself: it is read from a copy staged under the ceiling.
	copied, err := os.CreateTemp(feed.Dir, ".pfbstage_")
	if err != nil {
		return "", err
	}
	defer os.Remove(copied.Name())
	defer copied.Close()
	limit := f.extractMax
	if limit <= 0 {
		limit = maxExtract
	}
	rc, err := book.Open()
	if err != nil {
		return "", err
	}
	_, err = io.Copy(&capWriter{w: copied, left: limit}, ctxReader{ctx, rc})
	rc.Close()
	if err != nil {
		return "", err
	}
	wb, err := openZip(copied)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(wb.File, func(zf *zip.File) bool { return zf.Name == "xl/sharedStrings.xml" })
	if i < 0 {
		return "", errors.New("no shared strings")
	}
	src, err := wb.File[i].Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	// shortcut: 10M distinct addresses, when a larger workbook must match PHP's disk-backed sort -u.
	chunkValues := make([]uint32, 0, xlsxAddressChunk)
	chunkWidths := make([]uint8, 0, xlsxAddressChunk)
	var addresses []uint32
	var addressWidths []uint8
	flush := func() error {
		if len(chunkValues) == 0 {
			return nil
		}
		sort.Sort(xlsxAddressSlice{values: chunkValues, widths: chunkWidths})
		n := compactXLSXAddresses(chunkValues, chunkWidths)
		chunkValues, chunkWidths = chunkValues[:n], chunkWidths[:n]
		var err error
		addresses, addressWidths, err = mergeXLSXAddresses(addresses, addressWidths, chunkValues, chunkWidths, maxXLSXAddresses)
		if err != nil {
			return err
		}
		chunkValues, chunkWidths = chunkValues[:0], chunkWidths[:0]
		return nil
	}
	if err := scanIPv4(&capReader{r: ctxReader{ctx, src}, left: limit}, func(value uint32, widths uint8) error {
		chunkValues = append(chunkValues, value)
		chunkWidths = append(chunkWidths, widths)
		if len(chunkValues) == cap(chunkValues) {
			return flush()
		}
		return nil
	}); err != nil {
		return "", err
	}
	if err := flush(); err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		return "", errors.New("no address in the shared strings")
	}
	out, err := os.CreateTemp(feed.Dir, ".pfbstage_")
	if err != nil {
		return "", err
	}
	w := bufio.NewWriter(out)
	var line [15]byte
	for i, address := range addresses {
		if _, err := w.Write(appendXLSXAddress(line[:0], address, addressWidths[i])); err != nil {
			return finishStaged(out, err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return finishStaged(out, err)
		}
	}
	return finishStaged(out, w.Flush())
}

// scanIPv4 is `grep -aoEw` with processxlsx()'s pattern, (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) four times over dots:
// every address standing as a whole word (no letter, digit or underscore on either side), left to right, each after
// the last. A match lies in a run of digits and dots, whose dots cut it into groups: four groups that are octets, the
// first one starting the run or following a dot, the last one ending the run or followed by a dot.
type octetSpelling struct {
	digits [3]byte
	width  uint8
}

type ipv4Group struct {
	value  uint16
	digits uint8
}

// Width codes preserve grep's exact octet spelling while the address values stay in uint32 slices.
type xlsxAddressSlice struct {
	values []uint32
	widths []uint8
}

func (s xlsxAddressSlice) Len() int { return len(s.values) }

func (s xlsxAddressSlice) Less(i, j int) bool {
	return compareXLSXAddress(s.values[i], s.widths[i], s.values[j], s.widths[j]) < 0
}

func (s xlsxAddressSlice) Swap(i, j int) {
	s.values[i], s.values[j] = s.values[j], s.values[i]
	s.widths[i], s.widths[j] = s.widths[j], s.widths[i]
}

var xlsxOctetSpellings = makeXLSXOctetSpellings()

func makeXLSXOctetSpellings() [256][3]octetSpelling {
	var table [256][3]octetSpelling
	for value := range table {
		var digits [3]byte
		text := strconv.AppendUint(digits[:0], uint64(value), 10)
		for width := len(text); width <= 3; width++ {
			spelling := &table[value][width-1]
			spelling.width = uint8(width)
			padding := width - len(text)
			for i := 0; i < padding; i++ {
				spelling.digits[i] = '0'
			}
			copy(spelling.digits[padding:width], text)
		}
	}
	return table
}

func compareXLSXAddress(a uint32, aWidths uint8, b uint32, bWidths uint8) int {
	for group := 0; group < 4; group++ {
		shift := uint(24 - 8*group)
		left := xlsxOctetSpellings[byte(a>>shift)][(aWidths>>uint(2*group))&3]
		right := xlsxOctetSpellings[byte(b>>shift)][(bWidths>>uint(2*group))&3]
		limit := left.width
		if right.width < limit {
			limit = right.width
		}
		for i := uint8(0); i < limit; i++ {
			if left.digits[i] < right.digits[i] {
				return -1
			}
			if left.digits[i] > right.digits[i] {
				return 1
			}
		}
		if left.width < right.width {
			return -1
		}
		if left.width > right.width {
			return 1
		}
	}
	return 0
}

func appendXLSXAddress(dst []byte, value uint32, widths uint8) []byte {
	for group := 0; group < 4; group++ {
		if group > 0 {
			dst = append(dst, '.')
		}
		shift := uint(24 - 8*group)
		spelling := xlsxOctetSpellings[byte(value>>shift)][(widths>>uint(2*group))&3]
		dst = append(dst, spelling.digits[:spelling.width]...)
	}
	return dst
}

func compactXLSXAddresses(values []uint32, widths []uint8) int {
	if len(values) == 0 {
		return 0
	}
	write := 0
	for read := 1; read < len(values); read++ {
		if compareXLSXAddress(values[write], widths[write], values[read], widths[read]) != 0 {
			write++
			values[write], widths[write] = values[read], widths[read]
		}
	}
	return write + 1
}

func mergeXLSXAddresses(values []uint32, widths []uint8, chunkValues []uint32, chunkWidths []uint8, limit int) ([]uint32, []uint8, error) {
	oldLen, total := len(values), len(values)+len(chunkValues)
	if cap(values) < total {
		grown := make([]uint32, oldLen, total)
		copy(grown, values)
		values = grown
	}
	if cap(widths) < total {
		grown := make([]uint8, oldLen, total)
		copy(grown, widths)
		widths = grown
	}
	values, widths = values[:total], widths[:total]
	i, j, k, written := oldLen-1, len(chunkValues)-1, total-1, 0
	for i >= 0 || j >= 0 {
		var value uint32
		var width uint8
		switch {
		case i < 0:
			value, width = chunkValues[j], chunkWidths[j]
			j--
		case j < 0:
			value, width = values[i], widths[i]
			i--
		default:
			switch cmp := compareXLSXAddress(values[i], widths[i], chunkValues[j], chunkWidths[j]); {
			case cmp > 0:
				value, width = values[i], widths[i]
				i--
			case cmp < 0:
				value, width = chunkValues[j], chunkWidths[j]
				j--
			default:
				value, width = values[i], widths[i]
				i--
				j--
			}
		}
		if written >= limit {
			return nil, nil, errTooManyXLSXAddresses
		}
		values[k], widths[k] = value, width
		k--
		written++
	}
	start := k + 1
	copy(values[:written], values[start:total])
	copy(widths[:written], widths[start:total])
	return values[:written], widths[:written], nil
}

func scanIPv4(r io.Reader, found func(uint32, uint8) error) error {
	br := bufio.NewReader(r)
	var groups [4]ipv4Group
	groupCount := 0
	wordBefore := false // a word character precedes the first of groups
	var cur [3]byte
	curLen, long := 0, false
	flush := func(last, wordAfter bool) error {
		group := ipv4Group{value: 256}
		if !long && curLen > 0 {
			value := uint16(0)
			for _, digit := range cur[:curLen] {
				value = value*10 + uint16(digit-'0')
			}
			if curLen < 3 || value <= 255 {
				group = ipv4Group{value: value, digits: uint8(curLen)}
			}
		}
		curLen, long = 0, false
		groups[groupCount] = group
		groupCount++
		if groupCount < 4 {
			return nil
		}
		if !wordBefore && !(last && wordAfter) &&
			groups[0].value < 256 && groups[1].value < 256 && groups[2].value < 256 && groups[3].value < 256 {
			value := uint32(groups[0].value)<<24 | uint32(groups[1].value)<<16 | uint32(groups[2].value)<<8 | uint32(groups[3].value)
			widths := groups[0].digits - 1 |
				(groups[1].digits-1)<<2 |
				(groups[2].digits-1)<<4 |
				(groups[3].digits-1)<<6
			if err := found(value, widths); err != nil {
				return err
			}
			groupCount = 0
		} else {
			copy(groups[:3], groups[1:])
			groupCount = 3
		}
		wordBefore = false // what comes next follows a dot
		return nil
	}
	inRun := false
	prev := byte(0)
	for {
		c, err := br.ReadByte()
		if err == io.EOF {
			if inRun {
				if err := flush(true, false); err != nil {
					return err
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case c >= '0' && c <= '9' || c == '.':
			if !inRun {
				inRun, wordBefore, groupCount = true, word(prev), 0
			}
			if c == '.' {
				if err := flush(false, false); err != nil {
					return err
				}
			} else if curLen == len(cur) {
				long = true
			} else {
				cur[curLen] = c
				curLen++
			}
		case inRun:
			if err := flush(true, word(c)); err != nil {
				return err
			}
			inRun = false
		}
		prev = c
	}
}

func word(c byte) bool { return c == '_' || c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'z' }
