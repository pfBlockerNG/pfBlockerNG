package feedfetch

// The two per-feed formats pfb_download() hands to pfblockerng.sh: ET IQRisk (processet(), a feed whose URL holds
// "iprepdata.txt") and xlsx (processxlsx(), a zip whose last member is a workbook).

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var maxXLSXAddresses = 10_000_000

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
	n, err := io.Copy(w, src)
	last := []byte{'\n'}
	if err == nil && n > 0 {
		_, err = src.ReadAt(last, n-1)
	}
	if err == nil && last[0] != '\n' {
		err = w.WriteByte('\n')
	}
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
	// shortcut: the distinct addresses are held in memory where sort -u spills to disk; spill too if a workbook of
	// millions of them ever appears.
	found := map[string]bool{}
	if err := scanIPv4(ctxReader{ctx, src}, func(ip string) { found[ip] = true }); err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", errors.New("no address in the shared strings")
	}
	out, err := os.CreateTemp(feed.Dir, ".pfbstage_")
	if err != nil {
		return "", err
	}
	w := bufio.NewWriter(out)
	for _, ip := range slices.Sorted(maps.Keys(found)) {
		w.WriteString(ip + "\n")
	}
	return finishStaged(out, w.Flush())
}

// scanIPv4 is `grep -aoEw` with processxlsx()'s pattern, (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) four times over dots:
// every address standing as a whole word (no letter, digit or underscore on either side), left to right, each after
// the last. A match lies in a run of digits and dots, whose dots cut it into groups: four groups that are octets, the
// first one starting the run or following a dot, the last one ending the run or followed by a dot.
func scanIPv4(r io.Reader, found func(string)) error {
	br := bufio.NewReader(r)
	var groups []string // the groups of the run since its start, its last match, or the last three
	wordBefore := false // a word character precedes the first of groups
	cur, long := make([]byte, 0, 3), false
	flush := func(last, wordAfter bool) {
		g := string(cur)
		if long {
			g = "long" // past three digits: no octet
		}
		cur, long = cur[:0], false
		groups = append(groups, g)
		if len(groups) < 4 {
			return
		}
		if !wordBefore && !(last && wordAfter) && octet(groups[0]) && octet(groups[1]) && octet(groups[2]) && octet(groups[3]) {
			found(strings.Join(groups, "."))
			groups = groups[:0]
		} else {
			groups = groups[1:]
		}
		wordBefore = false // what comes next follows a dot
	}
	inRun := false
	prev := byte(0)
	for {
		c, err := br.ReadByte()
		if err == io.EOF {
			if inRun {
				flush(true, false)
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case c >= '0' && c <= '9' || c == '.':
			if !inRun {
				inRun, wordBefore, groups = true, word(prev), groups[:0]
			}
			if c == '.' {
				flush(false, false)
			} else if len(cur) == 3 {
				long = true
			} else {
				cur = append(cur, c)
			}
		case inRun:
			flush(true, word(c))
			inRun = false
		}
		prev = c
	}
}

func word(c byte) bool { return c == '_' || c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'z' }

// octet is (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) as a whole group.
func octet(g string) bool {
	switch len(g) {
	case 1, 2:
		return true
	case 3:
		return g[0] == '0' || g[0] == '1' || g[0] == '2' && (g[1] < '5' || g[1] == '5' && g[2] <= '5')
	}
	return false
}
