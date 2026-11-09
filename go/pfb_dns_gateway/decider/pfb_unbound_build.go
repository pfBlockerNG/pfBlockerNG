// Go translation of src/usr/local/pkg/pfblockerng/pfb_unbound.py, the DNSBL build: _load_user_regex_entries
// (1491-1525); _RefusalLog, _dnsbl_compile_regex_rules and _dnsbl_compile_user_regex (5801-5930); build (5933-6306);
// the manifest layer, _dnsbl_path_within_base .. dnsbl_build_from_manifest (6309-6664); dnsbl_emit_count and
// dnsbl_emit_reject_stats (6667-6721).
//
// Python's manifest and config dicts become typed values: the manifest document is validated as the JSON it is
// (dnsblValidateManifestRaws), then read through buildManifest / buildConfig. buildConfig's zero value is not an empty
// Python config dict (psl_wildcard_enabled and psl_include_private default to True there): start from newBuildConfig.
// Python's `isinstance(psl_rules, PslRules)` guard in build() is the type system here.
//
// A Python generator that can raise mid-stream (the feed line readers, the TOP1M sidecar) is an iter.Seq2[string,
// error]: the error is the one a Python consumer would see raised from its for-loop.
package decider

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/regexrules"
)

// ---------------------------------------------------------------------------------------------------------------
// stdlib emulation shared by the readers below

// decodeReplace is bytes.decode("utf-8", errors="replace"): each maximal invalid subpart (the longest prefix of a
// well-formed sequence) becomes one U+FFFD. Go's range-over-string replaces every invalid byte on its own, so a
// truncated three-byte sequence would give two.
func decodeReplace(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var out strings.Builder
	out.Grow(len(data))
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r != utf8.RuneError || size > 1 {
			out.Write(data[:size])
			data = data[size:]
			continue
		}
		out.WriteString("\uFFFD")
		data = data[invalidSubpartLen(data):]
	}
	return out.String()
}

// invalidSubpartLen is the length of the maximal invalid subpart at the start of data, whose first rune is invalid.
func invalidSubpartLen(data []byte) int {
	lo, hi := byte(0x80), byte(0xBF) // range of the second byte
	var need int                     // bytes of the sequence, lead byte included
	switch b := data[0]; {
	case b >= 0xC2 && b <= 0xDF:
		need = 2
	case b == 0xE0:
		need, lo = 3, 0xA0
	case b >= 0xE1 && b <= 0xEC, b == 0xEE, b == 0xEF:
		need = 3
	case b == 0xED:
		need, hi = 3, 0x9F
	case b == 0xF0:
		need, lo = 4, 0x90
	case b >= 0xF1 && b <= 0xF3:
		need = 4
	case b == 0xF4:
		need, hi = 4, 0x8F
	default:
		return 1
	}
	n := 1
	for n < need && n < len(data) {
		if b := data[n]; b < lo || b > hi {
			break
		}
		n++
		lo, hi = 0x80, 0xBF
	}
	return n
}

// pyOSError is str(OSError): "[Errno 2] No such file or directory: 'path'".
// shortcut: the text is Go's errno table with its first letter capitalised, which is libc's strerror for the errnos a
// path can raise; it only shapes the logged and ledger message.
func pyOSError(err error, filename string) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return err.Error()
	}
	text := errno.Error()
	if text != "" {
		text = strings.ToUpper(text[:1]) + text[1:]
	}
	return fmt.Sprintf("[Errno %d] %s: %s", int(errno), text, pysem.Repr(filename))
}

func pyJoin(path, name string) string {
	switch {
	case strings.HasPrefix(name, "/"):
		return name
	case path == "" || strings.HasSuffix(path, "/"):
		return path + name
	}
	return path + "/" + name
}

// pySplit is posixpath.split.
func pySplit(path string) (head, tail string) {
	i := strings.LastIndex(path, "/") + 1
	head, tail = path[:i], path[i:]
	if head != "" && strings.Trim(head, "/") != "" {
		head = strings.TrimRight(head, "/")
	}
	return head, tail
}

// pyRealpath is os.path.realpath(path) (non-strict): symlinks resolve as far as the path exists.
// shortcut: a readlink that fails after lstat saw a symlink (a race) keeps the component as it is, where Python raises
// OSError; normpath is filepath.Clean, which differs only for a leading "//" (POSIX keeps two slashes).
func pyRealpath(path string) string {
	joined, _ := joinRealpath("", path, map[string]*string{})
	if !strings.HasPrefix(joined, "/") {
		cwd, err := os.Getwd()
		if err == nil {
			joined = pyJoin(cwd, joined)
		}
	}
	return filepath.Clean(joined)
}

// joinRealpath is posixpath._joinrealpath; a nil seen value is Python's None (a symlink being resolved).
func joinRealpath(path, rest string, seen map[string]*string) (string, bool) {
	if strings.HasPrefix(rest, "/") {
		rest = rest[1:]
		path = "/"
	}
	for rest != "" {
		name, remaining, _ := strings.Cut(rest, "/")
		rest = remaining
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			if path != "" {
				head, tail := pySplit(path)
				path = head
				if tail == ".." {
					path = pyJoin(pyJoin(path, ".."), "..")
				}
			} else {
				path = ".."
			}
			continue
		}
		newpath := pyJoin(path, name)
		info, err := os.Lstat(newpath)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			path = newpath
			continue
		}
		if resolved, ok := seen[newpath]; ok {
			if resolved != nil {
				path = *resolved
				continue
			}
			return pyJoin(newpath, rest), false
		}
		seen[newpath] = nil
		target, err := os.Readlink(newpath)
		if err != nil {
			path = newpath
			continue
		}
		var ok bool
		path, ok = joinRealpath(path, target, seen)
		if !ok {
			return pyJoin(path, rest), false
		}
		resolved := path
		seen[newpath] = &resolved
	}
	return path, true
}

// pyCommonpath2 is os.path.commonpath([a, b]) for two absolute paths.
func pyCommonpath2(a, b string) string {
	split := func(path string) []string {
		var parts []string
		for _, part := range strings.Split(path, "/") {
			if part != "" && part != "." {
				parts = append(parts, part)
			}
		}
		return parts
	}
	pa, pb := split(a), split(b)
	common := 0
	for common < len(pa) && common < len(pb) && pa[common] == pb[common] {
		common++
	}
	return "/" + strings.Join(pa[:common], "/")
}

// lineSeq is the Python list a caller hands build() as an iterable of lines.
func lineSeq(lines []string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		for _, line := range lines {
			if !yield(line, nil) {
				return
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// _load_user_regex_entries (1491-1525)

// userRegexEntry is one (name, pattern) row of MAIN.regex_list.
type userRegexEntry struct{ name, pattern string }

// b64decodeValidate is base64.b64decode(s, validate=True), which is binascii.a2b_base64(s, strict_mode=True) in Python
// 3.11: the loop below is that function's validation, the decoding of the data characters is the standard library's
// (both ignore trailing bits that are not zero).
func b64decodeValidate(s string) ([]byte, error) {
	if strings.HasPrefix(s, "=") {
		return nil, &valueError{"Leading padding not allowed"}
	}
	var data strings.Builder
	quadPos, pads, paddingStarted, done := 0, 0, false, false
	for i := 0; i < len(s) && !done; i++ {
		c := s[i]
		if c == '=' {
			paddingStarted = true
			if quadPos >= 2 {
				// A pad sequence ends the input: the quad is complete and anything after it is excess.
				if pads++; quadPos+pads >= 4 {
					if i+1 < len(s) {
						return nil, &valueError{"Excess data after padding"}
					}
					done = true
				}
			}
			continue
		}
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return nil, &valueError{"Only base64 data is allowed"}
		}
		if paddingStarted {
			return nil, &valueError{"Discontinuous padding not allowed"}
		}
		pads = 0
		data.WriteByte(c)
		quadPos = (quadPos + 1) % 4
	}
	if !done {
		switch quadPos {
		case 1:
			return nil, &valueError{fmt.Sprintf("Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4", data.Len())}
		case 2, 3:
			return nil, &valueError{"Incorrect padding"}
		}
	}
	return base64.RawStdEncoding.DecodeString(data.String())
}

func loadUserRegexEntries(config *configParser) []userRegexEntry {
	if !config.hasOption("MAIN", "regex_list") {
		return nil
	}
	encoded, _ := config.getRaw("MAIN", "regex_list") // hasOption holds, so the lookup cannot fail
	var text string
	decoded, err := func() ([]byte, error) {
		for i := range len(encoded) {
			if encoded[i] >= utf8.RuneSelf {
				return nil, &valueError{"'ascii' codec can't encode characters: ordinal not in range(128)"}
			}
		}
		raw, err := b64decodeValidate(encoded)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(raw) {
			return nil, &valueError{"'utf-8' codec can't decode bytes: invalid data"}
		}
		return raw, nil
	}()
	if err != nil {
		logErr("[pfBlockerNG]: Failed to decode MAIN.regex_list: " + err.Error())
		return nil
	}
	text = string(decoded)

	var entries []userRegexEntry
	names := map[string]struct{}{}
	rowNumber := 0
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\r' || r == '\n' }) {
		line = pyStrip(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rowNumber++
		pattern, description := regexrules.SplitRegexLine(line)
		pattern = strings.TrimRightFunc(pattern, pysem.IsSpace)
		if pattern == "" {
			continue
		}
		var name string
		if description != nil {
			label, _ := regexrules.SplitRegexLine(*description)
			var word strings.Builder
			for _, r := range strings.ReplaceAll(pyStrip(label), " ", "_") {
				if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
					word.WriteRune(r)
				}
			}
			name = word.String()
		} else {
			name = fmt.Sprintf("Regex_%d", rowNumber)
		}
		name = pysem.Lower(name)
		if _, taken := names[name]; taken {
			name = fmt.Sprintf("%s_%d", name, rowNumber)
		}
		names[name] = struct{}{}
		entries = append(entries, userRegexEntry{name, pattern})
	}
	return entries
}

// ---------------------------------------------------------------------------------------------------------------
// _RefusalLog, _dnsbl_compile_regex_rules, _dnsbl_compile_user_regex (5801-5930)

// refusalLog holds the refusal lines of one regex list: the first REGEX_REFUSAL_LOG_MAX are written, the rest are
// counted into the one summary line summarize writes.
type refusalLog struct{ logged, suppressed int }

func (l *refusalLog) write(line string) {
	if l.logged < REGEX_REFUSAL_LOG_MAX {
		l.logged++
		logErr(line)
	} else {
		l.suppressed++
	}
}

func (l *refusalLog) summarize(kind string) {
	if l.suppressed > 0 {
		logErr(fmt.Sprintf("[pfBlockerNG]: %d more refused %s regex rules not logged", l.suppressed, kind))
	}
}

// compileRegexText is re.compile(compile_text, re.IGNORECASE). The Go and Python engines differ on Unicode \w \s \b
// and on "$" before a trailing newline; regexrules' re2 divergence table records them. It is a variable so a test can
// make compilation fail, as the Python tests monkeypatch re.compile.
var compileRegexText = func(compileText string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + compileText)
}

// dnsblCompileRegexRules compiles one list of irreducible regexRule into the live regex-DB shape and returns it with
// the count of patterns that compiled. A pattern that fails the gate, the opt-in length cap or compilation is logged
// and skipped, never aborting the build.
func dnsblCompileRegexRules(regexRules []regexRule, staticCap bool) (*regexDB, int) {
	db := &regexDB{}
	admitted := 0
	seq := 0
	log := &refusalLog{}
	kind := ""
	for _, rule := range regexRules {
		kind = rule.kind
		_, compileText, refusal := regexrules.Admission(rule.pattern)
		failure := ""
		if compileText == nil {
			failure = fmt.Sprintf("[pfBlockerNG]: dropping %s regex feed [ %s ] pattern [ %s ] (%s)",
				rule.kind, rule.feed, regexrules.Excerpt(rule.pattern), refusal)
		} else if staticCap && len(rule.pattern) > regexrules.REGEX_STATIC_LEN_CAP { // the gate refused non-ASCII text: bytes are characters
			failure = fmt.Sprintf("[pfBlockerNG]: dropping over-length %s regex feed [ %s ] pattern [ %s ] (static length cap)",
				rule.kind, rule.feed, regexrules.Excerpt(rule.pattern))
		} else if compiled, err := compileRegexText(*compileText); err != nil {
			// "error" is the __name__ of Python's re.error.
			failure = fmt.Sprintf("[pfBlockerNG]: ABP regex compile error feed [ %s ] pattern [ %s ]: error %s",
				rule.feed, regexrules.Excerpt(rule.pattern), regexrules.Excerpt(err.Error()))
		} else {
			// Key by feed + a per-build sequence so identical patterns from different feeds (or the same feed) do not
			// collide and each keeps its own warn rate-limit (P7).
			feed := rule.feed
			if feed == "" {
				feed = "DNSBL"
			}
			db.set(fmt.Sprintf("%s#%d", feed, seq), &regexEntry{
				re:          compiled,
				important:   rule.important,
				band:        rule.band,
				groupOwner:  rule.group,
				groupOrigin: "custom",
			})
			seq++
			admitted++
		}
		if failure != "" {
			log.write(failure)
		}
	}
	log.summarize(kind)
	return db, admitted
}

// dnsblCompileUserRegex compiles admin-owned MAIN.regex_list rows into band-5 (user block) regex-DB entries. A row
// that fails the always-on gate, the opt-in length cap (regexCap) or compilation is skipped and logged by excerpt
// with its 1-based row number.
func dnsblCompileUserRegex(entries []userRegexEntry, regexCap bool) *regexDB {
	db := &regexDB{}
	log := &refusalLog{}
	for index, entry := range entries {
		rowCount := index + 1
		_, compileText, refusal := regexrules.Admission(entry.pattern)
		if compileText == nil {
			log.write(fmt.Sprintf("[pfBlockerNG]: dropping user regex [ %s ] pattern [ %s ] on line #%d (%s)",
				entry.name, regexrules.Excerpt(entry.pattern), rowCount, refusal))
			continue
		}
		if regexCap && len(entry.pattern) > regexrules.REGEX_STATIC_LEN_CAP { // the gate refused non-ASCII text: bytes are characters
			log.write(fmt.Sprintf("[pfBlockerNG]: dropping over-length user regex [ %s ] pattern [ %s ] on line #%d (static length cap)",
				entry.name, regexrules.Excerpt(entry.pattern), rowCount))
			continue
		}
		compiled, err := compileRegexText(*compileText)
		if err != nil {
			log.write(fmt.Sprintf("[pfBlockerNG]: Regex [ %s ] compile error pattern [ %s ] on line #%d: error %s",
				entry.name, regexrules.Excerpt(entry.pattern), rowCount, regexrules.Excerpt(err.Error())))
			continue
		}
		// ADR-07: a USER regex is SOVEREIGN -- band 5 (user block), so it beats feed allows and remains user-owned.
		db.set(entry.name, &regexEntry{
			re:          compiled,
			important:   false,
			band:        PRIO_USER_BLOCK,
			groupOwner:  "DNSBL_Regex",
			groupOrigin: "builtin",
		})
	}
	log.summarize("user")
	return db
}

// ---------------------------------------------------------------------------------------------------------------
// build (5933-6306)

// manifestFeed is one row of the manifest's "feeds": the per-feed boundary mapping a raw feed file to its feed,
// group and log flag. mode and provenance are "" when the row leaves them out.
type manifestFeed struct {
	raw, feed, group, logFlag string
	mode, provenance          string
	top1m                     bool // the Group's "TOP1M Whitelist" box (issue #3648); Python reads `row.get("top1m") is True`
}

type buildManifest struct{ feeds []manifestFeed }

// buildConfig is build()'s config dict.
type buildConfig struct {
	pslRules             pslRules // the zero value is Python's PslRules()
	pslWildcardEnabled   bool
	pslIncludePrivate    bool
	pslFeedPrivatePolicy string
	pslFeedIcannPolicy   string
	tldWildcardBlacklist []string
	tldWildcardExclusion []string
	userWhitelist        []string
	userUnlock           []string
	regexCap             bool
	builtinLogFlag       string
}

// newBuildConfig is the config a Python caller gets from `{}`: every config.get default applied.
func newBuildConfig() buildConfig {
	return buildConfig{
		pslWildcardEnabled:   true,
		pslIncludePrivate:    true,
		pslFeedPrivatePolicy: "honor",
		pslFeedIcannPolicy:   "honor",
		builtinLogFlag:       "0",
	}
}

// lineReader yields the raw lines for a feed's `raw` reference, injected so build() stays free of filesystem coupling.
type lineReader func(raw string) iter.Seq2[string, error]

// dnsblTop1mNames is the TOP1M list as validated canonical bare domains; retired comma-framed records and invalid
// domains are rejected by normalise() and not tallied. It also returns the error the line source raised.
func dnsblTop1mNames(lines iter.Seq2[string, error]) (map[string]struct{}, error) {
	names := map[string]struct{}{}
	for line, err := range lines {
		if err != nil {
			return nil, err
		}
		if domain, ok := normalise(line); ok {
			names[domain] = struct{}{}
		}
	}
	return names, nil
}

// build is the pure, reentrant DNSBL build: raw feeds + config -> matcher structure-set. It returns a fresh
// buildResult and mutates no global; it performs no dedup, no subdomain collapse and no build-time whitelist removal.
// The error is what a Python line_reader or top1m_lines raises.
func build(manifest buildManifest, config buildConfig, lineReader lineReader, top1mEnabled bool, top1mLines iter.Seq2[string, error]) (*buildResult, error) {
	// issue #3050: dot-stripped ONCE here; every consumer below reads these as-is.
	blacklistRoots := map[string]struct{}{}
	for _, tld := range config.tldWildcardBlacklist {
		blacklistRoots[strings.Trim(tld, ".")] = struct{}{}
	}
	exclusion := map[string]struct{}{}
	for _, e := range config.tldWildcardExclusion {
		exclusion[strings.Trim(e, ".")] = struct{}{}
	}

	staticCap := config.regexCap

	psl := config.pslRules
	pslClassification := psl
	if !config.pslWildcardEnabled {
		pslClassification = pslRules{}
	}
	// issue #2371: feed-at-suffix policy, keyed off the RAW psl rules (never the wildcard-gated classification
	// rules) -- ABP zones exist independently of Wildcard Blocking (#1255).
	pslFeedPrivatePolicy := config.pslFeedPrivatePolicy
	pslFeedIcannPolicy := config.pslFeedIcannPolicy
	pslFeedPolicyActive := pslFeedPrivatePolicy != "honor" || pslFeedIcannPolicy != "honor"
	suffixPolicy := func(name string) string {
		if policy := dnsblSuffixFeedPolicy(name, psl, pslFeedPrivatePolicy, pslFeedIcannPolicy); policy != nil {
			return *policy
		}
		return ""
	}

	dataDB := map[string]*blockEntry{}
	zoneDB := map[string]*blockEntry{}
	feedGroupIndexDB := map[int]feedGroup{}
	feedGroupDB := map[string]int{}
	nextIndex := 0
	// ADR-48 (issue #789): the per-entry reject tally this build accumulates.
	rejects := rejectTally{}
	var top1m map[string]struct{}
	if top1mEnabled {
		var err error
		if top1m, err = dnsblTop1mNames(top1mLines); err != nil {
			return nil, err
		}
	}
	top1mRows := map[feedGroup]struct{}{}
	if len(top1m) > 0 {
		for _, row := range manifest.feeds {
			if row.top1m {
				top1mRows[feedGroup{row.feed, row.group}] = struct{}{}
			}
		}
	}
	// issue #3648: zone key whose last writer is a TOP1M-filtered row -> the key's last unfiltered payload (nil when
	// it has none); the final loop reads it. A key present with a nil value is Python's None.
	zoneTop1m := map[string]*blockEntry{}

	trackZoneTop1m := func(key string, filtered bool) {
		// Called before zoneDB[key] is (over)written, only while some row is filtered.
		if !filtered {
			delete(zoneTop1m, key)
			return
		}
		prior := zoneDB[key]
		if _, tracked := zoneTop1m[key]; prior != nil && !tracked {
			zoneTop1m[key] = prior
		} else {
			zoneTop1m[key] = zoneTop1m[key]
		}
	}

	indexFor := func(feed, group string) int {
		key := feed + group
		idx, ok := feedGroupDB[key]
		if !ok {
			idx = nextIndex
			feedGroupDB[key] = idx
			feedGroupIndexDB[idx] = feedGroup{feed, group}
			nextIndex++
		}
		return idx
	}

	// Whole-TLD block: a blacklisted TLD becomes a synthetic DNSBL_TLD zone entry carrying the global mechanism flag
	// (issue #3332).
	builtinLogFlag := config.builtinLogFlag
	// Python sorts the roots so a set inserts in a fixed order; a Go map has no insertion order to fix, and every
	// TLD zone takes the one DNSBL_TLD feed/group index.
	for tld := range blacklistRoots {
		if tld == "" {
			continue
		}
		idx := indexFor("DNSBL_TLD", "DNSBL_TLD")
		zoneDB[tld] = &blockEntry{
			log:            builtinLogFlag,
			index:          idx,
			band:           PRIO_FEED_BLOCK,
			groupOwner:     "DNSBL_TLD",
			groupOrigin:    "builtin",
			hasGroupOwner:  true,
			hasGroupOrigin: true,
		}
	}

	// ADR-06 (#51): the temporary per-alert Unlock store loads into whiteDB exactly like the permanent user whitelist
	// -- both are band-6 sovereign user allows. Merge it WITHOUT narrowing an existing permanent allow: widen on
	// collision instead.
	whiteDB := dnsblNormaliseWhitelist(config.userWhitelist, rejects, "user-whitelist")
	for domain, unlockEntry := range dnsblNormaliseWhitelist(config.userUnlock, rejects, "user-unlock") {
		existing, found := whiteDB[domain]
		if !found {
			whiteDB[domain] = unlockEntry
			continue
		}
		whiteDB[domain] = whiteWidenEntry(existing, unlockEntry)
	}

	// ADR-07: an ABP-shaped line is routed by the per-line capture guard to the typed Rule stream (Stage A, parse_abp)
	// and reconciled (Stage B); every other line keeps the ADR-06 lite parse() -> block-only path.
	var abpRules []rule
	// ADR-31 §2.2.3: a permit feed that inserts a band-2 allow must engage the numeric band-aware resolution, so a
	// higher-band block still wins.
	permitAllowInserted := false

	for _, feedRow := range manifest.feeds {
		feed := feedRow.feed
		group := feedRow.group
		logFlag := feedRow.logFlag
		// ADR-31: permit-mode feeds -- every host line is a band-2 wildcard allow.
		if feedRow.mode == "permit" {
			for rawLine, err := range lineReader(feedRow.raw) {
				if err != nil {
					return nil, err
				}
				// Skip ABP/comment control lines -- in a permit feed every plain host is an allow; ABP directives are
				// ignored (v1). The skip set matches the plain-block loop's broadened capture below (ADR-62 delta D4).
				stripped := pyStrip(rawLine)
				if stripped == "" || strings.HasPrefix(stripped, "!") || strings.HasPrefix(stripped, "[") {
					continue
				}
				if dnsblIsAbpRuleLine(stripped) {
					continue
				}
				entry := parseEntry(stripped)
				if entry == nil {
					continue
				}
				domain, bucket := normaliseVerdict(entry.value, false)
				if domain == "" {
					if bucket != "" {
						tallyReject(rejects, feed, group, bucket)
					}
					continue
				}
				// Insert as band-2 wildcard allow (@@||host^ shape) into whiteDB. Monotonic-widen on collision: never
				// downgrade an existing higher band (a user whitelist entry at band 6 must not be narrowed to band 2).
				idx := indexFor(feed, group)
				newEntry := whiteEntry{wildcard: true, important: false, band: PRIO_FEED_ALLOW, hasBand: true, index: idx, hasIndex: true}
				existing, found := whiteDB[domain]
				if !found || whiteEntryBand(existing) < PRIO_FEED_ALLOW {
					whiteDB[domain] = newEntry
					permitAllowInserted = true
				}
				// Same or higher band: keep existing (monotonic widen -- never downgrade).
			}
			continue
		}
		// ADR-07: a DNSBL Group Custom_List (provenance='user') is USER-curated -> SOVEREIGN over feeds: its blocks
		// carry the user-block band (5), which beats any feed allow; only the band-6 whitelist wins. A downloaded feed
		// stays band 1.
		provenance := RULE_PROV_FEED
		if feedRow.provenance == "user" {
			provenance = RULE_PROV_USER
		}
		blockBand := PRIO_FEED_BLOCK
		if provenance == RULE_PROV_USER {
			blockBand = PRIO_USER_BLOCK
		}
		_, top1mRow := top1mRows[feedGroup{feed, group}]
		for rawLine, err := range lineReader(feedRow.raw) {
			if err != nil {
				return nil, err
			}
			// ADR-62/#1083: per-line ABP detection -- a self-identifying ABP entry is invalid in every plain dialect, so
			// route it to the full parse_abp() Stage-A parser -> the abpRules stream (Stage-B reconcile). parse_abp()
			// returns None for anything it itself skips.
			stripped := pyStrip(rawLine)
			if dnsblIsAbpRuleLine(stripped) {
				if r := parseAbp(stripped, provenance, feed, group, logFlag, rejects); r != nil {
					abpRules = append(abpRules, *r)
				}
				continue
			}
			entry := parseEntry(stripped)
			if entry == nil {
				continue
			}
			domain, bucket := normaliseVerdict(entry.value, false)
			if domain == "" {
				if bucket != "" {
					tallyReject(rejects, feed, group, bucket)
				}
				continue
			}
			// Only BLOCK is produced by the lite path (ABP-ready seam; module header).
			if entry.kind != DNSBL_KIND_BLOCK {
				continue
			}
			// issue #2371: FEED entry AT a suffix boundary, judged against the FULL PSL: 'ignore' -> drop (tallied);
			// 'apex' -> any ZONE the classifier yields is demoted back to an exact apex DATA block (tallied).
			policy := ""
			if provenance == RULE_PROV_FEED && pslFeedPolicyActive {
				policy = suffixPolicy(domain)
				if policy == "ignore" {
					tallyReject(rejects, feed, group, "suffix_drop")
					continue
				}
			}
			idx := indexFor(feed, group)
			cls, key := tldWildcardClassify(domain, pslClassification, exclusion, config.pslIncludePrivate, blacklistRoots)
			// Non-ABP block: band 1 (downloaded feed) or 5 (USER Custom_List); never $important (the plain path has no
			// $options grammar).
			payload := &blockEntry{log: logFlag, index: idx, important: false, band: blockBand}
			if cls == DNSBL_CLASS_ZONE && policy == "apex" {
				tallyReject(rejects, feed, group, "suffix_demote")
				if !(top1mRow && top1mListed(domain, top1m)) {
					dataDB[domain] = payload
				}
			} else if cls == DNSBL_CLASS_ZONE {
				if len(top1mRows) > 0 {
					trackZoneTop1m(key, top1mRow)
				}
				zoneDB[key] = payload // last-wins (dict; ADR-06 SS2 attribution change)
			} else if !(top1mRow && top1mListed(key, top1m)) {
				dataDB[key] = payload
			}
		}
	}

	// ---- Stage-B reconcile + Stage-C emit for the ABP rule stream -------------- //
	regexDBOut := &regexDB{}
	allowRegexDB := &regexDB{}
	userRegexDB := &regexDB{}
	userAllowRegexDB := &regexDB{}
	importantRules := permitAllowInserted
	regexCount := 0
	if len(abpRules) > 0 {
		result := reconcile(abpRules, nil, exclusion, rejects)
		importantRules = importantRules || result.importantRules

		// Domain blocks -> dataDB/zoneDB (carry band + $important). issue #2371: a FEED rule AT a suffix boundary is
		// dropped ('ignore') or demoted from ZONE to DATA at the SAME key ('apex', band/important/log preserved).
		for _, b := range result.blockDomains {
			cls := b.cls
			if b.provenance == RULE_PROV_FEED && pslFeedPolicyActive {
				policy := suffixPolicy(b.key)
				if policy == "ignore" {
					tallyReject(rejects, orDefault(b.feed, "DNSBL"), orDefault(b.group, "DNSBL"), "suffix_drop")
					continue
				}
				if policy == "apex" && cls == DNSBL_CLASS_ZONE {
					tallyReject(rejects, orDefault(b.feed, "DNSBL"), orDefault(b.group, "DNSBL"), "suffix_demote")
					cls = DNSBL_CLASS_DATA
				}
			}
			idx := indexFor(orDefault(b.feed, "DNSBL"), orDefault(b.group, "DNSBL"))
			// issue #3539: an unset ABP log is Null Blocking ("0"), never VIP.
			payload := &blockEntry{log: orDefault(b.log, "0"), index: idx, important: b.important, band: b.band}
			_, top1mRow := top1mRows[feedGroup{b.feed, b.group}]
			if cls == DNSBL_CLASS_ZONE {
				if len(top1mRows) > 0 {
					trackZoneTop1m(b.key, top1mRow)
				}
				zoneDB[b.key] = payload
			} else if !(top1mRow && top1mListed(b.key, top1m)) {
				dataDB[b.key] = payload
			}
		}

		// Domain allows (@@||domain^ and reduced @@/re/) -> whiteDB. A user whitelist entry (band 6) must never be
		// downgraded by a feed allow on the SAME key, so only widen when the key is absent or the existing band is lower.
		for _, a := range result.allowDomains {
			existing, found := whiteDB[a.domain]
			if !found || whiteEntryBand(existing) < a.band {
				whiteDB[a.domain] = whiteEntry{wildcard: a.wildcard, important: a.important, band: a.band, hasBand: true}
				continue
			}
			// Same key, SAME band: a key can carry both an exact (reduced @@/^d$/) and a wildcard (@@||d^) allow. The
			// suffix-walk only honours wildcard entries, so first-writer-wins would silently drop subdomain coverage.
			// Merge monotonically (widen) -- keep the strongest of each field.
			if whiteEntryBand(existing) == a.band {
				whiteDB[a.domain] = whiteEntry{
					wildcard:  whiteEntryWildcard(existing) || a.wildcard,
					important: whiteEntryImportant(existing) || a.important,
					band:      a.band,
					hasBand:   true,
				}
			}
		}

		// Irreducible regex -> regexDB (feed block) / allowRegexDB (feed allow) and, for a user Custom_List row,
		// userRegexDB / userAllowRegexDB. Compile here; a broken pattern is logged + skipped.
		var feedBlock, userBlock, feedAllow, userAllow []regexRule
		for _, r := range result.blockRegexIrreducible {
			if r.provenance == RULE_PROV_USER {
				userBlock = append(userBlock, r)
			} else {
				feedBlock = append(feedBlock, r)
			}
		}
		for _, r := range result.allowRegexIrreducible {
			if r.provenance == RULE_PROV_USER {
				userAllow = append(userAllow, r)
			} else {
				feedAllow = append(feedAllow, r)
			}
		}
		var feedBlockAdmitted, feedAllowAdmitted, userBlockAdmitted, userAllowAdmitted int
		regexDBOut, feedBlockAdmitted = dnsblCompileRegexRules(feedBlock, staticCap)
		allowRegexDB, feedAllowAdmitted = dnsblCompileRegexRules(feedAllow, staticCap)
		userRegexDB, userBlockAdmitted = dnsblCompileRegexRules(userBlock, staticCap)
		userAllowRegexDB, userAllowAdmitted = dnsblCompileRegexRules(userAllow, staticCap)
		regexCount = feedBlockAdmitted + feedAllowAdmitted + userBlockAdmitted + userAllowAdmitted
		// A loaded user regex needs the numeric precedence path: the fast path never reads the allow-regex lists, so a
		// user `@@/re/` could not override a plain feed block there.
		importantRules = importantRules || userRegexDB.len() > 0 || userAllowRegexDB.len() > 0
	}

	for key, fallback := range zoneTop1m {
		// Every filtered zone shares one immutable name set, retained by the snapshot.
		zoneDB[key].top1m = top1m
		zoneDB[key].hasTop1m = true
		if fallback != nil {
			zoneDB[key].top1mFallback = fallback
		}
	}

	result := newBuildResult()
	result.dataDB = dataDB
	result.zoneDB = zoneDB
	result.feedGroupIndexDB = feedGroupIndexDB
	result.whiteDB = whiteDB
	result.counts = len(dataDB) + len(zoneDB)
	result.regexDB = regexDBOut
	result.allowRegexDB = allowRegexDB
	result.userRegexDB = userRegexDB
	result.userAllowRegexDB = userAllowRegexDB
	result.importantRules = importantRules
	result.regexCount = regexCount
	result.rejects = rejects
	result.pslRules = psl
	result.builtinLogFlag = builtinLogFlag
	return result, nil
}

// orDefault is Python's `value or default` for a str.
func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// ---------------------------------------------------------------------------------------------------------------
// the manifest (6309-6664)

// dnsblPathWithinBase reports whether the resolved real path of path is inside baseDir. The manifest is published
// next to its raw feeds, so every `raw` file a row references must resolve under the manifest's own directory; links
// are resolved so one inside baseDir cannot point outside it.
func dnsblPathWithinBase(path, baseDir string) bool {
	realBase := pyRealpath(baseDir)
	realPath := pyRealpath(path)
	return pyCommonpath2(realBase, realPath) == realBase
}

// dnsblGenerationError is _DnsblGenerationError: a manifest generation member is invalid or unreadable.
type dnsblGenerationError struct{ msg string }

func (e *dnsblGenerationError) Error() string { return e.msg }

func generationErrorf(format string, args ...any) error {
	return &dnsblGenerationError{fmt.Sprintf(format, args...)}
}

func isStringList(value any) bool {
	list, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

// dnsblValidateManifestRaws checks the manifest/v1 contract of a decoded JSON document, then that every raw member is
// a regular file under baseDir. Every shape is checked before any file is touched.
func dnsblValidateManifestRaws(manifest any, baseDir string) error {
	root, ok := manifest.(map[string]any)
	if !ok {
		return generationErrorf("DNSBL manifest/v1 root must be an object")
	}
	// type(version) is int and version == 1: a float spells itself with a fraction or exponent, so only "1" passes.
	if version, ok := root["version"].(json.Number); !ok || version.String() != "1" {
		return generationErrorf("DNSBL manifest/v1 version must be integer 1")
	}

	config, ok := root["config"].(map[string]any)
	if !ok {
		return generationErrorf("DNSBL manifest/v1 config must be an object")
	}
	// issue #1841: top1m_list is RETIRED (#1542 moved TOP1M to the sidecar) but a box upgraded across that retirement
	// still has a manifest carrying it until the next full update rewrites one: tolerated, and read as the TOP1M source
	// of its own vintage (dnsblBuildFromManifest) -- shape still checked.
	for _, field := range []string{"tld_wildcard_blacklist", "tld_wildcard_exclusion", "user_whitelist", "user_unlock", "top1m_list"} {
		if value, present := config[field]; present && !isStringList(value) {
			return generationErrorf("DNSBL manifest/v1 config.%s must be list[str]", field)
		}
	}
	for _, field := range []string{"top1m_enabled", "regex_cap"} {
		if value, present := config[field]; present {
			if _, ok := value.(bool); !ok {
				return generationErrorf("DNSBL manifest/v1 config.%s must be bool", field)
			}
		}
	}
	// issue #3291: the effective global DNSBL mechanism's logging flag for built-in blocks; issue #3539: absent -> "0".
	if value, present := config["builtin_log_flag"]; present {
		flag, ok := value.(string)
		if !ok || !slices.Contains([]string{"0", "1", "2", "3", "4", "5", "6"}, flag) {
			return generationErrorf(`DNSBL manifest/v1 config.builtin_log_flag must be one of "0".."6"`)
		}
	}

	feeds, ok := root["feeds"].([]any)
	if !ok {
		return generationErrorf("DNSBL manifest/v1 feeds must be a list")
	}
	for index, item := range feeds {
		prefix := fmt.Sprintf("DNSBL manifest/v1 feeds[%d]", index)
		feed, ok := item.(map[string]any)
		if !ok {
			return generationErrorf("%s must be an object", prefix)
		}
		for _, field := range []string{"raw", "feed", "group", "log_flag"} {
			if _, ok := feed[field].(string); !ok {
				return generationErrorf("%s.%s must be a string", prefix, field)
			}
		}
		for _, field := range []string{"raw", "feed"} {
			if feed[field].(string) == "" {
				return generationErrorf("%s.%s must be a non-empty string", prefix, field)
			}
		}
		if value, present := feed["provenance"]; present {
			if provenance, ok := value.(string); !ok || provenance != "feed" && provenance != "user" {
				return generationErrorf("%s.provenance must be feed or user", prefix)
			}
		}
		if value, present := feed["mode"]; present {
			if mode, ok := value.(string); !ok || mode != "deny" && mode != "permit" {
				return generationErrorf("%s.mode must be deny or permit", prefix)
			}
		}
		// issue #3648: the Group's "TOP1M Whitelist" box; absent means the box is cleared.
		if value, present := feed["top1m"]; present {
			if _, ok := value.(bool); !ok {
				return generationErrorf("%s.top1m must be bool", prefix)
			}
		}
	}

	for index, item := range feeds {
		raw := item.(map[string]any)["raw"].(string)
		path := raw
		if !strings.HasPrefix(raw, "/") {
			path = pyJoin(baseDir, raw)
		}
		if !dnsblPathWithinBase(path, baseDir) {
			return generationErrorf("DNSBL manifest/v1 feeds[%d].raw resolves outside manifest base: '%s'", index, path)
		}
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			return generationErrorf("DNSBL manifest/v1 feeds[%d].raw is missing or not a regular file: '%s'", index, path)
		}
	}
	return nil
}

// dnsblFileLineReader is a file-backed lineReader for build(): it maps a feed row's raw reference to its raw lines,
// streamed lazily so peak RAM stays at the dict floor. raw may be an absolute path or a name relative to baseDir (the
// directory holding the manifest). LF is the only record delimiter and actual CR characters are removed from yielded
// lines. failClosed turns any path/open/read failure into a generation error for dnsblBuildFromManifest; direct
// diagnostic readers retain the historical log-and-yield-nothing behavior.
func dnsblFileLineReader(baseDir string, failClosed bool) lineReader {
	return func(raw string) iter.Seq2[string, error] {
		return func(yield func(string, error) bool) {
			fail := func(message string) {
				logErr("[pfBlockerNG]: " + message)
				if failClosed {
					yield("", &dnsblGenerationError{message})
				}
			}
			path := raw
			if !strings.HasPrefix(raw, "/") {
				path = pyJoin(baseDir, raw)
			}
			if !dnsblPathWithinBase(path, baseDir) {
				fail(fmt.Sprintf("Refusing DNSBL feed outside base dir: '%s'", path))
				return
			}
			fh, err := os.Open(path)
			if err == nil {
				if info, statErr := fh.Stat(); statErr == nil && info.IsDir() {
					fh.Close()
					err = syscall.EISDIR
				}
			}
			if err != nil {
				var pathErr *os.PathError
				if errors.As(err, &pathErr) {
					err = pathErr.Err
				}
				fail(fmt.Sprintf("Failed to read DNSBL feed '%s': %s", path, pyOSError(err, path)))
				return
			}
			defer fh.Close()
			reader := bufio.NewReader(fh)
			for {
				chunk, readErr := reader.ReadBytes('\n')
				if len(chunk) > 0 {
					line := strings.ReplaceAll(decodeReplace(chunk), "\r", "")
					if !yield(strings.TrimSuffix(line, "\n"), nil) {
						return
					}
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					var pathErr *os.PathError
					if errors.As(readErr, &pathErr) {
						readErr = pathErr.Err
					}
					fail(fmt.Sprintf("Failed while reading DNSBL feed '%s': %s", path, pyOSError(readErr, path)))
					return
				}
			}
		}
	}
}

// dnsblFixedTop1mLines streams the fixed TOP1M sidecar; any source failure aborts the build.
func dnsblFixedTop1mLines(baseDir string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		path := pyJoin(baseDir, "pfb_py_top1m.txt")
		fail := func(format string, args ...any) { yield("", generationErrorf(format, args...)) }
		if sidecarOpenFlags == 0 {
			fail("TOP1M sidecar cannot be opened without symlink protection: '%s'", path)
			return
		}
		pathStat, err := os.Lstat(path)
		if err != nil {
			fail("TOP1M sidecar unavailable: '%s'", path)
			return
		}
		if !pathStat.Mode().IsRegular() {
			fail("TOP1M sidecar is not a regular file: '%s'", path)
			return
		}
		handle, err := os.OpenFile(path, os.O_RDONLY|sidecarOpenFlags, 0)
		if err != nil {
			fail("TOP1M sidecar unavailable: '%s'", path)
			return
		}
		defer handle.Close()
		readFailed := func() { fail("TOP1M sidecar read failed: '%s'", path) }

		opened, err := handle.Stat()
		if err != nil {
			readFailed()
			return
		}
		if !opened.Mode().IsRegular() {
			fail("TOP1M sidecar is not a regular file: '%s'", path)
			return
		}
		if !sameFileState(pathStat, opened) {
			fail("TOP1M sidecar changed before reading: '%s'", path)
			return
		}
		expectedDigest := md5.New()
		if _, err := io.Copy(expectedDigest, handle); err != nil {
			readFailed()
			return
		}
		if _, err := handle.Seek(0, io.SeekStart); err != nil {
			readFailed()
			return
		}
		consumedDigest := md5.New()
		reader := bufio.NewReader(handle)
		for {
			rawLine, readErr := reader.ReadBytes('\n')
			if len(rawLine) > 0 {
				consumedDigest.Write(rawLine)
				if !utf8.Valid(rawLine) { // strict decode
					readFailed()
					return
				}
				if !yield(pyStrip(string(rawLine)), nil) {
					return
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				readFailed()
				return
			}
		}
		consumed, err := handle.Seek(0, io.SeekCurrent)
		if err != nil {
			readFailed()
			return
		}
		finished, err := handle.Stat()
		if err != nil {
			readFailed()
			return
		}
		finalDigest := md5.New()
		if _, err := handle.Seek(0, io.SeekStart); err != nil {
			readFailed()
			return
		}
		if _, err := io.Copy(finalDigest, handle); err != nil {
			readFailed()
			return
		}
		pathname, err := os.Lstat(path)
		if err != nil {
			readFailed()
			return
		}
		openedCtime, openedNlink := statCtimeNlink(opened)
		finishedCtime, finishedNlink := statCtimeNlink(finished)
		pathnameRegular := pathname.Mode().IsRegular()
		pathnameSame := pathnameRegular && os.SameFile(pathname, opened)
		pathnameReplaced := pathnameRegular && !pathnameSame && finishedNlink < openedNlink
		fdMetadataChanged := finishedCtime != openedCtime || finishedNlink != openedNlink
		if consumed != finished.Size() ||
			!sameFileState(opened, finished) ||
			!bytes.Equal(consumedDigest.Sum(nil), expectedDigest.Sum(nil)) ||
			!bytes.Equal(finalDigest.Sum(nil), expectedDigest.Sum(nil)) ||
			!(pathnameSame || pathnameReplaced) ||
			(fdMetadataChanged && !pathnameReplaced) {
			fail("TOP1M sidecar changed while reading: '%s'", path)
		}
	}
}

// sameFileState is Python's (st_dev, st_ino, st_mode, st_size, st_mtime_ns) equality.
func sameFileState(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().UnixNano() == b.ModTime().UnixNano()
}

// stringList is `list(value)` of a validated list[str]; a missing key is an empty list.
func stringList(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, item.(string))
	}
	return out
}

// dnsblConfigFromManifest shapes the manifest's config block into the build() config.
//
// The public-suffix oracle is not part of the manifest: a shipped dnsbl_psl file (pfb["pfb_py_psl"]) gated by
// python_tld_wildcard or TLD-Allow, mirroring the HSTS file. A manifest config.tld_master key (a stale pre-#1255 shape)
// is ignored entirely. issue #2371 adds a THIRD gate: either psl_feed_private_policy or psl_feed_icann_policy != "honor"
// also requires the authority. With any gate ON, a missing/corrupt authority is an error (fail-closed, no silent empty
// rule set); with all OFF it is never opened. The manifest is already validated; baseDir is unused, as in Python.
func (m *pfbUnbound) dnsblConfigFromManifest(manifest map[string]any, _ string) (buildConfig, error) {
	config, _ := manifest["config"].(map[string]any)

	privatePolicy := m.pfb.pslFeedPrivatePolicy
	icannPolicy := m.pfb.pslFeedIcannPolicy
	rules, err := loadPslAuthority(m.pfb.pfbPyPsl, m.pfb.pythonTldWildcard || m.pfb.tldAllow || privatePolicy != "honor" || icannPolicy != "honor")
	if err != nil {
		return buildConfig{}, err
	}

	// ADR-07: the static-cap flag reaches build() via the ini-derived pfb setting (the cap setting lives in
	// pfb_unbound.ini MAIN, not the manifest); a manifest config.regex_cap (if present) takes precedence.
	regexCap := m.pfb.regexCap
	if value, ok := config["regex_cap"].(bool); ok {
		regexCap = value
	}
	builtinLogFlag := "0"
	if value, ok := config["builtin_log_flag"].(string); ok {
		builtinLogFlag = value
	}

	return buildConfig{
		pslRules:             rules,
		pslWildcardEnabled:   m.pfb.pythonTldWildcard,
		pslIncludePrivate:    m.pfb.pslIncludePrivate,
		pslFeedPrivatePolicy: privatePolicy,
		pslFeedIcannPolicy:   icannPolicy,
		tldWildcardBlacklist: stringList(config["tld_wildcard_blacklist"]),
		tldWildcardExclusion: stringList(config["tld_wildcard_exclusion"]),
		userWhitelist:        stringList(config["user_whitelist"]),
		// ADR-06 (#51): the temporary per-alert unlock set -> band-6 whiteDB allows.
		userUnlock:     stringList(config["user_unlock"]),
		regexCap:       regexCap,
		builtinLogFlag: builtinLogFlag,
	}, nil
}

// manifestFromDocument reads a validated manifest document's feeds.
func manifestFromDocument(document map[string]any) buildManifest {
	var manifest buildManifest
	feeds, _ := document["feeds"].([]any)
	for _, item := range feeds {
		row := item.(map[string]any)
		str := func(field string) string { value, _ := row[field].(string); return value }
		top1m, _ := row["top1m"].(bool)
		manifest.feeds = append(manifest.feeds, manifestFeed{
			raw: str("raw"), feed: str("feed"), group: str("group"), logFlag: str("log_flag"),
			mode: str("mode"), provenance: str("provenance"), top1m: top1m,
		})
	}
	return manifest
}

// parseManifestJSON is json.load of a UTF-8 text file: the whole text is one JSON value, numbers keep their int /
// float spelling (decoded as json.Number), and a file that is not UTF-8 is an error rather than silently repaired.
// shortcut: Python also accepts the NaN / Infinity / -Infinity literals and lone-surrogate escapes, and raises
// RecursionError (not caught) past about 1000 nested levels; here they are decode errors. PHP's json_encode writes none
// of them, so an unknown key carrying one never reaches a manifest; the error text is Go's, not json's.
func parseManifestJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, &valueError{"'utf-8' codec can't decode the manifest: invalid data"}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &valueError{"Extra data"}
	}
	return document, nil
}

// dnsblBuildFromManifest reads the per-feed manifest JSON and BUILDS the DNSBL structure-set from raw. This is the
// ADR-06 init swap point: a pure (manifest+raw) -> buildResult step that a zero-downtime reload runs off to the side
// and swaps in. The manifest carries `feeds` (one row per raw feed file) and a `config` block; top1m_enabled is taken
// from config["top1m_enabled"]. It returns nil when the manifest is absent or cannot be built -- ADR-65: the caller
// then leaves dataDB/zoneDB/whiteDB EMPTY (no fallback); the open ledger entry is the signal.
func (m *pfbUnbound) dnsblBuildFromManifest(manifestPath string) *buildResult {
	if info, err := os.Stat(manifestPath); err != nil || !info.Mode().IsRegular() {
		// ADR-65: fail LOUD, never stale-serve -- open (never close-only) so the missing manifest surfaces via the
		// ledger instead of silently doing nothing.
		m.pfbPyStatusOpen("dnsbl", manifestPath, "parse", "DNSBL manifest absent: "+manifestPath+" -- DNSBL not loaded")
		return nil
	}

	data, err := os.ReadFile(manifestPath)
	var document any
	if err == nil {
		document, err = parseManifestJSON(data)
	}
	if err != nil {
		message := err.Error()
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			message = pyOSError(pathErr.Err, manifestPath)
		}
		logErr(fmt.Sprintf("[pfBlockerNG]: Failed to load DNSBL manifest '%s': %s", manifestPath, message))
		m.pfbPyStatusOpen("dnsbl", manifestPath, "parse", fmt.Sprintf("Failed to load DNSBL manifest '%s': %s", manifestPath, message))
		return nil
	}

	result, err := m.buildFromManifestDocument(manifestPath, document)
	if err != nil {
		logErr("[pfBlockerNG]: Failed to build DNSBL structures from raw: " + err.Error())
		m.pfbPyStatusOpen("dnsbl", manifestPath, "parse", "Failed to build DNSBL structures from raw: "+err.Error())
		return nil
	}

	m.pfbPyStatusClose("dnsbl", manifestPath, "parse")
	return result
}

// buildFromManifestDocument is the try-block of dnsbl_build_from_manifest: any error is one Python raises there.
func (m *pfbUnbound) buildFromManifestDocument(manifestPath string, document any) (*buildResult, error) {
	root, ok := document.(map[string]any)
	if !ok {
		return nil, generationErrorf("DNSBL manifest/v1 root must be an object")
	}
	absolute, err := filepath.Abs(manifestPath)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(absolute)
	if err := dnsblValidateManifestRaws(root, baseDir); err != nil {
		return nil, err
	}
	manifestConfig := root["config"].(map[string]any)
	config, err := m.dnsblConfigFromManifest(root, baseDir)
	if err != nil {
		return nil, err
	}
	top1mEnabled, _ := manifestConfig["top1m_enabled"].(bool)
	// issue #1841: a manifest still carrying the retired inline TOP1M list predates the sidecar (#1542), which
	// therefore does not exist on that box yet -- read the list the manifest itself ships so an upgrade keeps the DNSBL
	// it had, and warn so the retirement stays visible until the next full update rewrites the manifest.
	legacyTop1m, hasLegacyTop1m := manifestConfig["top1m_list"]
	if hasLegacyTop1m {
		action := "ignoring it (TOP1M is disabled)"
		if top1mEnabled {
			action = "reading TOP1M from it"
		}
		logErr(fmt.Sprintf("[pfBlockerNG]: DNSBL manifest '%s' still carries the retired config.top1m_list -- %s until the next full update rewrites the manifest",
			manifestPath, action))
	}
	var top1mLines iter.Seq2[string, error]
	switch {
	case !top1mEnabled:
		top1mLines = lineSeq(nil)
	case hasLegacyTop1m:
		top1mLines = lineSeq(stringList(legacyTop1m))
	default:
		top1mLines = dnsblFixedTop1mLines(baseDir)
	}
	return build(manifestFromDocument(root), config, dnsblFileLineReader(baseDir, true), top1mEnabled, top1mLines)
}

// ---------------------------------------------------------------------------------------------------------------
// dnsbl_emit_count, dnsbl_emit_reject_stats (6667-6721)

// dnsblEmitCount writes the Python-emitted entry total to pfb_py_count, which pfb_update_unbound() reads for the UI.
// ADR-06 redefines pfb_py_count to the LOADED entry total (len(dataDB)+len(zoneDB)); its value legitimately differs
// from the raw feed line count because the lists are no longer dedup/collapse/whitelist-pruned.
func dnsblEmitCount(countPath string, count int) bool {
	if err := os.WriteFile(countPath, fmt.Appendf(nil, "%d\n", count), 0o666); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			err = pathErr.Err
		}
		logErr(fmt.Sprintf("[pfBlockerNG]: Failed to write DNSBL count '%s': %s", countPath, pyOSError(err, countPath)))
		return false
	}
	return true
}

// rejectStatsRow is one {"feed", "group", "shape", "wire_cap"} row of pfb_py_reject_stats; issue #2371's
// "suffix_drop" / "suffix_demote" are present only on a row that actually tallied one.
type rejectStatsRow struct {
	Feed         string `json:"feed"`
	Group        string `json:"group"`
	Shape        int    `json:"shape"`
	WireCap      int    `json:"wire_cap"`
	SuffixDrop   int    `json:"suffix_drop,omitempty"`
	SuffixDemote int    `json:"suffix_demote,omitempty"`
}

// dnsblEmitRejectStats writes the ADR-48 (issue #789) per-entry reject tally to pfb_py_reject_stats as a JSON array of
// rows, one per (feed, group) with a NONZERO bucket -- PHP reads it after a DNSBL run and emits the canonical
// stage=entries line per nonzero bucket. An empty tally still writes "[]" so PHP can tell "ran, zero rejects" from "no
// artifact". Atomic temp + rename: a partial write can never leave PHP reading a truncated artifact.
// shortcut: the JSON is json.Marshal's (no spaces, non-ASCII raw), not json.dump's; PHP reads it with json_decode.
func dnsblEmitRejectStats(statsPath string, rejects rejectTally) bool {
	keys := make([][2]string, 0, len(rejects))
	for key := range rejects {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	entries := []rejectStatsRow{}
	for _, key := range keys {
		counts := rejects[key]
		row := rejectStatsRow{Feed: key[0], Group: key[1], Shape: counts["shape"], WireCap: counts["wire_cap"],
			SuffixDrop: counts["suffix_drop"], SuffixDemote: counts["suffix_demote"]}
		if row.Shape != 0 || row.WireCap != 0 || row.SuffixDrop != 0 || row.SuffixDemote != 0 {
			entries = append(entries, row)
		}
	}
	tmp := statsPath + ".tmp"
	err := func() error {
		encoded, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
		if err != nil {
			return err
		}
		_, err = fh.Write(encoded)
		if err == nil {
			err = fh.Sync()
		}
		if closeErr := fh.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		return os.Rename(tmp, statsPath)
	}()
	if err != nil {
		var pathErr *os.PathError
		var linkErr *os.LinkError
		switch {
		case errors.As(err, &pathErr):
			err = pathErr.Err
		case errors.As(err, &linkErr):
			err = linkErr.Err
		}
		logErr(fmt.Sprintf("[pfBlockerNG]: Failed to write DNSBL reject stats '%s': %s", statsPath, pyOSError(err, statsPath)))
		os.Remove(tmp)
		return false
	}
	return true
}
