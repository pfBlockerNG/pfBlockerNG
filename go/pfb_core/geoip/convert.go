// Package geoip converts the MaxMind GeoLite2 Country CSVs into the country and continent lists pfBlockerNG's GeoIP
// aliases read (#4034): what pfblockerng_uc_countries() writes, and the per-country lists pfblockerng_get_countries()
// splits out of the continent files, and the geo-catalog, the data that pfblockerng_get_countries() writes into the pages
// (slice 5b). Nothing calls it yet (slice 9, #4038).
package geoip

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// Conversion is pfblockerng_uc_countries() as the dcc verb runs it, without the pages.
type Conversion struct {
	Share  string    // the MaxMind CSVs ($pfb['geoipshare'])
	CCDir  string    // the country folder ($pfb['ccdir']): a link to the generation published last
	LogDir string    // where maxmind_ver goes ($pfb['logdir'])
	Locale string    // the MaxMind locale (extras.maxmindLocale)
	Now    time.Time // the continent files' "Generated" stamp
	Log    io.Writer // the Extras log
}

//go:embed countries.json
var countriesJSON []byte

// known is $pfb_geoip_all, every country Geonames.org lists, in its order: [geoname_id, iso, name, continent].
var known = func() [][4]string {
	var rows [][4]string
	if err := json.Unmarshal(countriesJSON, &rows); err != nil {
		panic(err)
	}
	return rows
}()

// topSpammers is the fixed Top Spammers group, in its order.
var topSpammers = []string{"CN", "RU", "JP", "UA", "GB", "DE", "BR", "FR", "IN", "TR",
	"IT", "KR", "PL", "ES", "VN", "AR", "CO", "TW", "MX", "CL"}

var continentStems = []string{"Africa", "Antarctica", "Asia", "Europe", "North_America", "Oceania", "South_America",
	"Proxy_and_Satellite"}

// errFatal is where today's PHP dies with an Error: a list operation on a Top Spammers entry (whose ISO is a string), or
// escapeshellarg() refusing a continent code. The conversion stops and publishes nothing.
var errFatal = errors.New("today's conversion dies here with a PHP Error")

var errMalformed = errors.New("malformed row")

// malformed refuses a row the continent files could not carry: split() reads them line by line, so a field written into
// them that spans lines forges headers, and a network that is not one breaks the list it lands in (#4127). The
// conversion stops and the previous generation stays; today's PHP writes the row as it was read.
func (c Conversion) malformed(path string) error {
	c.log(" [ MAXMIND UPDATE FAIL, malformed row in %s, using previous Country code database ]\n", filepath.Base(path))
	return errMalformed
}

// country is an entry of $pfb_geoip['country']. A field PHP leaves unset reads as "".
type country struct {
	id, continent, name, continentEn string
	iso                              []string
	isoText                          *string // a Top Spammers entry's ISO, a string where a country has a list
}

func (c *country) firstISO() string {
	switch {
	case c == nil:
		return ""
	case c.isoText != nil:
		return (*c.isoText)[:1] // a string read at offset 0; a Locations ISO is never empty
	case len(c.iso) > 0:
		return c.iso[0]
	}
	return ""
}

// countries is $pfb_geoip['country']: its entries in PHP's array order.
type countries struct {
	keys  []string
	byKey map[string]*country
}

func (cs *countries) set(key string, c *country) {
	if _, ok := cs.byKey[key]; !ok {
		cs.keys = append(cs.keys, key)
	}
	cs.byKey[key] = c
}

// addISO is $pfb_geoip['country'][$key]['iso'][] = $iso, which creates the entry when there is none. Its callers have
// ruled out a Top Spammers entry (addISOOnce), or name proxy or satellite.
func (cs *countries) addISO(key, iso string) {
	c := cs.byKey[key]
	if c == nil {
		c = &country{}
		cs.set(key, c)
	}
	c.iso = append(c.iso, iso)
}

// addISOOnce adds iso unless the entry already lists it.
func (cs *countries) addISOOnce(key, iso string) error {
	if c := cs.byKey[key]; c != nil {
		if c.isoText != nil {
			return errFatal
		}
		if slices.Contains(c.iso, iso) {
			return nil
		}
	}
	cs.addISO(key, iso)
	return nil
}

// stage is the generation being built, file by file, before it is written to the staged folder.
type stage map[string][]byte

func (s stage) has(name string) bool         { _, ok := s[name]; return ok }
func (s stage) append(name string, b []byte) { s[name] = append(s[name], b...) }
func (s stage) truncate(name string)         { s[name] = []byte{} }
func (s stage) remove(name string)           { delete(s, name) }

func (c Conversion) log(format string, args ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, format, args...)
	}
}

// eachRow calls row for every record of path, read as fgetcsv() reads it; false when the file cannot be opened or read
// to its end.
func eachRow(ctx context.Context, path string, row func([]string) error) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer f.Close()
	cr := newCSVReader(f)
	for n := 0; ; n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		rec, err := cr.Read()
		switch {
		case errors.Is(err, io.EOF):
			return true, nil
		case err != nil:
			return false, nil // a read that fails part-way converts nothing rather than half a file
		}
		if err := row(rec); err != nil {
			return false, err
		}
	}
}

func field(rec []string, i int) string {
	if i < len(rec) {
		return rec[i]
	}
	return ""
}

// Run converts the CSVs and publishes the new generation whole: the continent files, the per-country lists, Top
// Spammers, the ISO list (.geoip_isos) and the geo-catalog (.geo_catalog). False leaves the previous generation in place; maxmind_ver is written as the
// conversion goes, as today.
func (c Conversion) Run(ctx context.Context) bool {
	c.CCDir = filepath.Clean(c.CCDir) // a trailing slash would put the generations inside the live one
	for _, dir := range []string{c.LogDir, filepath.Dir(c.CCDir)} {
		os.MkdirAll(dir, 0o755)
	}
	c.log("Country code update Start\n")
	locations := filepath.Join(c.Share, "GeoLite2-Country-Locations-"+c.Locale+".csv")
	info, err := os.Stat(locations)
	if err != nil {
		c.log(" [ MAXMIND UPDATE FAIL, Language File Missing, using previous Country code database ]\n")
		return false
	}
	maxmindVer := filepath.Join(c.LogDir, "maxmind_ver")
	os.WriteFile(maxmindVer, []byte("MaxMind GeoLite2 Date/Time Stamp\nLast-Modified: "+
		info.ModTime().UTC().Format(time.DateTime)+"\n"), 0o644)
	built, ok, err := c.build(ctx, locations, maxmindVer)
	if err != nil || !ok || ctx.Err() != nil {
		return false
	}
	return c.publish(ctx, built)
}

// generationDir is a new generation's folder beside the country folder: .<name>.<pid>.<8 hex>, as staleSibling knows it.
func (c Conversion) generationDir() string {
	var id [4]byte
	rand.Read(id[:])
	return filepath.Join(filepath.Dir(c.CCDir),
		fmt.Sprintf(".%s.%d.%s", filepath.Base(c.CCDir), os.Getpid(), hex.EncodeToString(id[:])))
}

// continentFile is the str_replace() that makes a continent name a file name.
var continentFile = strings.NewReplacer(" ", "_", `"`, "")

// build is the conversion in memory: the generation's files (the ISO list as .geoip_isos, the geo-catalog as
// .geo_catalog), and whether every required file is there.
func (c Conversion) build(ctx context.Context, locations, maxmindVer string) (stage, bool, error) {
	cs := &countries{byKey: map[string]*country{}}
	english := map[string]string{}
	read, err := eachRow(ctx, locations, func(cc []string) error {
		if field(cc, 0) == "geoname_id" {
			return nil
		}
		for i := 0; i <= 5; i++ {
			if empty(field(cc, i)) {
				return nil
			}
		}
		// A field that is not UTF-8 is refused too: the geo-catalog carries the names as JSON text (#4034 slice 5b).
		if slices.ContainsFunc(cc[:6], func(f string) bool { return strings.ContainsAny(f, "\r\n") || !utf8.ValidString(f) }) {
			return c.malformed(locations)
		}
		entry := &country{id: cc[0], continent: cc[3], name: cc[5], iso: []string{cc[4]}}
		continentEn := cc[3]
		if cc[1] != "en" {
			if strings.IndexByte(cc[2], 0) >= 0 {
				// escapeshellarg() throws on a NUL.
				// shortcut: near the platform's argument-length limit (ARG_MAX) PHP also fails, by escapeshellarg()
				// throwing or by exec() getting E2BIG (no English name); no continent code comes near it. Upgrade if a
				// corpus row needs one.
				return errFatal
			}
			v, seen := english[cc[2]]
			if !seen {
				v = c.englishContinent(locations, cc[2])
				english[cc[2]] = v
			}
			continentEn = v
		}
		entry.continentEn = continentFile.Replace(continentEn)
		cs.set(cc[0], entry)
		if i := slices.Index(topSpammers, cc[4]); i >= 0 {
			iso := cc[4]
			cs.set(fmt.Sprintf("A%05d", i), &country{name: cc[5], isoText: &iso, id: cc[0]})
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	generationOK := read

	cs.set("proxy", &country{continent: "Proxy and Satellite", name: "Proxy", iso: []string{"A1"}, continentEn: "Proxy_and_Satellite"})
	cs.set("satellite", &country{continent: "Proxy and Satellite", name: "Satellite", iso: []string{"A2"}, continentEn: "Proxy_and_Satellite"})
	cs.set("6255147", &country{continent: "Asia", name: "AA ASIA UNDEFINED", iso: []string{"6255147"}, continentEn: "Asia"})
	cs.set("6255148", &country{continent: "Europe", name: "AA EUROPE UNDEFINED", iso: []string{"6255148"}, continentEn: "Europe"})

	// A MaxMind country is one the Locations file still holds (no built-in entry replaced it) that continents() takes
	// for a country, not for a Top Spammers entry. It is placed when its list lands in a continent file split() reads.
	maxmind := func(key string) bool { return cs.byKey[key].id == key && !strings.Contains(key, "A000") }
	placed := func(key string) bool {
		g := cs.byKey[key]
		return maxmind(key) && slices.Contains(continentStems, g.continentEn) && len(g.iso) > 0 && word(g.iso[0])
	}
	if slices.ContainsFunc(cs.keys, maxmind) && !slices.ContainsFunc(cs.keys, placed) {
		// Today's PHP publishes the generation without MaxMind's countries, deleting their previous lists (#4125).
		c.log(" [ MAXMIND UPDATE FAIL, no MaxMind country has a continent file, using previous Country code database ]\n")
		return nil, false, nil
	}

	s := stage{}
	var isoList strings.Builder
	unlisted := map[string]bool{} // $pfb_geoip_all's countries MaxMind has not listed in IPv4 yet
	for _, k := range known {
		unlisted[k[0]] = true
		isoList.WriteString(k[1] + " [ " + k[2] + " ]," + k[1] + "_rep [ " + k[2] + " ],")
		if cs.byKey[k[0]] == nil {
			cs.set(k[0], &country{id: k[0], name: k[2], iso: []string{k[1], k[1] + "_rep"}, continent: k[3],
				continentEn: continentFile.Replace(k[3])})
			cs.addISO("proxy", "A1_"+k[1]+"_rep")
			cs.addISO("satellite", "A2_"+k[1]+"_rep")
		}
	}
	isoList.WriteString("Africa [Continent],Antarctica [Continent],Asia [Continent],Europe [Continent],North_America [Continent],Oceania [Continent]")
	isoList.WriteString(",South_America [Continent],Proxy_and_Satellite [GeoIP]")

	// ksort(SORT_NATURAL), stable since PHP 8.0.
	slices.SortStableFunc(cs.keys, natCompare)

	tmp := map[string][]byte{} // $pfb['ccdir_tmp']: each ISO's networks, "<iso>_v<type>"
	stamp := c.Now.Format(time.DateTime)
	for _, family := range []string{"4", "6"} {
		c.log(" Processing ISO IPv%s Continent/Country Data\n", family)
		dup := 0
		blocks := filepath.Join(c.Share, "GeoLite2-Country-Blocks-IPv"+family+".csv")
		// The first record that is not a blank line is the header; a second one is a share put together from two files.
		header := true
		read, err := eachRow(ctx, blocks, func(cc []string) error {
			network, gid, reg := field(cc, 0), field(cc, 1), field(cc, 2)
			blank := !slices.ContainsFunc(cc, func(f string) bool { return trim(f) != "" })
			// The network is read as split() reads a line, trimmed; "0" is checked too, though PHP's empty() would skip it.
			switch n := trim(network); {
			case header && n == "network":
				header = false
				return nil
			case n == "":
				header = header && blank
				network = "" // white space alone is no network, skipped as an empty one is
			default:
				header = false
				if _, err := netip.ParsePrefix(n); err != nil {
					return c.malformed(blocks)
				}
			}
			iso, isoRep := "", ""
			if family == "4" {
				delete(unlisted, gid)
				prefix, owner := "", reg
				switch {
				case isOne(field(cc, 4)):
					prefix, owner = "A1_", "proxy"
				case isOne(field(cc, 5)):
					prefix, owner = "A2_", "satellite"
				}
				if prefix != "" {
					// A network located in a country (an entry of the Locations file or the built-in table, or one of
					// MaxMind's continent-only ids) goes to A1_<country> or A2_<country>, listed under Proxy and Satellite
					// (#4126); today's PHP stages it as A1_A1 or A2_A2, which no continent file lists. An id that names no
					// such entry stays dropped.
					if g := cs.byKey[gid]; g != nil && (!empty(g.id) || gid == "6255147" || gid == "6255148") {
						iso = prefix + g.firstISO()
						if err := cs.addISOOnce(owner, iso); err != nil {
							return err
						}
					}
					if !empty(reg) && !equal(gid, reg) {
						dup++
						isoRep = prefix + cs.byKey[reg].firstISO() + "_rep"
					}
					if empty(gid) && empty(reg) {
						iso = strings.TrimSuffix(prefix, "_")
					}
				} else {
					if !empty(gid) {
						iso = cs.byKey[gid].firstISO()
					}
					if !empty(reg) && !equal(gid, reg) {
						dup++
						isoRep = cs.byKey[reg].firstISO() + "_rep"
					}
				}
				if !empty(isoRep) && !empty(owner) {
					if err := cs.addISOOnce(owner, isoRep); err != nil {
						return err
					}
				}
				if !empty(gid) {
					// The country's first ISO is read again for each one: the first may just have created its entry.
					for _, p := range [][2]string{{"", gid}, {"A1_", "proxy"}, {"A2_", "satellite"}} {
						if err := cs.addISOOnce(p[1], p[0]+cs.byKey[gid].firstISO()+"_rep"); err != nil {
							return err
						}
					}
				}
				if !empty(isoRep) && !empty(network) && word(isoRep) {
					tmp[isoRep+"_v4"] = append(tmp[isoRep+"_v4"], network+"\n"...)
				}
			} else if !empty(gid) {
				iso = cs.byKey[gid].firstISO()
			}
			if !empty(iso) && !empty(network) && word(iso) {
				tmp[iso+"_v"+family] = append(tmp[iso+"_v"+family], network+"\n"...)
			}
			return nil
		})
		if err != nil {
			return nil, false, err
		}
		if !read {
			c.log("\n Failed to load file: %s\n", blocks)
			generationOK = false
			continue
		}
		if family == "4" {
			for _, k := range known {
				if unlisted[k[0]] {
					cs.addISO("proxy", "A1_"+k[1]+"_rep")
					cs.addISO("satellite", "A2_"+k[1]+"_rep")
				}
			}
		}
		if dup != 0 {
			appendFile(maxmindVer, fmt.Sprintf("Duplicate Represented IP%s Networks: %d\n", family, dup))
		}
		c.continents(cs, s, tmp, family, stamp)
	}

	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	for _, family := range []string{"4", "6"} {
		for _, stem := range continentStems {
			if !s.has(stem + "_v" + family + ".txt") {
				generationOK = false
			}
		}
	}
	if !generationOK {
		return nil, false, nil
	}
	s[".geo_catalog"] = c.split(s)
	s[".geoip_isos"] = []byte(isoList.String())
	return s, true, nil
}

// continents writes one family's continent files and Top Spammers from the countries, in their order.
func (c Conversion) continents(cs *countries, s stage, tmp map[string][]byte, family, stamp string) {
	for _, key := range cs.keys {
		g := cs.byKey[key]
		if strings.Contains(key, "A000") {
			name := "Top_Spammers_v" + family + ".info"
			if !s.has(name) {
				s.append(name, []byte("# Generated from MaxMind Inc. on: "+stamp+"\n# Continent IPv"+family+
					": Top_Spammers\n# Continent en: Top_Spammers\n"))
			}
			iso := ""
			switch {
			case g.isoText != nil:
				iso = *g.isoText
			case g.iso != nil:
				iso = "Array" // a list where the entry is a Top Spammers one: PHP's array-to-string conversion
			}
			entry := "# Country: " + g.name + " (" + g.id + ")\n# ISO Code: " + iso + "\n# Total Networks: Top20\nTop20\n"
			if _, ok := tmp[iso+"_rep_v"+family]; ok {
				entry += "# Country: " + g.name + " (" + g.id + ")\n# ISO Code: " + iso + "_rep\n# Total Networks: Top20\nTop20\n"
			}
			s.append(name, []byte(entry))
			continue
		}
		if empty(g.continentEn) || !word(g.continentEn) {
			c.log("\n Failed to create Continent file: %s", g.continent)
			continue
		}
		name := g.continentEn + "_v" + family + ".txt"
		if !s.has(name) {
			s.append(name, []byte("# Generated from MaxMind Inc. on: "+stamp+"\n# Continent IPv"+family+": "+
				g.continent+"\n# Continent en: "+g.continentEn+"\n"))
		}
		if len(g.iso) == 0 {
			c.log("\n Missing ISO data: %s", g.continent)
			continue
		}
		geoID := ""
		if !empty(g.id) {
			geoID = " [" + g.id + "]"
		}
		for _, iso := range g.iso {
			if !word(iso) {
				continue
			}
			networks, ok := tmp[iso+"_v"+family]
			if !ok {
				s.append(name, []byte("# Country: "+g.name+geoID+"\n# ISO Code: "+iso+"\n# Total Networks: NA\n"))
				continue
			}
			s.append(name, []byte(fmt.Sprintf("# Country: %s%s\n# ISO Code: %s\n# Total Networks: %d\n", g.name, geoID, iso,
				countLines(networks))))
			s.append(name, networks)
		}
		g.iso = g.iso[:1] // the represented ISOs are listed once, with IPv4
	}
}

var splitFiles = []struct{ cont, file string }{
	{"Africa", "Africa_v4.txt"}, {"Antarctica", "Antarctica_v4.txt"}, {"Asia", "Asia_v4.txt"},
	{"Europe", "Europe_v4.txt"}, {"North America", "North_America_v4.txt"}, {"Oceania", "Oceania_v4.txt"},
	{"South America", "South_America_v4.txt"}, {"Proxy and Satellite", "Proxy_and_Satellite_v4.txt"},
	{"Top Spammers", "Top_Spammers_v4.info"},
}

// split is pfblockerng_get_countries()'s pass over the continent files that writes each ISO's list
// ("<iso>_v<family>.txt") into the staged folder: a header starts an ISO's list afresh, its network lines follow, and a
// header with no networks ("Total Networks: 0" or "NA") leaves it empty. Top Spammers names lists, it writes none.
// An ISO code that is not a word is never a file name: today's PHP removes "<folder>/<iso>_v<family>.txt" for it
// whatever it holds, a path outside the folder included (#4034 forbids it).
// The same pass gathers what the continent pages and the Reputation tab list (#4034 slice 5b): it returns the
// geo-catalog, the data today's PHP writes into those pages as source code (see catalog).
// shortcut: a continent file is read as it stood when its pass began; PHP reads the open file, so a header naming that
// continent's own file could cut its pass short there. Only a forged header can name one.
func (c Conversion) split(s stage) []byte {
	pages := map[string]page{}
	var reputation []option
	var carried [2][]option // a family's options of a continent whose name is empty, which the next continent lists
	byKey := func(a, b option) int { return strings.Compare(a.sortKey(), b.sortKey()) }
	for _, sf := range splitFiles {
		continent, continentEn := "", "" // read from either family's file, as $continent and $continent_en are
		var lists [2][]option
		for f, family := range []string{"4", "6"} {
			name := strings.Replace(sf.file, "_v4", "_v"+family, 1)
			options := carried[f]
			carried[f] = nil
			add := func(country, iso string, networks int) {
				o := option{country, iso, networks}
				options = append(options, o)
				// The Reputation tab offers no proxy or satellite list of a country: the exclusion it feeds
				// compares a plain ISO code (#4149).
				proxy := strings.HasPrefix(iso, "A1_") || strings.HasPrefix(iso, "A2_")
				if family == "4" && !strings.Contains(iso, "_rep") && !proxy {
					reputation = append(reputation, o)
				}
			}
			if content, ok := s[name]; ok {
				isocode, country, total, complete := "", "", 0, false
				lines := strings.SplitAfter(string(content), "\n")
				if lines[len(lines)-1] == "" {
					lines = lines[:len(lines)-1] // fgets() reads no line after the last line feed
				}
				for _, raw := range lines {
					line := trim(raw)
					list := isocode + "_v" + family + ".txt"
					if !strings.HasPrefix(line, "#") {
						if word(isocode) {
							if sf.cont == "Top Spammers" {
								total = countLines(s[list])
							} else {
								total++
								if !empty(line) {
									s.append(list, []byte(line+"\n"))
								}
							}
						}
						complete = true
					} else {
						// The ISO a list closes is listed at the next header, when it is in the staged folder.
						if complete {
							if s.has(list) {
								add(country, isocode, total)
							}
							total, complete = 0, false
						}
						// A header is matched at the start of its line, where continents() writes it; today's PHP matches it
						// anywhere in a '#' line, so a country name holding header text forges one (#4127).
						if strings.HasPrefix(line, "# Continent IPv") {
							_, after, _ := strings.Cut(line, ":")
							continent = trim(strings.ReplaceAll(after, ":", ""))
						}
						if strings.HasPrefix(line, "# Continent en:") {
							_, after, _ := strings.Cut(line, ":")
							continentEn = trim(strings.ReplaceAll(after, ":", ""))
						}
						if strings.HasPrefix(line, "# Country: ") {
							country = strings.ReplaceAll(line, "# Country: ", "")
						}
						if strings.HasPrefix(line, "# ISO Code: ") {
							isocode = strings.TrimPrefix(line, "# ISO Code: ")
							list = isocode + "_v" + family + ".txt"
							if sf.cont != "Top Spammers" && word(isocode) {
								s.remove(list)
							}
						}
						if line == "# Total Networks: 0" || line == "# Total Networks: NA" {
							if word(isocode) {
								s.truncate(list)
							}
							complete = true
						}
					}
				}
				// The last line closes the last ISO, complete or not.
				if word(isocode) && s.has(isocode+"_v"+family+".txt") {
					add(country, isocode, total)
				}
			}
			if empty(continent) {
				// Today's PHP skips this family's list and does not clear its options: the next continent lists them. A
				// continent name that is empty once trimmed and its colons removed comes here.
				c.log("Continent data [ %s ] not found\n", sf.cont)
				carried[f] = options
				continue
			}
			if sf.cont != "Top Spammers" {
				slices.SortFunc(options, byKey)
			}
			lists[f] = options
		}
		if word(continentEn) { // the page is pfblockerng_<continent_en>.php; a later continent naming it again replaces it
			pages[continentEn] = page{continent, lists}
		}
	}
	slices.SortFunc(reputation, byKey)
	return catalog(pages, reputation)
}

// option is an entry of a continent page's country list or of the Reputation tab's, shown "<country> <iso> (<networks>)".
type option struct {
	country, iso string
	networks     int
}

// sortKey is the string today's PHP sorts the options by (sort(SORT_STRING)) before it cuts the key at its first "|".
func (o option) sortKey() string {
	return o.country + `|"` + o.iso + `" => "` + o.country + " " + o.iso + " (" + strconv.Itoa(o.networks) + `)"`
}

// page is a continent page: its continent name in the locale and its IPv4 and IPv6 country lists.
type page struct {
	continent string
	lists     [2][]option
}

// catalog is the geo-catalog resource body (docs/specs/go-updater-pipeline.md §7): JSON Lines in byte order, one row a
// line. A "page" row per continent page ({"kind", "page": its continent_en, "continent"}), a "country" row per entry of
// its lists ({"kind", "page", "family": 4 or 6, "position" from 1, "iso", "country", "networks"}), and a "reputation"
// row per entry of the Reputation tab's IPv4 list ({"kind", "position", "iso", "country", "networks"}). The Outpost apply
// renders the pages from it (#4037); today's PHP writes the same values into their source, where a quote in a name ends
// the string it sits in.
func catalog(pages map[string]page, reputation []option) []byte {
	var lines []string
	add := func(row any) { lines = append(lines, JSONMember(row)) }
	type countryRow struct {
		Kind     string `json:"kind"`
		Page     string `json:"page,omitempty"`
		Family   int    `json:"family,omitempty"`
		Position int    `json:"position"`
		ISO      string `json:"iso"`
		Country  string `json:"country"`
		Networks int    `json:"networks"`
	}
	for en, p := range pages {
		add(struct {
			Kind      string `json:"kind"`
			Page      string `json:"page"`
			Continent string `json:"continent"`
		}{"page", en, p.continent})
		for f, list := range p.lists {
			for i, o := range list {
				add(countryRow{"country", en, 4 + 2*f, i + 1, o.iso, o.country, o.networks})
			}
		}
	}
	for i, o := range reputation {
		add(countryRow{Kind: "reputation", Position: i + 1, ISO: o.iso, Country: o.country, Networks: o.networks})
	}
	// shortcut: a name over the resource store's 1 MiB member limit is written as it is, and publishing the catalog then
	// fails; the Core Updater that publishes it (#4038) reports that.
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n") + "\n")
}

// JSONMember is row as one resource member of a JSON Lines body: its JSON, with every control character escaped, as
// JSON escapes those below U+0020 and leaves DEL and the C1 controls as they are. Row holds strings and numbers: invalid
// UTF-8 in a string becomes U+FFFD, and nothing fails.
func JSONMember(row any) string {
	b, _ := json.Marshal(row)
	var line strings.Builder
	for _, r := range string(b) {
		if unicode.IsControl(r) {
			fmt.Fprintf(&line, `\u%04x`, r)
		} else {
			line.WriteRune(r)
		}
	}
	return line.String()
}

// englishContinent is the continent's English name as `grep -m1 ",en,<code>" <English Locations> | cut -d, -f4`
// returns it to exec(): the fourth comma-separated field of the first line holding the text, the whole line when it
// has no comma, its trailing white space stripped; "" when no line holds it or the file cannot be read.
// shortcut: the code is matched as text, not as grep's basic regular expression, and a file grep would call binary is
// read as text; MaxMind's codes are two letters.
func (c Conversion) englishContinent(locations, code string) string {
	path := strings.ReplaceAll(locations, "Locations-"+c.Locale, "Locations-en")
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	needle := ",en," + code
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		fields := strings.Split(line, ",")
		out := ""
		switch {
		case len(fields) == 1:
			out = line
		case len(fields) >= 4:
			out = fields[3]
		}
		return strings.TrimRight(out, " \t\n\v\f\r")
	}
	return ""
}

func appendFile(path, s string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	f.WriteString(s)
	f.Close()
}

// publish writes the generation into a folder of its own and makes it live in one step (#4140): a link to it is renamed
// over the country folder, so a reader sees the previous generation or this one whole, and a run killed at any point
// leaves one of them. All of it runs under the publication lock beside the link (.<name>.lock), which readers share
// from the cutover (#4038), so the cleanup that follows (every generation but this one and the previous, and what
// interrupted publications left) never meets a generation still being written. A country folder that is still a real
// folder (an install from before #4140) is first set aside as the previous generation, and put back if the link cannot
// replace it. A missing country folder leaves no previous generation to tell apart, so no generation is removed.
func (c Conversion) publish(ctx context.Context, s stage) bool {
	parent, base := filepath.Dir(c.CCDir), filepath.Base(c.CCDir)
	lock, ok := publicationLock(ctx, filepath.Join(parent, "."+base+".lock"))
	if !ok {
		return false
	}
	defer lock.Close() // closing the file releases the lock
	genDir := c.generationDir()
	if os.Mkdir(genDir, 0o755) != nil {
		return false
	}
	for name, b := range s {
		if os.WriteFile(filepath.Join(genDir, name), b, 0o644) != nil {
			os.RemoveAll(genDir)
			return false
		}
	}
	previous, _ := os.Readlink(c.CCDir)
	if previous != "" {
		previous = filepath.Base(previous) // the generation's name, however the link spells its path
	}
	aside := ""
	if info, err := os.Lstat(c.CCDir); err == nil && info.Mode()&os.ModeSymlink == 0 {
		aside = c.generationDir()
		if os.Rename(c.CCDir, aside) != nil {
			os.RemoveAll(genDir)
			return false
		}
		previous = filepath.Base(aside)
	}
	link := genDir + ".link"
	if os.Symlink(filepath.Base(genDir), link) != nil || rename(link, c.CCDir) != nil {
		os.Remove(link)
		if aside != "" && os.Rename(aside, c.CCDir) != nil {
			c.log(" [ GeoIP publication failed, previous Country code database left at %s ]\n", aside)
		}
		os.RemoveAll(genDir)
		return false
	}
	if previous == "" {
		return true
	}
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if name := e.Name(); name != filepath.Base(genDir) && name != previous && staleSibling(base, name) {
			os.RemoveAll(filepath.Join(parent, name))
		}
	}
	return true
}

// staleSibling reports whether name, beside the country folder base, is what a publication leaves: a generation
// (.<base>.<pid>.<8 hex>) or its link (.link), or today's PHP staged and set-aside folders (<base>.new.*, <base>.old.*).
func staleSibling(base, name string) bool {
	if rest, ok := strings.CutPrefix(name, "."+base+"."); ok {
		return generationID(strings.TrimSuffix(rest, ".link"))
	}
	for _, prefix := range []string{base + ".new.", base + ".old."} {
		if rest, ok := strings.CutPrefix(name, prefix); ok {
			return generationID(rest)
		}
	}
	return false
}

// generationID reports whether s is getmypid() . '.' . bin2hex(random_bytes(4)).
var generationID = regexp.MustCompile(`^[0-9]+\.[0-9a-f]{8}$`).MatchString

// publicationLock is pfb_geoip_generation_publication_lock(): the lock file held exclusively, tried every 20 ms for up
// to 60 s as pfb_flock_bounded() does, or until ctx ends.
func publicationLock(ctx context.Context, path string) (*os.File, bool) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, true
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, false
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			f.Close()
			return nil, false
		}
	}
}

// rename moves the link over the country folder; a test watches it.
var rename = os.Rename
