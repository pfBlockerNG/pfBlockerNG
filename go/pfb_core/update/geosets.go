package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// GeoSets is stage 11 of the Update loop (docs/specs/go-updater-pipeline.md §3): each enabled GeoIP continent's IPv4
// and IPv6 set, the concatenation of its selected countries' lists in the country folder, as today's continent block of
// sync_package_pfblockerng() builds it (pfblockerng_apply.inc:3471-3661; corpus
// tests/geoip/fixtures/continents/continent_sets.json). A set is kept as the baseline <alias>.orig in OrigDir and the
// list <alias>.txt in the folder of its list class.
//
// Departures from today: an empty set is written empty, never with the placeholder address (spec §7; #4038 owner
// question 1); a set is compared with its baseline as it is stored, its last line terminated; the kernel table's count
// is not read (Core has none) and no ADR-40 mirror, Reputation snapshot or aggregation is written here (the Outpost
// apply's, and the IP sets' of sub-slice 9h).
type GeoSets struct {
	CCDir   string            // the country folder ($pfb['ccdir']): a link to the generation the conversion published
	OrigDir string            // the baselines ($pfb['origdir'])
	Folders map[string]string // the folder of each list class: deny, permit, match and native
	Enabled bool              // pfBlockerNG is on ($pfb['enable']); off builds nothing
	Force   bool              // a forced reload ($pfb['reuse']): every set is rebuilt
	// GeoIPChanged: stage 5's conversion changed the country lists (ExtrasOutcome.GeoIPChanged): every set is rebuilt.
	GeoIPChanged bool
	Log          io.Writer // the main log: a country list that cannot be read is logged; nil discards
}

// GeoSet is one continent set Build visited.
type GeoSet struct {
	Alias     string // pfB_<continent>_v4 or _v6
	Group     string // the alias without pfB_ and the family suffix: the <group> of ip-set/<group>/<family>
	Family    string // ipv4 or ipv6
	Action    string // the continent's action
	ListClass string // deny, permit, match or native
	Path      string // the list
	Changed   bool   // the set was rebuilt and published this Update
}

// geoWrite writes a staged set: a test seam for a disk without room.
var geoWrite = func(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

// continents are the GeoIP continents in the package's order ($pfb['continents']).
var continents = []string{"pfB_Top", "pfB_Africa", "pfB_Antarctica", "pfB_Asia", "pfB_Europe", "pfB_NAmerica", "pfB_Oceania",
	"pfB_SAmerica", "pfB_PS"}

// Build builds the sets of geoip, the settings/feeds/geoip projection, in the package's continent order whatever the
// order of its groups (a name outside the nine is no continent), IPv4 before IPv6. A set
// that could not be published keeps its previous baseline and list, is not reported changed, and its error is joined
// to the others; the other sets are still built.
func (g GeoSets) Build(ctx context.Context, geoip map[string]any) ([]GeoSet, error) {
	if !g.Enabled {
		return nil, nil
	}
	byName := map[string]map[string]any{}
	for _, group := range rows(geoip["groups"]) {
		if name, _ := group["name"].(string); byName[name] == nil {
			byName[name] = group
		}
	}
	var sets []GeoSet
	var errs []error
	for _, name := range continents {
		group := byName[name]
		action, _ := group["action"].(string)
		class, _ := group["listClass"].(string)
		folder := g.Folders[class]
		if action == "" || action == "Disabled" || folder == "" {
			continue
		}
		for _, fam := range [...]struct{ field, suffix, family string }{{"countriesV4", "_v4", "ipv4"}, {"countriesV6", "_v6", "ipv6"}} {
			var isos []string
			for _, c := range rows(group[fam.field]) {
				if code, _ := c["code"].(string); code != "" {
					isos = append(isos, code)
				}
			}
			if len(isos) == 0 {
				continue
			}
			if err := ctx.Err(); err != nil {
				return sets, errors.Join(append(errs, err)...)
			}
			s := GeoSet{Alias: name + fam.suffix, Group: strings.TrimPrefix(name, "pfB_"), Family: fam.family, Action: action,
				ListClass: class, Path: filepath.Join(folder, name+fam.suffix+".txt")}
			changed, err := g.build(s, isos, fam.suffix)
			s.Changed = changed
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Alias, err))
			}
			sets = append(sets, s)
		}
	}
	return sets, errors.Join(errs...)
}

// build publishes one set when it changed: the list and the baseline are staged beside their targets, then renamed,
// the list first. A run killed between the two renames leaves the old baseline, so the next Update finds the set
// changed and publishes both again (roll forward); its staged files are removed first.
func (g GeoSets) build(s GeoSet, isos []string, suffix string) (bool, error) {
	orig := filepath.Join(g.OrigDir, s.Alias+".orig")
	for _, target := range []string{orig, s.Path} {
		stale, _ := filepath.Glob(filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".*"))
		for _, p := range stale {
			os.Remove(p)
		}
	}
	var body []byte
	for _, iso := range isos {
		b, err := os.ReadFile(filepath.Join(g.CCDir, iso+suffix+".txt"))
		if err != nil {
			if g.Log != nil {
				fmt.Fprintf(g.Log, "\nCould not open ISO [ %s%s ]\n", iso, suffix)
			}
			continue
		}
		body = append(body, b...)
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	if old, err := os.ReadFile(orig); err == nil && bytes.Equal(old, body) && !g.Force && !g.GeoIPChanged {
		if _, err := os.Stat(s.Path); err == nil {
			return false, nil
		}
	}
	var staged []string
	defer func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}()
	for _, target := range []string{s.Path, orig} {
		p, err := stageFile(target, body)
		if err != nil {
			return false, err
		}
		staged = append(staged, p)
	}
	for i, target := range []string{s.Path, orig} {
		if err := os.Rename(staged[i], target); err != nil {
			return false, err
		}
	}
	staged = nil
	return true, nil
}

// stageFile writes body to a new file of mode 0644 beside target, synced, and returns its name.
func stageFile(target string, body []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*")
	if err != nil {
		return "", err
	}
	err = geoWrite(f, body)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// rows is a list of objects of a decoded projection.
func rows(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// GeoCatalog is the geo-catalog resource body (spec §7): the rows of the country folder's .geo_catalog, which the GeoIP
// conversion publishes with the country lists, and an "asn" row per line of the ASN table asnTable
// (pfblockerng_asn.txt), {"kind": "asn", "asn": <number>, "name": <text>}, canonical (members in byte order, each once).
// The Outpost renders the GeoIP pages from the page, country and reputation rows and skips the asn rows
// (pfb_geoip_render_catalog()); "AS<asn> [ <name> ]" is the table's line. A table line of another shape, or whose number
// is not a 32-bit AS number written as Go writes it, is left out; a name that is not UTF-8 has each bad byte replaced by
// U+FFFD. A missing table gives no asn row; a missing .geo_catalog is an error (no conversion has published one).
func GeoCatalog(ccDir, asnTable string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(ccDir, ".geo_catalog"))
	if err != nil {
		return nil, err
	}
	var members []string
	if s := strings.TrimSuffix(string(b), "\n"); s != "" {
		members = strings.Split(s, "\n")
	}
	table, err := os.ReadFile(asnTable)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(string(table), "\n") {
		rest, ok := strings.CutPrefix(line, "AS")
		num, name, ok2 := strings.Cut(rest, " [ ")
		name, ok3 := strings.CutSuffix(name, " ]")
		n, err := strconv.ParseUint(num, 10, 32)
		if !ok || !ok2 || !ok3 || err != nil || strconv.FormatUint(n, 10) != num {
			continue
		}
		row, _ := json.Marshal(struct {
			Kind string `json:"kind"`
			ASN  uint64 `json:"asn"`
			Name string `json:"name"`
		}{"asn", n, name})
		// A member holds no control character: JSON escapes those below U+0020, not DEL and the C1 controls.
		var line strings.Builder
		for _, r := range string(row) {
			if unicode.IsControl(r) {
				fmt.Fprintf(&line, `\u%04x`, r)
			} else {
				line.WriteRune(r)
			}
		}
		members = append(members, line.String())
	}
	return resources.Canonical(members)
}
