// Translation of the part of Python 3.11's configparser that pfb_unbound.py's init_standard depends on: the
// default ConfigParser() (delimiters '=' and ':', full-line comments '#' and ';', strict, empty lines kept in
// values, DEFAULT section, BasicInterpolation) reading one file. PHP writes pfb_unbound.ini for exactly these
// semantics, so a Go reader that parsed it "almost" the same would split the two decisions apart.
package decider

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

const (
	defaultSection          = "DEFAULT"
	MAX_INTERPOLATION_DEPTH = 10
)

// configError stands for configparser.Error and its subclasses, valueError for Python's ValueError (int(), float(),
// getboolean): init_standard swallows only the latter.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

type valueError struct{ msg string }

func (e *valueError) Error() string { return e.msg }

var booleanStates = map[string]bool{
	"1": true, "yes": true, "true": true, "on": true,
	"0": false, "no": false, "false": false, "off": false,
}

type configParser struct {
	defaults map[string]string
	sections map[string]map[string]string
	order    map[string][]string // the option names of the DEFAULT section and of each section, in file order
}

func newConfigParser() *configParser {
	return &configParser{defaults: map[string]string{}, sections: map[string]map[string]string{}, order: map[string][]string{}}
}

func pyStrip(s string) string { return strings.TrimFunc(s, pysem.IsSpace) }

// optionxform is str.lower.
func optionxform(option string) string { return pysem.Lower(option) }

// read is ConfigParser.read([path], encoding="utf-8"): a file that cannot be opened is skipped without an error, a
// file that is not UTF-8 is a read error, and the text gets universal newlines.
// shortcut: Python decodes in 8 KiB chunks and parses the lines of the chunks before the bad byte; this decodes the
// whole file first, so a non-UTF-8 file leaves the config empty. They agree for files under 8 KiB; upgrade if the
// ini grows past it.
func (c *configParser) read(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if !utf8.Valid(data) {
		bad := 0
		for bad < len(data) {
			r, size := utf8.DecodeRune(data[bad:])
			if r == utf8.RuneError && size == 1 {
				break
			}
			bad += size
		}
		return &valueError{fmt.Sprintf("'utf-8' codec can't decode byte 0x%02x in position %d: invalid data", data[bad], bad)}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	return c.readString(strings.ReplaceAll(text, "\r", "\n"), path)
}

// sectionHeader is SECTCRE.match: `\[(?P<header>.+)\]`, greedy to the last ']', anything after it ignored.
func sectionHeader(value string) (string, bool) {
	if !strings.HasPrefix(value, "[") {
		return "", false
	}
	end := strings.LastIndex(value, "]")
	if end < 2 {
		return "", false
	}
	return value[1:end], true
}

func indentLevelOf(line string) int {
	n := 0
	for _, r := range line {
		if !pysem.IsSpace(r) {
			break
		}
		n++
	}
	return n
}

// readString is read_string, i.e. the body of RawConfigParser._read. Like Python it keeps whatever it parsed
// when it fails: a parsing error is only reported after the whole text was read, the other errors stop the read.
func (c *configParser) readString(text, source string) error {
	var values []*multilineValue
	var current *multilineValue
	defer func() { joinMultilineValues(values) }()
	elementsAdded := map[string]bool{}
	var cursect map[string]string
	sectname, optname := "", ""
	indentLevel := 0
	var parsingErrors *configError

	handleError := func(lineno int, line string) {
		if parsingErrors == nil {
			parsingErrors = &configError{fmt.Sprintf("Source contains parsing errors: %q", source)}
		}
		parsingErrors.msg += fmt.Sprintf("\n\t[line %2d]: %q", lineno, line)
	}

	// SplitAfter ends with an empty piece when the text ends in "\n"; it reads as one more blank line, which the join drops.
	for i, line := range strings.SplitAfter(text, "\n") {
		lineno := i + 1
		value := pyStrip(line)
		fullLineComment := strings.HasPrefix(value, "#") || strings.HasPrefix(value, ";")
		if fullLineComment {
			value = ""
		}
		if value == "" {
			// a blank line (not a comment) is part of a multi-line value; the trailing ones are dropped at the join
			if !fullLineComment && cursect != nil && optname != "" {
				current.lines = append(current.lines, "")
			}
			continue
		}
		curIndentLevel := indentLevelOf(line)
		if cursect != nil && optname != "" && curIndentLevel > indentLevel {
			current.lines = append(current.lines, value)
			continue
		}
		indentLevel = curIndentLevel
		if header, ok := sectionHeader(value); ok {
			sectname = header
			if _, exists := c.sections[sectname]; exists {
				if elementsAdded["s\x00"+sectname] {
					return &configError{fmt.Sprintf("While reading from %q [line %2d]: section %q already exists", source, lineno, sectname)}
				}
				cursect = c.sections[sectname]
				elementsAdded["s\x00"+sectname] = true
			} else if sectname == defaultSection {
				cursect = c.defaults
			} else {
				cursect = map[string]string{}
				c.sections[sectname] = cursect
				elementsAdded["s\x00"+sectname] = true
			}
			optname = "" // so sections can't start with a continuation line
			continue
		}
		if cursect == nil {
			return &configError{fmt.Sprintf("File contains no section headers.\nfile: %q, line: %d\n%q", source, lineno, line)}
		}
		delimiter := strings.IndexAny(value, "=:")
		if delimiter < 0 {
			handleError(lineno, line)
			continue
		}
		if delimiter == 0 {
			handleError(lineno, line)
		}
		optname = optionxform(strings.TrimRightFunc(value[:delimiter], pysem.IsSpace))
		if elementsAdded["o\x00"+sectname+"\x00"+optname] {
			return &configError{fmt.Sprintf("While reading from %q [line %2d]: option %q in section %q already exists", source, lineno, optname, sectname)}
		}
		elementsAdded["o\x00"+sectname+"\x00"+optname] = true
		c.order[sectname] = append(c.order[sectname], optname)
		current = &multilineValue{cursect, optname, []string{pyStrip(value[delimiter+1:])}}
		values = append(values, current)
	}
	if parsingErrors != nil {
		return parsingErrors
	}
	return nil
}

// multilineValue is the lines of one option's value; Python keeps them in a list and joins them once at the end.
type multilineValue struct {
	options map[string]string // the DEFAULT or section options the value belongs to
	name    string
	lines   []string
}

// joinMultilineValues is _join_multiline_values: a value is its lines joined with "\n", minus the trailing blank ones.
func joinMultilineValues(values []*multilineValue) {
	for _, value := range values {
		value.options[value.name] = strings.TrimRightFunc(strings.Join(value.lines, "\n"), pysem.IsSpace)
	}
}

func (c *configParser) hasSection(section string) bool {
	_, ok := c.sections[section]
	return ok
}

func (c *configParser) hasOption(section, option string) bool {
	option = optionxform(option)
	if section == "" || section == defaultSection {
		_, ok := c.defaults[option]
		return ok
	}
	options, ok := c.sections[section]
	if !ok {
		return false
	}
	if _, ok := options[option]; ok {
		return true
	}
	_, ok = c.defaults[option]
	return ok
}

// lookup is the section's value of option, else DEFAULT's: Python's ChainMap(vars, section, defaults) without vars.
func (c *configParser) lookup(section string) (func(option string) (string, bool), error) {
	sectiondict, ok := c.sections[section]
	if !ok && section != defaultSection {
		return nil, &configError{fmt.Sprintf("No section: %q", section)}
	}
	return func(option string) (string, bool) {
		if v, ok := sectiondict[option]; ok {
			return v, true
		}
		v, ok := c.defaults[option]
		return v, ok
	}, nil
}

// find is the lookup of option in section plus the option's uninterpolated value.
func (c *configParser) find(section, option string) (func(string) (string, bool), string, error) {
	lookup, err := c.lookup(section)
	if err != nil {
		return nil, "", err
	}
	value, ok := lookup(option)
	if !ok {
		return nil, "", &configError{fmt.Sprintf("No option %q in section: %q", option, section)}
	}
	return lookup, value, nil
}

func (c *configParser) getRaw(section, option string) (string, error) {
	_, rawval, err := c.find(section, optionxform(option))
	return rawval, err
}

// items is ConfigParser.items(section, raw=raw): the DEFAULT options first, then the section's own that DEFAULT lacks,
// each in file order, a section value overriding a default's value but not its position. Without raw every value is
// interpolated, so a bad '%' in any value of the section is an error here, as it is in Python.
func (c *configParser) items(section string, raw bool) ([][2]string, error) {
	lookup, err := c.lookup(section)
	if err != nil {
		return nil, err
	}
	names := slices.Clone(c.order[defaultSection])
	for _, name := range c.order[section] {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	pairs := make([][2]string, 0, len(names))
	for _, name := range names {
		value, _ := lookup(name)
		if !raw {
			var accum strings.Builder
			if err := interpolateSome(name, section, &accum, value, value, lookup, 1); err != nil {
				return nil, err
			}
			value = accum.String()
		}
		pairs = append(pairs, [2]string{name, value})
	}
	return pairs, nil
}

// get is ConfigParser.get with BasicInterpolation (before_get).
func (c *configParser) get(section, option string) (string, error) {
	option = optionxform(option)
	lookup, rawval, err := c.find(section, option)
	if err != nil {
		return "", err
	}
	var accum strings.Builder
	if err := interpolateSome(option, section, &accum, rawval, rawval, lookup, 1); err != nil {
		return "", err
	}
	return accum.String(), nil
}

// interpolateSome is BasicInterpolation._interpolate_some; rawval is the option's uninterpolated value, quoted by
// the errors.
func interpolateSome(option, section string, accum *strings.Builder, rest, rawval string, lookup func(string) (string, bool), depth int) error {
	if depth > MAX_INTERPOLATION_DEPTH {
		return &configError{fmt.Sprintf("Recursion limit exceeded in value substitution: option %q in section %q contains an interpolation key which cannot be substituted in %d steps. Raw value: %q",
			option, section, MAX_INTERPOLATION_DEPTH, rawval)}
	}
	for rest != "" {
		p := strings.Index(rest, "%")
		if p < 0 {
			accum.WriteString(rest)
			return nil
		}
		accum.WriteString(rest[:p])
		rest = rest[p:]
		c := ""
		if len(rest) > 1 {
			c = rest[1:2]
		}
		switch c {
		case "%":
			accum.WriteString("%")
			rest = rest[2:]
		case "(":
			// _KEYCRE: %\(([^)]+)\)s
			end := strings.IndexByte(rest, ')')
			if end < 3 || end+1 >= len(rest) || rest[end+1] != 's' {
				return &configError{"bad interpolation variable reference " + strconv.Quote(rest)}
			}
			variable := optionxform(rest[2:end])
			rest = rest[end+2:]
			v, ok := lookup(variable)
			if !ok {
				return &configError{fmt.Sprintf("Bad value substitution: option %q in section %q contains an interpolation key %q which is not a valid option name. Raw value: %q",
					option, section, variable, rawval)}
			}
			if strings.Contains(v, "%") {
				if err := interpolateSome(option, section, accum, v, rawval, lookup, depth+1); err != nil {
					return err
				}
			} else {
				accum.WriteString(v)
			}
		default:
			return &configError{"'%' must be followed by '%' or '(', found: " + strconv.Quote(rest)}
		}
	}
	return nil
}

func (c *configParser) getboolean(section, option string) (bool, error) {
	value, err := c.get(section, option)
	if err != nil {
		return false, err
	}
	state, ok := booleanStates[pysem.Lower(value)]
	if !ok {
		return false, &valueError{"Not a boolean: " + value}
	}
	return state, nil
}

func (c *configParser) getint(section, option string) (int64, error) {
	value, err := c.get(section, option)
	if err != nil {
		return 0, err
	}
	v, err := pysem.Int(value)
	if err != nil {
		return 0, &valueError{err.Error()}
	}
	return v, nil
}

func (c *configParser) getfloat(section, option string) (float64, error) {
	value, err := c.get(section, option)
	if err != nil {
		return 0, err
	}
	v, ok := pyFloat(value)
	if !ok {
		return 0, &valueError{"could not convert string to float: '" + value + "'"}
	}
	return v, nil
}

// pyFloat is float(s). Go's ParseFloat also reads hex floats, which float() rejects, and wants no underscores;
// Python allows one between digits. shortcut: a signed "nan" and non-ASCII digits, which Python accepts, are
// rejected; neither can come from a PHP-written ini.
func pyFloat(s string) (float64, bool) {
	s = pyStrip(s)
	if s == "" || strings.ContainsAny(s, "xXpP") {
		return 0, false
	}
	if strings.Contains(s, "_") {
		digit := func(b byte) bool { return b >= '0' && b <= '9' }
		for i := range len(s) {
			if s[i] == '_' && (i == 0 || i == len(s)-1 || !digit(s[i-1]) || !digit(s[i+1])) {
				return 0, false
			}
		}
		s = strings.ReplaceAll(s, "_", "")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) { // float("1e999") is inf, not an error
		return 0, false
	}
	return v, true
}
