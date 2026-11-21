package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

const maxHookContext = 16 << 20 // the stdin a context may take

// hookFields are the context fields of `--run-hooks` that become PFB_* values: the name, whether only post takes it,
// and whether it is a flag (a JSON bool, "1" or "0") rather than a string.
var hookFields = map[string]struct {
	name       string
	post, flag bool
}{
	"trigger":            {"TRIGGER", false, false},
	"ipChanged":          {"IP_CHANGED", true, true},
	"dnsblChanged":       {"DNSBL_CHANGED", true, true},
	"changedIpAliases":   {"CHANGED_IP_ALIASES", true, false},
	"changedDnsblGroups": {"CHANGED_DNSBL_GROUPS", true, false},
}

// runHooks is `pfb-core --run-hooks <pre|post>` (docs/misc/core-api-protocol.md "Hooks outside an Update"): the hooks
// of when, read through backend from the hooks projection alone, run once by runner with the context read from stdin.
// It needs no Core API, takes no lock and publishes nothing. Every line and all hook output go to stderr, the main log;
// under the uninstall lifecycle stdout gets a copy, the console of the package operation. The status is 0 once the
// hooks ran, whatever they did, or when the settings are not initialized (no hooks); 2 for a context outside the
// vocabulary and 1 for settings that cannot be read, when nothing runs; 1 when ctx ended the run.
func runHooks(ctx context.Context, when string, backend settings.Backend, kind string, runner hooks.Runner,
	stdin io.Reader, stdout, stderr io.Writer) int {
	logger := log.New(stderr, "pfb_core: ", log.LstdFlags)
	c, err := hookContext(when, stdin)
	if err != nil {
		logger.Printf("refused the hook context: %v", err)
		return 2
	}
	schema := settings.Production()
	schema.Projections = slices.DeleteFunc(schema.Projections, func(p settings.Projection) bool { return p.ID != "hooks" })
	store, err := settings.Load(hooksOnly{backend}, schema)
	if err != nil {
		logger.Printf("cannot read the hooks from the %s backend: %v", kind, err)
		return 1
	}
	value, err := store.GetClear("hooks")
	if err != nil { // an uninitialized Core, which the daemon serves: it has no hooks
		logger.Printf("no hooks run: %v", err)
		return 0
	}
	runner.Log = stderr
	if c.Lifecycle == "uninstall" { // pfb_run_streams_to_stdout(): a package lifecycle's console sees the main log
		runner.Log = io.MultiWriter(stderr, console{stdout})
	}
	runner.Run(ctx, when, hooks.Rows(value), c)
	if ctx.Err() != nil { // cancelled: the hooks did not all run
		return 1
	}
	return 0
}

// hooksOnly reads a backend for its hooks projection alone: what the others hold is not the one-shot's to refuse.
type hooksOnly struct{ settings.Backend }

func (b hooksOnly) Read(ctx context.Context) (settings.Stored, error) {
	s, err := b.Backend.Read(ctx)
	s.Projections = map[string]map[string]json.RawMessage{"hooks": s.Projections["hooks"]}
	return s, err
}

// console is the stdout copy of the main log: a failed write is dropped, so that a closed console never stops the log.
type console struct{ io.Writer }

func (c console) Write(p []byte) (int, error) {
	c.Writer.Write(p)
	return len(p), nil
}

// hookContext reads the one JSON object of a --run-hooks context: trigger, lifecycle (uninstall), pkgOp (install,
// upgrade, reinstall, delete or empty) and, for post only, ipChanged, dnsblChanged (bools), changedIpAliases and
// changedDnsblGroups (strings). Any other name, a name given twice, a value of another type or outside the vocabulary,
// a NUL or a lone surrogate escape in a string, or input that is not exactly one object in UTF-8 is an error. post also
// gets PFB_STATUS, the reserved ok.
func hookContext(when string, in io.Reader) (hooks.Context, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxHookContext+1))
	if err != nil {
		return hooks.Context{}, err
	}
	if len(data) > maxHookContext {
		return hooks.Context{}, errors.New("the input is over 16 MiB")
	}
	if !utf8.Valid(data) {
		return hooks.Context{}, errors.New("the input is not UTF-8")
	}
	notObject := errors.New("the input is not one JSON object")
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return hooks.Context{}, notObject
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		name, err := dec.Token()
		var raw json.RawMessage
		if err != nil || dec.Decode(&raw) != nil {
			return hooks.Context{}, notObject
		}
		if _, twice := fields[name.(string)]; twice {
			return hooks.Context{}, fmt.Errorf("%q is given twice", name)
		}
		fields[name.(string)] = raw
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return hooks.Context{}, notObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return hooks.Context{}, errors.New("the input holds more than one JSON object")
	}
	// decoding turns a lone surrogate escape into U+FFFD: one the input does not hold itself came from such an escape
	replacement := bytes.Contains(data, []byte("\uFFFD")) || bytes.Contains(bytes.ToLower(data), []byte(`\ufffd`))
	c := hooks.Context{Vars: map[string]string{}}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		var v any
		json.Unmarshal(fields[field], &v) // a whole object's member: valid JSON
		s, isString := v.(string)
		if isString && strings.Contains(s, "\x00") {
			return hooks.Context{}, fmt.Errorf("%s holds a NUL", field)
		}
		if isString && !replacement && strings.ContainsRune(s, utf8.RuneError) {
			return hooks.Context{}, fmt.Errorf("%s holds a lone surrogate", field)
		}
		f, known := hookFields[field]
		switch {
		case field == "lifecycle":
			if s != "uninstall" {
				return hooks.Context{}, errors.New(`lifecycle must be "uninstall" or absent`)
			}
			c.Lifecycle = s
		case field == "pkgOp":
			if !isString || s != "" && !slices.Contains(hooks.PkgOps, s) {
				return hooks.Context{}, errors.New(`pkgOp must be one of "install", "upgrade", "reinstall", "delete" or ""`)
			}
			c.PkgOp = s
		case !known:
			return hooks.Context{}, fmt.Errorf("%q is not a context field", field)
		case f.post && when != "post":
			return hooks.Context{}, fmt.Errorf("%s is a post field", field)
		case f.flag:
			b, ok := v.(bool)
			if !ok {
				return hooks.Context{}, fmt.Errorf("%s must be true or false", field)
			}
			c.Vars[f.name] = "0"
			if b {
				c.Vars[f.name] = "1"
			}
		case !isString:
			return hooks.Context{}, fmt.Errorf("%s must be a string", field)
		default:
			c.Vars[f.name] = s
		}
	}
	if when == "post" {
		c.Vars["STATUS"] = "ok" // reserved: no pass-wide status exists
	}
	return c, nil
}
