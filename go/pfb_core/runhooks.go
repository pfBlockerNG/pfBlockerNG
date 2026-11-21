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
// of when, read through backend, run once by runner with the context read from stdin. It needs no Core API, takes no
// lock and publishes nothing. Every line and all hook output go to stderr, the main log; under the uninstall lifecycle
// stdout gets a copy, the console of the package operation. The status is 0 once the hooks ran, whatever they did; 2
// for a context outside the vocabulary and 1 for settings that cannot be read, when nothing runs.
func runHooks(ctx context.Context, when string, backend settings.Backend, kind string, runner hooks.Runner,
	stdin io.Reader, stdout, stderr io.Writer) int {
	logger := log.New(stderr, "pfb_core: ", log.LstdFlags)
	c, err := hookContext(when, stdin)
	if err != nil {
		logger.Printf("refused the hook context: %v", err)
		return 2
	}
	value, err := func() (map[string]any, error) {
		store, err := settings.Load(backend, settings.Production())
		if err != nil {
			return nil, err
		}
		return store.GetClear("hooks")
	}()
	if err != nil {
		logger.Printf("cannot read the hooks from the %s backend: %v", kind, err)
		return 1
	}
	runner.Log = stderr
	if c.Lifecycle == "uninstall" { // pfb_run_streams_to_stdout(): a package lifecycle's console sees the main log
		runner.Log = io.MultiWriter(console{stdout}, stderr)
	}
	runner.Run(ctx, when, hooks.Rows(value), c)
	return 0
}

// console is the stdout copy of the main log: a failed write is dropped, so that a closed console never stops the log.
type console struct{ io.Writer }

func (c console) Write(p []byte) (int, error) {
	c.Writer.Write(p)
	return len(p), nil
}

// hookContext reads the one JSON object of a --run-hooks context: trigger, lifecycle (uninstall), pkgOp (install,
// upgrade, reinstall, delete or empty) and, for post only, ipChanged, dnsblChanged (bools), changedIpAliases and
// changedDnsblGroups (strings). Any other name, a value of another type or outside the vocabulary, a NUL in a string,
// or input that is not exactly one object is an error. post also gets PFB_STATUS, the reserved ok.
func hookContext(when string, in io.Reader) (hooks.Context, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxHookContext+1))
	if err != nil {
		return hooks.Context{}, err
	}
	if len(data) > maxHookContext {
		return hooks.Context{}, errors.New("the input is over 16 MiB")
	}
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&fields); err != nil || fields == nil {
		return hooks.Context{}, errors.New("the input is not one JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return hooks.Context{}, errors.New("the input holds more than one JSON object")
	}
	c := hooks.Context{Vars: map[string]string{}}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		var v any
		json.Unmarshal(fields[field], &v) // a whole object's member: valid JSON
		s, isString := v.(string)
		if isString && strings.Contains(s, "\x00") {
			return hooks.Context{}, fmt.Errorf("%s holds a NUL", field)
		}
		f, known := hookFields[field]
		switch {
		case field == "lifecycle":
			if s != "uninstall" {
				return hooks.Context{}, errors.New(`lifecycle must be "uninstall" or absent`)
			}
			c.Lifecycle = s
		case field == "pkgOp":
			if !isString || !slices.Contains([]string{"", "install", "upgrade", "reinstall", "delete"}, s) {
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
			c.Vars[f.name] = map[bool]string{true: "1", false: "0"}[b]
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
