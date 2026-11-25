// The ini options nothing set to another value (issue #4036, owner 2026-11-25): python_blocking (always on),
// python_tld_seg (always 1), python_idn (a copy of idn_mode) and regex_warn_ms (never written) are not read. A module
// behaves as the writer's constants made it behave, whatever an ini says for them.
package decider

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTheIniOptionsNothingSetsAreNotRead(t *testing.T) {
	base := []string{"python_enable = on", "idn_mode = confusable"}
	// What pfb_unbound_python_ini() wrote for them with IDN in confusable mode, and other values, in one module
	// directory: the settings the module loads are the same.
	dir := modIniDir(t, "[MAIN]\n"+strings.Join(append(base, "python_blocking = on", "python_tld_seg = 1", "python_idn = off"), "\n")+"\n")
	asWritten := modMust(t, dir)
	other := []string{"python_blocking = off", "python_tld_seg = 7", "python_idn = on", "regex_warn_ms = 0.5"}
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\n"+strings.Join(append(base, other...), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withOther := modMust(t, dir)
	if a, b := *asWritten.snapshot.Load().settings, *withOther.snapshot.Load().settings; !reflect.DeepEqual(a, b) {
		t.Errorf("the options change the settings:\nas written %+v\nother      %+v", a, b)
	}
	a, b := asWritten.evaluateCfg(asWritten.snapshot.Load()), withOther.evaluateCfg(withOther.snapshot.Load())
	a.regex, b.regex = nil, nil
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the options change the decisions:\nas written %+v\nother      %+v", a, b)
	}

	// Without idn_mode, IDN is off: python_idn does not stand in for it.
	m := modMain(t, "python_enable = on", "python_idn = on")
	if s := m.snapshot.Load().settings; s.idnMode != IdnModeOff || s.pythonBlacklist {
		t.Errorf("idnMode %q, blacklist %v; want IDN off", s.idnMode, s.pythonBlacklist)
	}
}
