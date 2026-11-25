// The ini options nothing sets (issue #4036, owner 2026-11-25): python_blocking (always on), python_tld_seg (always 1),
// python_idn (a copy of idn_mode, which the writer always sets) and regex_warn_ms (never written) are not read. A
// module behaves as the writer's constants make it behave, whatever an ini says for them.
package decider

import (
	"reflect"
	"testing"
)

func TestTheIniOptionsNothingSetsAreNotRead(t *testing.T) {
	base := []string{"python_enable = on", "idn_mode = confusable"}
	// What pfb_unbound_python_ini() writes for them with IDN in confusable mode.
	asWritten := modMain(t, append(base, "python_blocking = on", "python_tld_seg = 1", "python_idn = off")...)
	other := modMain(t, append(base, "python_blocking = off", "python_tld_seg = 7", "python_idn = on", "regex_warn_ms = 0.5")...)
	a, b := asWritten.evaluateCfg(asWritten.snapshot.Load()), other.evaluateCfg(other.snapshot.Load())
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
