package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tzif is a time zone file (TZif version 1) holding one zone: a fixed offset from UTC with no transitions.
func tzif(t *testing.T, offsetSeconds int32, abbrev string) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("TZif")
	b.WriteByte(0) // version 1
	b.Write(make([]byte, 15))
	for _, n := range []uint32{0, 0, 0, 0, 1, uint32(len(abbrev) + 1)} { // isutcnt isstdcnt leapcnt timecnt typecnt charcnt
		if err := binary.Write(&b, binary.BigEndian, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := binary.Write(&b, binary.BigEndian, offsetSeconds); err != nil {
		t.Fatal(err)
	}
	b.WriteByte(0) // not DST
	b.WriteByte(0) // abbreviation starts at 0
	b.WriteString(abbrev)
	b.WriteByte(0)
	return b.Bytes()
}

// startZoned starts a Core with the held quarter hour, the update program and the zone file at zonePath, over a state
// directory in which the daily and weekly Extras have completed right now: nothing is due, so each next due time is the next
// occurrence of its slot (the default one: 00:00 local) after now, in whatever zone the call is made.
func startZoned(t *testing.T, zonePath string) *runningCore {
	t.Helper()
	holdQuarters(t)
	f := newFakeUpdate(t)
	dir := scratchDir(t)
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	done := fmt.Sprintf(`{"last_completed_occurrence":%d,"completion_outcome":"success"}`, time.Now().Unix())
	seed := `{"schema":1,"items":{"extra:dcc":` + done + `,"extra:bl":` + done + `}}`
	if err := os.WriteFile(filepath.Join(state, "schedule_state.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	c := startCore(t, dir, "--update-cmd", f.path, "--zoneinfo", zonePath)
	c.initialize()
	return c
}

// dccNextDue is when GetSchedule says the daily Extra is next due.
func (c *runningCore) dccNextDue() int64 {
	c.t.Helper()
	got := c.post("GetSchedule", `{}`)
	var v struct {
		Extras map[string]struct {
			NextDue int64 `json:"nextDue"`
		} `json:"extras"`
	}
	if got.status != http.StatusOK || json.Unmarshal(got.body, &v) != nil {
		c.t.Fatalf("GetSchedule = %d %s", got.status, got.body)
	}
	return v.Extras["extra:dcc"].NextDue
}

// midnightAfter is the first 00:00 of loc after the present.
func midnightAfter(loc *time.Location) int64 {
	d := time.Now().In(loc)
	return time.Date(d.Year(), d.Month(), d.Day()+1, 0, 0, 0, 0, loc).Unix()
}

func writeZone(t *testing.T, path string, offsetHours int) *time.Location {
	t.Helper()
	if err := os.WriteFile(path, tzif(t, int32(offsetHours*3600), "TST"), 0o600); err != nil {
		t.Fatal(err)
	}
	return time.FixedZone("TST", offsetHours*3600)
}

// A change of the host's time zone reaches the schedule without a restart: the file is read at every evaluation.
func TestTheZoneinfoFileIsReadAtEveryEvaluation(t *testing.T) {
	zonePath := filepath.Join(scratchDir(t), "localtime")
	utc := writeZone(t, zonePath, 0)
	c := startZoned(t, zonePath)

	if got, want := c.dccNextDue(), midnightAfter(utc); got != want {
		t.Fatalf("at UTC the daily Extra is next due at %s, want %s", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
	}
	east := writeZone(t, zonePath, 5)
	if got, want := c.dccNextDue(), midnightAfter(east); got != want {
		t.Errorf("after the zone file changed to UTC+5 the daily Extra is next due at %s, want %s", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
	}
	west := writeZone(t, zonePath, -8)
	if got, want := c.dccNextDue(), midnightAfter(west); got != want {
		t.Errorf("after the zone file changed to UTC-8 the daily Extra is next due at %s, want %s", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
	}
}

// A zone file Core cannot use is the host's local zone, said once per outage: not at every evaluation, and again when the file
// breaks anew.
func TestAnUnusableZoneinfoFallsBackToTheLocalZoneAndSaysSoOncePerOutage(t *testing.T) {
	zonePath := filepath.Join(scratchDir(t), "localtime") // absent
	c := startZoned(t, zonePath)
	const said = "the time zone file"

	for range 2 {
		if got, want := c.dccNextDue(), midnightAfter(time.Local); got != want {
			t.Fatalf("without a zone file the daily Extra is next due at %s, want %s (the local zone)", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
		}
	}
	if n := strings.Count(c.stderr.String(), said); n != 1 {
		t.Errorf("the log names the unusable zone file %d times over two evaluations, want 1:\n%s", n, c.stderr.String())
	}
	east := writeZone(t, zonePath, 5)
	if got, want := c.dccNextDue(), midnightAfter(east); got != want {
		t.Errorf("once the zone file exists the daily Extra is next due at %s, want %s", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
	}
	if err := os.WriteFile(zonePath, []byte("not a time zone"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got, want := c.dccNextDue(), midnightAfter(time.Local); got != want {
			t.Fatalf("with a damaged zone file the daily Extra is next due at %s, want %s (the local zone)", time.Unix(got, 0).UTC(), time.Unix(want, 0).UTC())
		}
	}
	if n := strings.Count(c.stderr.String(), said); n != 2 {
		t.Errorf("the log names the unusable zone file %d times over two outages, want 2:\n%s", n, c.stderr.String())
	}
}

// The program's exit status 75 is a deferral: the Update is skipped, and nothing it wrote on fd 3 is recorded.
func TestAnUpdateTheProgramDefersIsSkippedAndRecordsNothing(t *testing.T) {
	c, f := startUpdateCore(t)
	c.initialize()
	f.result(`{"version":1,"outcomes":{"ipv4:Feed1_v4":"success"},"attempted":["ipv4:Feed1_v4"],"geoipReady":false}`)
	f.exit(75)
	f.release()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"d1","trigger":"retry"}`), http.StatusOK, `{}`)

	v := c.waitFinished("retry")
	if v.Update.Result != "skipped" || v.Update.FinishedAt == nil {
		t.Errorf("GetUpdate = %+v, want a finished Update whose result is skipped", v.Update)
	}
	state, err := os.ReadFile(filepath.Join(c.state, "schedule_state.json"))
	if err != nil || strings.Contains(string(state), "last_completed_occurrence") || strings.Contains(string(state), "last_successful_check") {
		t.Errorf("schedule_state.json = %q (%v), want the reservation only: nothing the deferred Update reported", state, err)
	}
	if strings.Contains(c.stderr.String(), "Update failed") {
		t.Errorf("the log calls the deferral a failure:\n%s", c.stderr.String())
	}
	// the gate is free again: a manual Update is admitted
	f.exit(0)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"d2","trigger":"manual"}`), http.StatusOK, `{}`)
	if end := c.waitFinished("manual"); end.Update.Result != "success" {
		t.Errorf("GetUpdate = %+v, want the next Update to end success", end.Update)
	}
}

// Stopping Core ends a running Update before the server goes: the program, told to stop, still sees the socket, and a client
// asking in that moment is answered, never met by a closed socket.
func TestStoppingCoreEndsTheRunningUpdateBeforeTheServerShutsDown(t *testing.T) {
	holdQuarters(t)
	dir := scratchDir(t)
	socket := filepath.Join(dir, "run", "api.sock") // where startCore puts it
	prog := t.TempDir()
	script := "#!/bin/sh\nD='" + prog + "'\nS='" + socket + "'\n" + `cat > "$D/req"
trap 'if [ -S "$S" ]; then echo present > "$D/at_term"; else echo gone > "$D/at_term"; fi; exit 0' TERM
echo "update program started"
while :; do sleep 0.05; done
`
	path := filepath.Join(prog, "update.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	c := startCore(t, dir, "--update-cmd", path)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"s1","trigger":"manual"}`), http.StatusOK, `{}`)
	c.waitLog("", "update program started")

	if code := c.stop(); code != 0 {
		t.Fatalf("run = %d after the stop, want 0; stderr:\n%s", code, c.stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(prog, "at_term"))
	if err != nil {
		t.Fatalf("the program was never told to stop: %v", err)
	}
	if strings.TrimSpace(string(got)) != "present" {
		t.Errorf("when the program was told to stop the socket was %q, want present: the Update must end before the server shuts down", got)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after run returned: %v", err)
	}
}
