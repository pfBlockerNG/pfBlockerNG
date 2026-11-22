package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// Loop selects the Core Updater loop (docs/specs/go-updater-pipeline.md section 3, issue #4038) for an Update and holds the
// paths it needs, copied by the Core API from its flags into the worker's state. It holds no setting: the loop reads the
// settings itself. A Command without one runs its program as before. Every path is absolute and clean, or empty.
type Loop struct {
	SettingsCmd   string   `json:"settingsCmd,omitempty"` // the settings adapter; empty: settings.json in the state directory
	ResourceDir   string   `json:"resourceDir,omitempty"`
	FeedLocalDirs []string `json:"feedLocalDirs,omitempty"`
	ScriptDirs    []string `json:"scriptDirs,omitempty"`
	RsyncBin      string   `json:"rsyncBin,omitempty"`
	HookDir       string   `json:"hookDir,omitempty"`
	PythonWrapper string   `json:"pythonWrapper,omitempty"`
	MainLog       string   `json:"mainLog,omitempty"` // the package's main log the loop's lines are appended to; empty: none
}

func (l *Loop) validate() error {
	paths := append([]string{l.SettingsCmd, l.ResourceDir, l.RsyncBin, l.HookDir, l.PythonWrapper, l.MainLog}, l.FeedLocalDirs...)
	for _, p := range append(paths, l.ScriptDirs...) {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || strings.IndexFunc(p, unicode.IsControl) >= 0) {
			return fmt.Errorf("the loop path %q is not absolute and clean", p)
		}
	}
	return nil
}

// boundary is the fault-injection seam: called at every stage boundary with the name of the stage about to run, and with
// "end" after the last. Production never sets it.
var boundary = func(name string) {}

// stages are the Core Updater's stages from the snapshot on, in the spec's order; a nil run is a stage not written yet.
// Stage 17, the feed outcomes, is written as each feed finishes and has no boundary.
var stages = []struct {
	name string
	run  func(*updater) error
}{
	{"snapshot", (*updater).snapshot}, {"work-list", nil}, {"pre-hook", nil}, {"extras", nil}, {"change-detection", nil},
	{"apply-window", nil}, {"dnsbl", nil}, {"dnsblip", nil}, {"publish-dnsbl", nil}, {"geoip-sets", nil}, {"ip", nil},
	{"recompute", nil}, {"suppression", nil}, {"uber", nil}, {"publish-ip", nil}, {"apply", nil}, {"post-hook", nil},
	{"settle", nil},
}

// updater is one run of the loop. The snapshot and its token stay in memory: nothing of them is written anywhere.
type updater struct {
	loop        Loop
	req         Request
	stateDir    string
	sinks       output.Sinks
	readTimeout time.Duration // the adapter's read bound; 0 is its default
	settings    *settings.Store
	token       json.RawMessage
}

// run runs the stages in order and stops at the first that fails; ErrDeferred is a skipped Update.
func (u *updater) run() error {
	for _, s := range stages {
		boundary(s.name)
		if s.run == nil {
			continue
		}
		if err := s.run(u); err != nil {
			if !errors.Is(err, ErrDeferred) {
				u.sinks.Line(true, "Core Updater: %s failed: %v\n", s.name, err)
			}
			return err
		}
	}
	boundary("end")
	return nil
}

// snapshot reads the settings once, under the lifetime lock the worker holds, and keeps them with the pending token.
func (u *updater) snapshot() error {
	var backend settings.Backend = settings.NewFileBackend(u.stateDir)
	if u.loop.SettingsCmd != "" {
		backend = &settings.AdapterBackend{Path: u.loop.SettingsCmd, ReadTimeout: u.readTimeout}
	}
	st, err := settings.Load(backend, settings.Production())
	if err != nil {
		return fmt.Errorf("the settings cannot be read: %w", err)
	}
	snap, _ := st.Get([]string{"ingest"})
	if !snap.Initialized {
		return errors.New("the settings are not initialized")
	}
	u.settings, u.token = st, st.PendingToken()
	u.sinks.Line(false, "Core Updater: settings revision %d\n", snap.Revision)
	if u.req.Trigger == "scheduled" && snap.Projections[0].Value["scheduledWorkDisabled"] == true {
		u.sinks.Line(false, "Core Updater: the scheduled Update is skipped: scheduled work is disabled\n")
		return ErrDeferred
	}
	return nil
}

// runLoop runs the loop for the worker in the state directory dir, its lines in the transcript log and the main log, and
// records the Update's end in state as an exit status: 0, or 75 for a skipped Update.
func runLoop(dir string, state *workerState, log *os.File) error {
	sinks := output.Sinks{Transcript: log}
	if state.Loop.MainLog != "" {
		main, err := openMainLog(state.Loop.MainLog)
		if err != nil {
			fmt.Fprintf(log, "Core Updater: the main log cannot be used: %v\n", err)
			return err
		}
		defer main.Close()
		sinks.Log = main
	}
	err := (&updater{loop: *state.Loop, req: state.Request, stateDir: dir, sinks: sinks}).run()
	code := 0
	if errors.Is(err, ErrDeferred) {
		code, err = deferredStatus, nil
	}
	if err == nil {
		state.ExitCode = &code
	}
	return err
}

// openMainLog opens path for appending, refusing a link and anything but a regular file before writing.
func openMainLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, nil
}
