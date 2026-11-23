package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/worklist"
)

// Loop selects the Core Updater loop (docs/specs/go-updater-pipeline.md section 3, issue #4038) for an Update and holds the
// paths it needs, copied by the Core API from its flags into the worker's request (update.log.request), never its status. It holds no setting: the loop reads the
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
	// The package's folders the stages work in: the database folder ($pfb['dbdir']: the class folders deny, permit, match
	// and native, original for IP feeds and baselines, dnsbl for DNSBL feeds, the Blacklist providers), the GeoIP share
	// ($pfb['geoipshare']), the country folder ($pfb['ccdir']; empty: cc in the share), the log folder ($pfb['logdir'];
	// empty: the error, Extras and parse-error logs are not written) and the package's own files (dnsbl_psl and the
	// SafeSearch lists). ASNTable is the ASN choices file (pfblockerng_asn.txt), Zoneinfo the time zone file the apply
	// window is read in (--zoneinfo; empty: the local zone).
	DBDir    string `json:"dbDir,omitempty"`
	GeoIPDir string `json:"geoipShareDir,omitempty"`
	CCDir    string `json:"ccDir,omitempty"`
	LogDir   string `json:"logDir,omitempty"`
	PkgDir   string `json:"pkgDir,omitempty"`
	ASNTable string `json:"asnTable,omitempty"`
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// UserAgent is what feed hosts are told (--user-agent), free of control characters.
	UserAgent string `json:"userAgent,omitempty"`
}

// CheckPath refuses a path the loop cannot be given: one that is not absolute and clean, is not valid UTF-8 (the request is
// JSON, which would write each invalid byte as U+FFFD and give the worker another path) or holds a control character.
func CheckPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || !utf8.ValidString(p) || hasControl(p) {
		return errors.New("is not an absolute and clean UTF-8 path free of control characters")
	}
	return nil
}

// validate refuses a loop with a path CheckPath refuses; empty means none for a single path, never for a list item.
func (l *Loop) validate() error {
	if hasControl(l.UserAgent) || !utf8.ValidString(l.UserAgent) {
		return errors.New("the loop's user agent holds a control character or is not UTF-8")
	}
	for _, p := range []string{l.SettingsCmd, l.ResourceDir, l.RsyncBin, l.HookDir, l.PythonWrapper, l.MainLog, l.DBDir, l.GeoIPDir,
		l.CCDir, l.LogDir, l.PkgDir, l.ASNTable, l.Zoneinfo} {
		if err := CheckPath(p); p != "" && err != nil {
			return fmt.Errorf("the loop path %q %w", p, err)
		}
	}
	for _, p := range slices.Concat(l.FeedLocalDirs, l.ScriptDirs) {
		if err := CheckPath(p); err != nil {
			return fmt.Errorf("the loop path %q %w", p, err)
		}
	}
	return nil
}

func hasControl(s string) bool { return strings.IndexFunc(s, unicode.IsControl) >= 0 }

// maxFailure bounds the failure line of a stage: an adapter's stderr tail may run to 4 KiB.
const maxFailure = 300

// boundary is the fault-injection seam: called at every stage boundary with the name of the stage about to run, and with
// "end" after the last. Production never sets it.
var boundary = func(name string) {}

// stages are the Core Updater's stages from the snapshot on, in the spec's order, but for the pre hook, which fires where
// today's pass fires it, once the work list has decided a pass runs; a nil run is a stage another one runs:
// DNSBLIP is built by the DNSBL build of publish-dnsbl, and the recompute, the suppression and the Uber unions by the IP
// sets of publish-ip. Stage 17, the feed outcomes, is written as each feed finishes and has no boundary.
var stages = []struct {
	name string
	run  func(*updater) error
}{
	{"snapshot", (*updater).snapshot}, {"work-list", (*updater).workList}, {"extras", (*updater).extrasStage},
	{"change-detection", (*updater).changeDetection}, {"apply-window", (*updater).applyWindow}, {"pre-hook", (*updater).preHook},
	{"dnsbl", (*updater).dnsblStage}, {"dnsblip", nil}, {"publish-dnsbl", (*updater).publishDNSBLStage},
	{"geoip-sets", (*updater).geoSets}, {"ip", (*updater).ipStage}, {"recompute", nil}, {"suppression", nil}, {"uber", nil},
	{"publish-ip", (*updater).publishIP}, {"apply", (*updater).applyStage}, {"post-hook", (*updater).postHook},
	{"settle", (*updater).settle},
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
	// The worker's: the apply program (Command.Path), the Update log, the lifetime lock the apply's holder inherits, and
	// update.log.result, the outcome lines.
	program, logPath  string
	lock, result, log *os.File

	snap                                         map[string]map[string]any // the projections the stages read
	pending                                      []string                  // the Updater state's pending feeds
	geoMarker, geoFailed                         bool                      // geoip.update at the work list; a GeoIP consumer failed
	store                                        *resources.Store
	stages                                       map[string]*feedstage.Stage
	extras                                       Extras
	extrasOut                                    ExtrasOutcome
	plan                                         worklist.Plan
	changed                                      map[string]bool // the feeds (names) parsed this Update
	markers                                      map[string]bool // Blacklist provider markers: whether a category of it failed
	issues                                       []apply.Issue
	dnsblOut                                     DNSBLOut
	geoSetsOut                                   []GeoSet
	ipOut                                        IPOut
	catalog                                      *apply.Resource
	applied                                      *apply.Result // what the apply reported, when its lines count
	applyErr                                     error         // the apply's failure, returned once its lines are settled
	errors, extrasLog, ipParseLog, dnsblParseLog io.Writer
	closers                                      []io.Closer
}

// run runs the stages in order and stops at the first that fails; ErrDeferred is a skipped Update.
func (u *updater) run() error {
	u.changed, u.markers = map[string]bool{}, map[string]bool{}
	defer func() {
		for _, c := range u.closers {
			c.Close()
		}
	}()
	for _, s := range stages {
		boundary(s.name)
		if s.run == nil {
			continue
		}
		if err := s.run(u); err != nil {
			if !errors.Is(err, ErrDeferred) {
				err = fmt.Errorf("%s failed: %s", s.name, output.OneLine(err.Error(), maxFailure))
				u.sinks.Line(true, "Core Updater: %v\n", err)
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
	// A store that cannot be written fails the Update here, before any stage publishes (issue #4038).
	if u.loop.ResourceDir != "" {
		if err := resources.Open(u.loop.ResourceDir).Writable(); err != nil {
			return fmt.Errorf("the resource store cannot be written: %w", err)
		}
	}
	return nil
}

// runLoop runs the loop for the worker in the state directory dir, its lines in the transcript log and the main log, its
// outcomes in result, and records the Update's end in state as an exit status: 0, or 75 for a skipped Update, and its
// outcomes as read back.
func runLoop(dir string, state *workerState, lock, result, log *os.File) error {
	sinks := output.Sinks{Transcript: log}
	if state.Loop.MainLog != "" {
		main, err := openMainLog(state.Loop.MainLog)
		if err != nil {
			err = fmt.Errorf("the main log cannot be used: %s", output.OneLine(err.Error(), maxFailure))
			fmt.Fprintf(log, "Core Updater: %v\n", err)
			return err
		}
		defer main.Close()
		sinks.Log = main
	}
	err := (&updater{loop: *state.Loop, req: state.Request, stateDir: dir, sinks: sinks, program: state.Path, logPath: log.Name(),
		lock: lock, result: result, log: log}).run()
	res, readErr := readResult(result)
	state.Result, err = res, errors.Join(err, readErr)
	code := 0
	if errors.Is(err, ErrDeferred) {
		code, err = deferredStatus, nil
	}
	if err == nil {
		state.ExitCode = &code
	}
	return err
}

// openMainLog opens path for appending, refusing a symbolic link, anything but a regular file and a file with another
// hard link (a file unlinked since the open has none, and is taken) before writing. A missing log is created as pfb_logger's file_put_contents() creates it: 0666 less the umask.
func openMainLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o666)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink > 1 {
		f.Close()
		return nil, fmt.Errorf("%s has more than one hard link", path)
	}
	return f, nil
}
