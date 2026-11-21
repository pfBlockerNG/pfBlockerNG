// pfb-core, the pfBlockerNG Core daemon (map #3813): the platform-neutral business logic behind a versioned HTTP+JSON API
// that the co-located pfSense layer (PHP, native curl) calls over a Unix socket. docs/misc/core-api-protocol.md is the contract.
//
//	pfb-core --socket PATH --state-dir DIR [--settings-backend-cmd PATH] [--update-cmd PATH] [--maintenance-cmd PATH] [--metrics-cmd PATH] [--counters-cmd PATH] [--zoneinfo PATH] [--resource-dir PATH] [--feed-local-dir PATH]... [--script-dir PATH]... [--rsync-bin PATH] [--user-agent STRING] [--allow-uid UID] [--client-uid UID]... [--socket-group GID]
//	pfb-core --run-hooks pre|post --hook-dir PATH (--settings-backend-cmd PATH | --state-dir DIR) [--python-wrapper PATH]
//
//	--socket PATH       the API's Unix socket: its directory is made 0700 and the socket 0600, the server's user's alone
//	--state-dir DIR     Core's own storage: core.lock, applied.json (the last ReportApplied) and, without
//	                    --settings-backend-cmd, settings.json; --update-cmd adds
//	                    schedule_state.json, update.log and Update receipts; --maintenance-cmd adds maintenance.log and its
//	                    private receipts. The directory is made 0700 and is the server user's alone.
//	--settings-backend-cmd PATH
//	                    keep the settings in the program at PATH instead of settings.json: Core runs it once per read or
//	                    write of the settings, a JSON request on its stdin and its JSON reply on stdout (settings.AdapterBackend)
//	--update-cmd PATH   run the quarter-hour scheduler and serve the singleton Update (StartUpdate, GetUpdate, GetSchedule): Core
//	                    launches an independent worker per Update; the worker runs PATH with request on stdin, stdout/stderr in
//	                    update.log and its result on fd 3. Without it those methods answer unavailable. Stopping Core ends
//	                    scheduling and observation, not an admitted worker; a restarted Core observes or reconciles its receipt.
//	                    Exit status 75 means the worker deferred the Update: its result is skipped and nothing is recorded
//	--maintenance-cmd PATH
//	                    optional quarter-hour Outpost command, no arguments, in an independent maintenance worker; it uses
//	                    maintenance.log and separate receipts/lock. Core reads the maintenance settings before each run and
//	                    skips it unless the package is enabled and scheduled work is not switched off. Core shutdown ends
//	                    observation, not an admitted maintenance transaction.
//	--metrics-cmd PATH  optional program Core starts, with no arguments, at every Unix minute boundary while the package is
//	                    enabled and exports metrics (memory, no reload per minute)
//	--counters-cmd PATH optional program Core starts at the first minute boundary of each local calendar day (--zoneinfo's
//	                    zone), after reading the settings again, with the verbs due as arguments: clearip, then cleardnsbl
//	                    (each daily, or weekly on a Sunday); nothing due starts nothing. The lanes are started and observed,
//	                    never signalled: a run still alive skips the boundary, output is discarded, a failure is logged once
//	                    per outage, and a Core stop leaves a running program alone
//	--zoneinfo PATH     the host's time zone file (a TZif file): the scheduler reads the schedule in its zone, re-reading it at
//	                    every evaluation, so a change of the host's zone applies without a restart. Without it, or when the file
//	                    cannot be used (logged once), the process's local zone
//	--resource-dir PATH the resource store's absolute directory, which the Core Updater writes and GetResources reads: bodies of IP
//	                    sets, aggregates, the geo catalog and DNSBL scopes, never settings. Without it GetResources answers
//	                    unavailable. A directory that does not exist is not an error: every resource is then not_found
//	--feed-local-dir PATH
//	                    an absolute folder a file:// feed may sit directly in; repeatable (issue #3975, the feed phase)
//	--script-dir PATH   an absolute folder a group's pre and post scripts are looked up in; repeatable, searched in the order given
//	--rsync-bin PATH    the absolute path of the rsync program a rsync feed is transferred with
//	--user-agent STRING what feed hosts are told Core is: no control character
//	--hook-dir PATH     the absolute folder of the update hooks (hook_pre_*, hook_post_*)
//	--python-wrapper PATH
//	                    the absolute path of the program a .py hook runs through (pfb_python.sh); without it a .py hook
//	                    is skipped
//	--run-hooks pre|post
//	                    run the hooks of that fire point once and exit, with the context as one JSON object on stdin
//	                    (docs/misc/core-api-protocol.md "Hooks outside an Update"): no socket, no lock, nothing published
//	--allow-uid UID     the privileged caller's uid, read from the kernel's credential of each connection (default 0, root)
//	--client-uid UID    a further local client's uid also served (pfb-dns's user); repeatable
//	--socket-group GID  open the socket's directory (0750) and the socket (0660) to this group, so that a client that is
//	                    not root can connect; who is served is still decided by uid
//
// Every path Core uses arrives as a flag: Core names no pfSense path (boundary_test.go). Log lines go to stderr; the rc
// script points it at the package log. TERM or INT stops scheduling and observation without signaling admitted workers;
// in-flight API requests finish (up to 3 s) and the socket is removed.
//
// Exit status: 0 after a clean stop, 1 when it cannot serve (including settings it cannot read at start), 2 for a usage error.
// With --run-hooks: 0 once the hooks ran, whatever they did, or when the settings are not initialized; 1 when the hooks
// did not all run: the settings cannot be read (nothing runs), TERM, INT or HUP came while the context was read (nothing
// runs), or such a signal left an enabled hook unrun or cut one short; 2 for a usage error or a context it refuses
// (nothing runs). An INT or HUP inherited ignored stays ignored. A signal during the settings read is acted on once
// that read ends (at most the adapter's 10 s read timeout).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/scheduler"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const shutdownGrace = 3 * time.Second // below the rc script's 5 s before KILL

// interruptIgnored is whether pfb-core started with SIGINT ignored, read before main's Notify clears the ignore: the
// one-shot keeps it, as it keeps an ignored SIGHUP.
var interruptIgnored = signal.Ignored(os.Interrupt)

func run(ctx context.Context, args []string, stderr io.Writer) int {
	fl := flag.NewFlagSet("pfb-core", flag.ContinueOnError)
	fl.SetOutput(stderr)
	socket := fl.String("socket", "", "the API's Unix socket (required)")
	stateDir := fl.String("state-dir", "", "Core's storage directory (required)")
	backendCmd := fl.String("settings-backend-cmd", "", "keep the settings in this program instead of the state directory's file")
	updateCmd := fl.String("update-cmd", "", "run the scheduler and the Updates through this program")
	var maintenanceCmd, metricsCmd, countersCmd string
	fl.Func("maintenance-cmd", "run independent quarter-hour maintenance through this program", programFlag(&maintenanceCmd))
	fl.Func("metrics-cmd", "start this program at every minute boundary", programFlag(&metricsCmd))
	fl.Func("counters-cmd", "start this program at the first minute boundary of each local day, with the cadences due", programFlag(&countersCmd))
	zoneinfo := fl.String("zoneinfo", "", "the host's time zone file the scheduler reads the schedule's zone from")
	feed := addFeedFlags(fl)
	var resourceDir, hookDir, pythonWrapper, runHooksWhen string
	fl.Func("resource-dir", "the resource store's directory (an absolute path)", absolutePath(&resourceDir))
	fl.Func("hook-dir", "the folder of the update hooks (an absolute path)", absolutePath(&hookDir))
	fl.Func("python-wrapper", "the program a .py hook runs through (an absolute path)", absolutePath(&pythonWrapper))
	fl.Func("run-hooks", "run the pre or post hooks once and exit", func(v string) error {
		if v != "pre" && v != "post" {
			return errors.New("must be pre or post")
		}
		runHooksWhen = v
		return nil
	})
	var allowUID uint32
	fl.Func("allow-uid", "the privileged caller's uid (default 0)", func(v string) error {
		uid, err := strconv.ParseUint(v, 10, 32)
		allowUID = uint32(uid)
		return err
	})
	var clients []uint32
	fl.Func("client-uid", "a further local client's uid (repeatable)", func(v string) error {
		uid, err := strconv.ParseUint(v, 10, 32)
		clients = append(clients, uint32(uid))
		return err
	})
	group, groupSet := 0, false
	fl.Func("socket-group", "the group the socket is opened to", func(v string) error {
		gid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return err
		}
		if gid > math.MaxInt32 { // chown(2) takes it as a Go int
			return fmt.Errorf("group id %d is out of range", gid)
		}
		group, groupSet = int(gid), true
		return nil
	})
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if runHooksWhen != "" {
		if fl.NArg() != 0 || hookDir == "" || *stateDir == "" && *backendCmd == "" {
			fmt.Fprintln(stderr, "pfb-core: usage: pfb-core --run-hooks pre|post --hook-dir PATH "+
				"(--settings-backend-cmd PATH | --state-dir DIR) [--python-wrapper PATH]")
			return 2
		}
		// SIGPIPE noticed, not ignored: a closed console fails its writes instead of ending the run, and hooks keep the
		// default action. A hangup or an interrupt cancels the run, so that no hook outlives its timeout, unless it came
		// in ignored (nohup, a background job of a shell without job control).
		signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
		if interruptIgnored { // main's Notify replaced the ignore
			signal.Ignore(os.Interrupt)
		}
		if !signal.Ignored(syscall.SIGHUP) {
			var stop context.CancelFunc
			ctx, stop = signal.NotifyContext(ctx, syscall.SIGHUP)
			defer stop()
		}
		runner := hooks.Runner{Dir: hookDir, Python: pythonWrapper}
		return runHooks(ctx, runHooksWhen, *stateDir, *backendCmd, runner, os.Stdin, os.Stdout, stderr)
	}
	if *socket == "" || *stateDir == "" || fl.NArg() != 0 {
		fmt.Fprintln(stderr, "pfb-core: usage: pfb-core --socket PATH --state-dir DIR [--settings-backend-cmd PATH] [--update-cmd PATH] [--maintenance-cmd PATH] [--metrics-cmd PATH] [--counters-cmd PATH] [--zoneinfo PATH] [--resource-dir PATH] [--feed-local-dir PATH]... [--script-dir PATH]... [--rsync-bin PATH] [--user-agent STRING] [--allow-uid UID] [--client-uid UID]... [--socket-group GID]")
		return 2
	}
	logger := log.New(stderr, "pfb_core: ", log.LstdFlags)
	if err := privateDir(*stateDir, 0o700); err != nil {
		logger.Printf("cannot use the state directory %s: %v", *stateDir, err)
		return 1
	}
	lock, err := lockStateDir(*stateDir)
	if err != nil {
		logger.Printf("%v", err)
		return 1
	}
	defer lock.Close()
	switch report, err := readApplied(*stateDir); {
	case err != nil:
		logger.Printf("ignored %s: %v", appliedFile, err)
	case report != nil:
		logger.Printf("applied report: %d resources", len(report))
	}
	backend, kind := settingsBackend(*stateDir, *backendCmd)
	store, err := settings.Load(backend, settings.Production())
	if err != nil {
		logger.Printf("cannot read the settings from the %s backend: %v", kind, err)
		return 1
	}
	snap, _ := store.Get(nil) // no ids to refuse: it cannot fail
	logger.Printf("settings: %s revision %d", kind, snap.Revision)
	logger.Printf("feed phase: %d local folders, %d script folders, rsync %q, user agent set %t", len(feed.LocalDirs), len(feed.ScriptDirs), feed.RsyncBin, feed.UserAgent != "")
	var resourceStore *resources.Store // nil without --resource-dir
	if resourceDir != "" {
		resourceStore = resources.Open(resourceDir)
	}
	lanes := newLaneSettings(store, logger.Printf)
	sched, gate := newUpdates(*updateCmd, maintenanceCmd, *zoneinfo, *stateDir, store, lanes, logger.Printf) // nil without --update-cmd
	methods := coreMethods(*stateDir, store, resourceStore, sched, gate)
	srv, err := listen(options{socket: *socket, allowUID: allowUID, clientUIDs: clients, socketGroup: group, groupSet: groupSet,
		methods: methods, logf: logger.Printf})
	if err != nil {
		logger.Printf("cannot listen on %s: %v", *socket, err)
		return 1
	}
	served := make(chan error, 1)
	go func() { served <- srv.serve() }()
	logger.Printf("serving API %s on %s for uid %d, clients %v", apiVersion, *socket, allowUID, clients)
	stopUpdates := runUpdates(ctx, sched, gate)
	defer stopUpdates()
	if metricsCmd != "" || countersCmd != "" {
		clock := make(chan struct{})
		go func() {
			runClock(ctx, clockNow, clockAfter, hostZone(*zoneinfo, logger.Printf),
				&lane{name: "metrics", path: metricsCmd, logf: logger.Printf}, &lane{name: "counters", path: countersCmd, logf: logger.Printf}, lanes)
			close(clock)
		}()
		defer func() { <-clock }() // ctx ends it before run returns; running children are left alone
	}
	select {
	case err := <-served:
		logger.Printf("stopped serving: %v", err)
		return 1
	case <-ctx.Done():
	}
	stopUpdates() // the Update running ends before the server does: a client that asks again then gets unavailable
	stop, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.shutdown(stop); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		logger.Printf("shutdown: %v", err)
	}
	<-served
	logger.Printf("stopped")
	return 0
}

// coreMethods is every method Core serves, over Core's state directory, its settings, its resource store (nil: none) and
// its Updates (nil: none).
func coreMethods(stateDir string, store *settings.Store, resourceStore *resources.Store, sched *scheduler.Scheduler,
	gate *update.Gate) map[string]method {
	methods := productionMethods()
	maps.Copy(methods, settingsMethods(store))
	maps.Copy(methods, resourceMethods(resourceStore))
	maps.Copy(methods, updateMethods(sched, gate))
	maps.Copy(methods, appliedMethods(stateDir))
	return methods
}

// settingsBackend is the settings backend the flags name, and its kind: the adapter program cmd, else the state
// directory's settings.json.
func settingsBackend(stateDir, cmd string) (settings.Backend, string) {
	if cmd != "" {
		return &settings.AdapterBackend{Path: cmd}, "adapter"
	}
	return settings.NewFileBackend(stateDir), "file"
}

// absolutePath is the flag.Func setter of an absolute path, which it cleans; a relative one is a usage error.
func absolutePath(dst *string) func(string) error {
	return func(v string) error {
		if !filepath.IsAbs(v) {
			return fmt.Errorf("%q is not an absolute path", v)
		}
		*dst = filepath.Clean(v)
		return nil
	}
}

// programFlag is the flag.Func setter of an optional program path (empty: off) that may hold no control character.
func programFlag(dst *string) func(string) error {
	return func(v string) error {
		if i := strings.IndexFunc(v, unicode.IsControl); i >= 0 {
			return fmt.Errorf("holds a control character at byte %d", i)
		}
		*dst = v
		return nil
	}
}

// lockStateDir takes core.lock in dir for the life of the process, whichever backend Core reads: two Cores on one state
// directory would each accept a save at the same revision. The flock goes when the returned file is closed or the process ends.
func lockStateDir(dir string) (*os.File, error) {
	lock, err := os.OpenFile(filepath.Join(dir, "core.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("the state directory %s is in use by another Core: %w", dir, err)
	}
	return lock, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(code)
}
