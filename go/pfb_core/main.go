// pfb-core, the pfBlockerNG Core daemon (map #3813): the platform-neutral business logic behind a versioned HTTP+JSON API
// that the co-located pfSense layer (PHP, native curl) calls over a Unix socket. docs/misc/core-api-protocol.md is the contract.
//
//	pfb-core --socket PATH --state-dir DIR [--settings-backend-cmd PATH] [--update-cmd PATH] [--zoneinfo PATH] [--feed-local-dir PATH]... [--script-dir PATH]... [--feed-orig-dir PATH] [--dnsbl-orig-dir PATH] [--feed-db-dir PATH] [--feed-geoip-dir PATH] [--feed-asn-csv PATH] [--rsync-bin PATH] [--user-agent STRING] [--allow-uid UID] [--client-uid UID]... [--socket-group GID]
//
//	--socket PATH       the API's Unix socket: its directory is made 0700 and the socket 0600, the server's user's alone
//	--state-dir DIR     Core's own storage (its lock core.lock, the settings store settings.json without
//	                    --settings-backend-cmd, and with --update-cmd the scheduler's schedule_state.json and the Update's
//	                    update.log): made 0700, the server's user's alone; one Core at a time may use it
//	--settings-backend-cmd PATH
//	                    keep the settings in the program at PATH instead of settings.json: Core runs it once per read or
//	                    write of the settings, a JSON request on its stdin and its JSON reply on stdout (settings.AdapterBackend)
//	--update-cmd PATH   run the quarter-hour scheduler and serve the singleton Update (StartUpdate, GetUpdate, GetSchedule): Core
//	                    runs the program at PATH once per Update, its request on stdin, stdout and stderr in update.log and
//	                    its result on fd 3 (update.Command). Without it those methods answer unavailable. A stop while an
//	                    Update runs ends it (TERM to its process group, KILL after 5 s) and nothing is resumed. The program's
//	                    exit status 75 means it deferred the Update: the result is skipped and nothing is recorded
//	--zoneinfo PATH     the host's time zone file (a TZif file): the scheduler reads the schedule in its zone, re-reading it at
//	                    every evaluation, so a change of the host's zone applies without a restart. Without it, or when the file
//	                    cannot be used (logged once), the process's local zone
//	--feed-local-dir PATH
//	                    an absolute folder a file:// feed may sit directly in; repeatable (issue #3975, the feed phase)
//	--script-dir PATH   an absolute folder a group's pre and post scripts are looked up in; repeatable, searched in the order given
//	--rsync-bin PATH    the absolute path of the rsync program a rsync feed is transferred with
//	--user-agent STRING what feed hosts are told Core is: no control character
//	--feed-orig-dir PATH  the absolute IPv4/IPv6 feed baseline directory
//	--dnsbl-orig-dir PATH the absolute DNSBL feed baseline directory
//	--feed-db-dir PATH    the absolute package database directory for synthetic DNSBLIP sources
//	--feed-geoip-dir PATH the absolute local GeoIP country-feed directory
//	--feed-asn-csv PATH   the absolute IPinfo ASN ranges file
//	--allow-uid UID     the privileged caller's uid, read from the kernel's credential of each connection (default 0, root)
//	--client-uid UID    a further local client's uid also served (pfb-dns's user); repeatable
//	--socket-group GID  open the socket's directory (0750) and the socket (0660) to this group, so that a client that is
//	                    not root can connect; who is served is still decided by uid
//
// Every path Core uses arrives as a flag: Core names no pfSense path (boundary_test.go). Log lines go to stderr; the rc
// script points it at the package log. TERM or INT stops it: requests in flight finish (up to 3 s) and the socket is removed.
//
// Exit status: 0 after a clean stop, 1 when it cannot serve (including settings it cannot read at start), 2 for a usage error.
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
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

const shutdownGrace = 3 * time.Second // below the rc script's 5 s before KILL

func run(ctx context.Context, args []string, stderr io.Writer) int {
	fl := flag.NewFlagSet("pfb-core", flag.ContinueOnError)
	fl.SetOutput(stderr)
	socket := fl.String("socket", "", "the API's Unix socket (required)")
	stateDir := fl.String("state-dir", "", "Core's storage directory (required)")
	backendCmd := fl.String("settings-backend-cmd", "", "keep the settings in this program instead of the state directory's file")
	updateCmd := fl.String("update-cmd", "", "run the scheduler and the Updates through this program")
	zoneinfo := fl.String("zoneinfo", "", "the host's time zone file the scheduler reads the schedule's zone from")
	feed := addFeedFlags(fl)
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
	if *socket == "" || *stateDir == "" || fl.NArg() != 0 {
		fmt.Fprintln(stderr, "pfb-core: usage: pfb-core --socket PATH --state-dir DIR [--settings-backend-cmd PATH] [--update-cmd PATH] [--zoneinfo PATH] [--feed-local-dir PATH]... [--script-dir PATH]... [--feed-orig-dir PATH] [--dnsbl-orig-dir PATH] [--feed-db-dir PATH] [--feed-geoip-dir PATH] [--feed-asn-csv PATH] [--rsync-bin PATH] [--user-agent STRING] [--allow-uid UID] [--client-uid UID]... [--socket-group GID]")
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
	var backend settings.Backend = settings.NewFileBackend(*stateDir)
	kind := "file"
	if *backendCmd != "" {
		backend, kind = &settings.AdapterBackend{Path: *backendCmd}, "adapter"
	}
	store, err := settings.Load(backend, settings.Production())
	if err != nil {
		logger.Printf("cannot read the settings from the %s backend: %v", kind, err)
		return 1
	}
	snap, _ := store.Get(nil) // no ids to refuse: it cannot fail
	logger.Printf("settings: %s revision %d", kind, snap.Revision)
	logger.Printf("feed phase: %d local folders, %d script folders, rsync %q, user agent set %t", len(feed.LocalDirs), len(feed.ScriptDirs), feed.RsyncBin, feed.UserAgent != "")
	methods := productionMethods()
	maps.Copy(methods, settingsMethods(store))
	sched, gate := newUpdates(*updateCmd, *zoneinfo, *stateDir, store, logger.Printf) // nil without --update-cmd
	maps.Copy(methods, updateMethods(sched, gate, newFeedPhaseRunner(store, *feed)))
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
