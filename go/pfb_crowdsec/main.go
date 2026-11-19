// pfb_crowdsec is pfBlockerNG's CrowdSec firewall bouncer (docs/specs/crowdsec-integration.md, D1): it polls a CrowdSec
// Local API for active bans and keeps two pf tables equal to them. Standard library only; it listens on nothing.
//
// Usage:
//
//	pfb_crowdsec -c <config>      run (logs `level=<lvl> msg=<text>` lines on stdout)
//	pfb_crowdsec -t -c <config>   validate the config and exit
//	pfb_crowdsec -version         print the version
//
// Signals: SIGUSR1 re-checks the tables at once (sent after a filter reload); SIGTERM and SIGINT flush both tables
// and exit 0.
//
// Status file (status_file, JSON, mode 0644, replaced atomically after every pull and every update_frequency, however
// long a LAPI request takes): version, start_time, update_frequency_seconds, updated_at, last_pull, last_error_time
// (Unix seconds, 0 for never), last_error, lapi_requests, lapi_errors (requests that have ended),
// banned.{ipv4,ipv6}.{total,origins{<origin>:<count>}} and dropped.{ipv4,ipv6}.{packets,bytes} (the inbound rules'
// counters, reset by every filter reload).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	version      = "0.1.0"
	pfctlPath    = "/sbin/pfctl"
	pfDevice     = "/dev/pf"
	pfctlTimeout = time.Minute
)

func main() { os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr)) }

// realMain returns the exit status: 0 done, 1 bad config or a failed start, 2 bad usage.
func realMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pfb_crowdsec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("c", "", "the JSON config file")
	testOnly := fs.Bool("t", false, "validate the config and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "pfb_crowdsec %s\n", version)
		return 0
	}
	if *cfgPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: pfb_crowdsec [-t] -c <config> | -version")
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "pfb_crowdsec: %v\n", err)
		return 1
	}
	if *testOnly {
		fmt.Fprintln(stdout, "pfb_crowdsec: configuration OK")
		return 0
	}
	return serve(cfg, stdout, pfctlPath, pfDevice)
}

// serve runs the daemon until SIGTERM or SIGINT; it returns 1 when it cannot start.
func serve(cfg *config, out io.Writer, pfctlBin, device string) int {
	// Before anything else, so that a SIGUSR1 sent during start-up queues a reconcile.
	usr1, stopUSR1 := notifyUSR1()
	defer stopUSR1()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log := newLogger(out, cfg.level)
	log.setSecret(cfg.APIKey)
	if err := preflight(pfctlBin, device); err != nil {
		log.errorf("%v", err)
		return 1
	}
	api, err := newLAPIClient(cfg)
	if err != nil {
		log.errorf("%v", err)
		return 1
	}
	d := newDaemon(cfg, log, &pfctl{r: execRunner{path: pfctlBin, timeout: pfctlTimeout}}, api, time.Now)
	log.infof("pfb_crowdsec %s starting: LAPI %s, tables %s and %s, every %s", version, cfg.APIURL, cfg.TableV4,
		cfg.TableV6, cfg.interval)
	if err := d.setup(ctx); err != nil {
		if ctx.Err() != nil { // stopped during start-up: leave both tables empty, as a normal stop does
			d.shutdown(context.WithoutCancel(ctx))
			log.infof("stopped")
			return 0
		}
		log.errorf("%v", err)
		return 1
	}
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	usage := time.NewTicker(usageInterval)
	defer usage.Stop()
	status := time.NewTicker(cfg.interval)
	defer status.Stop()
	d.run(ctx, ticker.C, usage.C, status.C, usr1, nil)
	log.infof("stopped")
	return 0
}

// preflight checks for an executable pfctl and the pf device.
func preflight(pfctl, device string) error {
	info, err := os.Stat(pfctl)
	if err != nil {
		return fmt.Errorf("%s: %w", pfctl, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable file", pfctl)
	}
	if _, err := os.Stat(device); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s does not exist: pf is not available", device)
		}
		return fmt.Errorf("%s: %w", device, err)
	}
	return nil
}

func notifyUSR1() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	return ch, func() { signal.Stop(ch) }
}
