// pfb_dns_gateway, the pfB-DNS network layer (issue #3513): serves plain DNS over UDP and TCP, and DoT, DoH and DoQ with the DNS Resolver's
// certificate; applies the Resolver ACL before anyone is asked, lets the Python DNSBL decider (its child) decide
// every other query, and forwards to Unbound with a PROXYv2 header naming the client.
//
//	pfb_dns_gateway [flags] -- <decider command...>
//
// The decider command is started with the decision socket as fd 3; docs/misc/dns-gateway-protocol.md is the
// protocol, docs/misc/dns-gateway-transports.md the encrypted transports. Readiness lines on stderr, once the
// decider has sent READY:
//
//	listening udp+tcp <host>:<port>     one per bound --listen address
//	listening dot|doh|doq <host>:<port> one per bound TLS listener
//	ready upstream <host>:<port>
//
// --ready-file PATH: the gateway writes its own pid there, mode 0600, once it serves, and removes the file at stop
// while the file still names it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultReadyTimeout   = 300 * time.Second               // the decider boots the whole DNSBL database before it says READY
	defaultKillAfter      = 3 * time.Second                 // how long the decider gets to leave on EOF
	defaultShutdownBudget = 4 * time.Second                 // all of shutdown: the rc stop sends KILL 5 s after TERM, which would leave a stale ready file
	defaultTLSPEM         = "/var/unbound/pfb_dns_cert.pem" // pfBlockerNG's export of the Resolver's certificate, in the Unbound chroot
)

type config struct {
	listen      []string
	port        int
	upstream    string
	timeout     time.Duration
	unboundConf string
	user        string
	dot         bool
	dotPort     int
	tlsPEM      string
	dohListen   []string
	dohPort     int
	dohTrusted  []string
	doqListen   []string
	doqPort     int
	noModule    bool // pfB-DNS modes: the decider's own flags of the same names, handed on to it
	observer    bool
	replyLog    bool
	readyFile   string // --ready-file: the gateway's pid is published here once it serves; "" = none
	decider     []string

	// Test seams; the zero value is production.
	drop           func() error      // replaces the privilege drop to --user
	trace          func(step string) // called after bind, decider start and READY (the drop hook records itself)
	readyTimeout   time.Duration
	killAfter      time.Duration
	shutdownBudget time.Duration
	interrupt      <-chan struct{} // closed on SIGINT/SIGTERM: start stops waiting for the decider
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// parseConfig reads the command line: flags, then `--`, then the decider command, which is never parsed. -h
// writes the flag defaults to usage and returns flag.ErrHelp.
func parseConfig(args []string, usage io.Writer) (config, error) {
	cfg := config{
		port: 53, upstream: "127.0.0.1:5353", timeout: 5 * time.Second, unboundConf: "/var/unbound/unbound.conf",
		tlsPEM: defaultTLSPEM, dotPort: defaultDoTPort, dohPort: 4443, doqPort: 853,
	}
	split := slices.Index(args, "--")
	if split < 0 {
		return config{}, errors.New("missing `--` and the decider command after it")
	}
	cfg.decider = args[split+1:]

	fs := flag.NewFlagSet("pfb_dns_gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var listen listFlag
	fs.Var(&listen, "listen", "plain DNS address (UDP and TCP), repeatable; required")
	fs.IntVar(&cfg.port, "port", cfg.port, "plain DNS port; 0 picks one per address")
	fs.StringVar(&cfg.upstream, "upstream", cfg.upstream, "Unbound's proxy-protocol HOST:PORT")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "wait for Unbound per exchange")
	fs.StringVar(&cfg.unboundConf, "unbound-conf", cfg.unboundConf, "Unbound's config: the access-control rows of it and of every file it includes are the ACL")
	fs.StringVar(&cfg.user, "user", "", "give up root for this user once the sockets are bound and the decider runs")
	fs.BoolVar(&cfg.dot, "dot", false, "serve DoT on every --listen address at --dot-port")
	fs.IntVar(&cfg.dotPort, "dot-port", cfg.dotPort, "DoT port; 0 picks one per address")
	fs.StringVar(&cfg.tlsPEM, "tls-pem", cfg.tlsPEM, "certificate chain and private key of DoT, DoH and DoQ, one PEM file; read again when it changes")
	var dohListen, dohTrusted, doqListen listFlag
	fs.Var(&dohListen, "doh-listen", "DoH address (HTTPS GET and POST on /dns-query), repeatable; none = DoH off")
	fs.IntVar(&cfg.dohPort, "doh-port", cfg.dohPort, "DoH port; 0 picks one per address")
	fs.Var(&dohTrusted, "doh-trusted", "front end trusted to send PROXYv2 and X-Forwarded-For to DoH (CIDR or address), repeatable")
	fs.Var(&doqListen, "doq-listen", "DoQ (RFC 9250) address, repeatable; none = DoQ off")
	fs.IntVar(&cfg.doqPort, "doq-port", cfg.doqPort, "DoQ UDP port; 0 picks one per address")
	fs.BoolVar(&cfg.noModule, "no-module", false, "pfB-DNS without DNSBL: the decider boots no module and forwards every query")
	fs.BoolVar(&cfg.observer, "observer", false, "DNSBL on, Resolver forwarding: the decider listens for the upstream observer's reports")
	fs.BoolVar(&cfg.replyLog, "reply-log", false, "the decider logs each relayed reply to dns_reply.log (needs --no-module)")
	fs.StringVar(&cfg.readyFile, "ready-file", "", "write the gateway's pid here, mode 0600, once it serves; removed at stop while it still names the gateway")
	if err := fs.Parse(args[:split]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(usage)
			fs.PrintDefaults()
		}
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q before `--`", fs.Arg(0))
	}
	cfg.listen, cfg.dohListen, cfg.dohTrusted, cfg.doqListen = listen, dohListen, dohTrusted, doqListen
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	for _, mode := range []struct {
		on   bool
		flag string
	}{{cfg.noModule, "--no-module"}, {cfg.replyLog, "--reply-log"}, {cfg.observer, "--observer"}} {
		if mode.on {
			cfg.decider = append(cfg.decider, mode.flag)
		}
	}
	return cfg, nil
}

func (c config) validate() error {
	if len(c.decider) == 0 {
		return errors.New("no decider command after `--`")
	}
	if c.decider[0] == "" {
		return errors.New("empty decider command after `--`")
	}
	if c.observer && c.noModule {
		return errors.New("--observer cannot be used with --no-module")
	}
	if c.replyLog && !c.noModule {
		return errors.New("--reply-log needs --no-module: the module logs its own replies")
	}
	if c.port < 0 || c.port > 65535 {
		return fmt.Errorf("--port %d is outside 0..65535", c.port)
	}
	if c.timeout <= 0 {
		return fmt.Errorf("--timeout %s must be positive", c.timeout)
	}
	if c.unboundConf == "" {
		return errors.New("--unbound-conf must not be empty")
	}
	if len(c.listen) == 0 {
		return errors.New("--listen is required: the addresses to serve plain DNS on")
	}
	if slices.Contains(c.listen, "") {
		return errors.New("--listen must not be empty")
	}
	if slices.Contains(c.dohListen, "") {
		return errors.New("--doh-listen must not be empty")
	}
	if slices.Contains(c.doqListen, "") {
		return errors.New("--doq-listen must not be empty")
	}
	if c.tlsPEM == "" {
		return errors.New("--tls-pem must not be empty")
	}
	if c.dotPort < 0 || c.dotPort > 65535 {
		return fmt.Errorf("--dot-port %d is outside 0..65535", c.dotPort)
	}
	if c.dohPort < 0 || c.dohPort > 65535 {
		return fmt.Errorf("--doh-port %d is outside 0..65535", c.dohPort)
	}
	if c.doqPort < 0 || c.doqPort > 65535 {
		return fmt.Errorf("--doq-port %d is outside 0..65535", c.doqPort)
	}
	host, port, err := net.SplitHostPort(c.upstream)
	if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		return fmt.Errorf("--upstream %q: want HOST:PORT", c.upstream)
	}
	return nil
}

// child is the decider process.
type child struct {
	cmd         *exec.Cmd
	killProcess func() error // cmd.Process.Kill; a test makes it refuse
	exited      chan struct{}
	err         error // how it ended; valid once exited is closed
}

// startDecider runs argv with fd as its fd 3 and our stdout and stderr, and closes fd here.
func startDecider(argv []string, fd *os.File) (*child, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{fd}
	err := cmd.Start()
	_ = fd.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot start the decider: %w", err)
	}
	c := &child{cmd: cmd, killProcess: cmd.Process.Kill, exited: make(chan struct{})}
	go func() { c.err = cmd.Wait(); close(c.exited) }()
	return c, nil
}

// kill stops the decider and waits at most bound for it to be gone. After the privilege drop the gateway cannot
// signal a decider that is still root (EPERM), and must not wait for that decider's boot to finish.
func (c *child) kill(logf func(format string, args ...any), bound time.Duration) {
	if err := c.killProcess(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		logf("cannot kill the decider: %v", err)
	}
	if !c.waitExit(bound) {
		logf("the decider is still running %s after the kill", bound.Round(time.Millisecond))
	}
}

func (c *child) waitExit(d time.Duration) bool {
	select {
	case <-c.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// server is a started gateway: listeners bound, decider ready, serving.
type server struct {
	cfg     config
	logf    func(format string, args ...any)
	g       *gateway
	dec     *Decider
	child   *child
	failed  chan error
	stopped chan struct{}
	once    sync.Once
}

// start binds every --listen address (one that fails is logged and skipped), starts the decider, gives up root,
// waits for READY, reports readiness and begins serving. On any error nothing is left running or bound.
func start(cfg config, logf func(format string, args ...any)) (*server, error) {
	trace := cfg.trace
	if trace == nil {
		trace = func(string) {}
	}
	drop := cfg.drop
	if drop == nil && cfg.user != "" {
		acct, err := lookupAccount(cfg.user)
		if err != nil {
			return nil, err
		}
		drop = acct.drop
	}
	if cfg.readyTimeout == 0 {
		cfg.readyTimeout = defaultReadyTimeout
	}
	if cfg.killAfter == 0 {
		cfg.killAfter = defaultKillAfter
	}
	if cfg.shutdownBudget == 0 {
		cfg.shutdownBudget = defaultShutdownBudget
	}

	acl := NewACL(cfg.unboundConf, logf)
	var listeners []*plainListener
	for _, host := range cfg.listen {
		l, err := bindPlain(host, cfg.port)
		if err != nil {
			logf("%v", err)
			continue
		}
		listeners = append(listeners, l)
	}
	var secure *tlsListeners
	closeListeners := func() {
		for _, l := range listeners {
			l.close()
		}
		secure.close()
	}
	if len(listeners) == 0 {
		return nil, errors.New("no address could be bound")
	}
	secure = bindTLS(cfg, logf) // the certificate file is read, and the sockets are bound, before the privilege drop
	trace("bind")

	conn, deciderEnd, err := newSocketpair()
	if err != nil {
		closeListeners()
		return nil, err
	}
	ch, err := startDecider(cfg.decider, deciderEnd)
	if err != nil {
		_ = conn.Close()
		closeListeners()
		return nil, err
	}
	trace("decider")
	dec := NewDecider(conn, logf)
	abort := func(err error) (*server, error) {
		dec.Close()
		ch.kill(logf, cfg.killAfter)
		closeListeners()
		return nil, err
	}

	if drop != nil {
		if err := drop(); err != nil {
			return abort(err)
		}
	}
	select {
	case <-dec.Ready():
	case <-dec.Done():
		return abort(fmt.Errorf("decider failed before READY: %w", dec.Err()))
	case <-ch.exited:
		return abort(fmt.Errorf("decider exited before READY: %v", ch.err))
	case <-cfg.interrupt:
		return abort(errInterrupted)
	case <-time.After(cfg.readyTimeout):
		return abort(fmt.Errorf("decider sent no READY within %s", cfg.readyTimeout))
	}
	trace("ready")

	g := newGateway(acl, dec, newUpstream(cfg.upstream, cfg.timeout), cfg.timeout, logf)
	for _, l := range listeners {
		g.serve(l)
	}
	secure.serve(g, cfg.dohTrusted)
	g.wg.Add(1)
	go func() { // a rewrite of the config or any file it includes reaches the matcher within a second
		defer g.wg.Done()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				acl.Refresh()
			case <-g.ctx.Done():
				return
			}
		}
	}()
	s := &server{cfg: cfg, logf: logf, g: g, dec: dec, child: ch, failed: make(chan error, 1), stopped: make(chan struct{})}
	if err := publishReady(cfg.readyFile); err != nil {
		s.shutdown()
		return nil, err
	}
	for _, l := range listeners {
		logf("listening udp+tcp %s", l.addr())
	}
	secure.report(logf)
	logf("ready upstream %s", cfg.upstream)
	go s.watch()
	return s, nil
}

// watch turns the end of the decider session, or of the decider process, into a fatal error.
func (s *server) watch() {
	var err error
	select {
	case <-s.stopped:
		return
	case <-s.dec.Done():
		err = fmt.Errorf("decider session ended: %w", s.dec.Err())
	case <-s.child.exited:
		err = fmt.Errorf("decider exited: %v", s.child.err)
	}
	select {
	case <-s.stopped: // our own shutdown made the decider leave
	default:
		s.failed <- err
	}
}

// fatal delivers the reason the gateway can no longer serve; a requested shutdown delivers nothing.
func (s *server) fatal() <-chan error { return s.failed }

// shutdown stops accepting, closes the decision socket (the decider reads EOF and exits), and waits for the
// decider, killing it when it does not leave in time. Everything in it, the transports' stop included, fits in
// shutdownBudget: the decider's patience for EOF is whatever the transports left, less an eighth of the budget
// that the kill and its reap keep.
func (s *server) shutdown() {
	s.once.Do(func() {
		deadline := time.Now().Add(s.cfg.shutdownBudget)
		close(s.stopped)
		if err := removeReady(s.cfg.readyFile); err != nil {
			s.logf("cannot remove the ready file: %v", err)
		}
		s.dec.Close() // first: queries blocked writing to a decider that reads nothing would hold g.stop() up to the write deadline
		s.g.stop()
		patience := max(min(s.cfg.killAfter, time.Until(deadline)-s.cfg.shutdownBudget/8), 0)
		if !s.child.waitExit(patience) {
			s.logf("the decider did not exit within %s of EOF: killing it", patience.Round(time.Millisecond))
			s.child.kill(s.logf, time.Until(deadline))
		}
	})
}

// publishReady writes the gateway's pid to path, mode 0600: a temporary file in the same directory, renamed over
// path, so a reader sees all of it or none, and a symlink planted at path is replaced rather than written through.
// An empty path publishes nothing.
func publishReady(path string) error {
	if path == "" {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("cannot write the ready file: %w", err)
	}
	_, err = fmt.Fprintf(tmp, "%d\n", os.Getpid())
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("cannot write the ready file: %w", err)
	}
	return nil
}

// removeReady deletes the ready file only while it still holds this process's pid. Anything else (another pid, a
// symlink, a FIFO) is left alone: the open never follows a symlink and never blocks on a FIFO.
func removeReady(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return err
	}
	if string(b) != strconv.Itoa(os.Getpid())+"\n" {
		return nil
	}
	return os.Remove(path)
}

var errInterrupted = errors.New("interrupted while waiting for the decider")

func realMain(args []string, stderr io.Writer) int {
	logger := log.New(stderr, "", 0)
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		logger.Printf("pfb_dns_gateway: %v\nusage: pfb_dns_gateway [flags] -- <decider command...>   (-h lists the flags)", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP) // SIGHUP's default action would leave a stale ready file
	defer stop()
	cfg.interrupt = ctx.Done()
	srv, err := start(cfg, logger.Printf)
	if errors.Is(err, errInterrupted) {
		logger.Print("pfb_dns_gateway: stopped by signal before the decider was ready")
		return 0
	}
	if err != nil {
		logger.Printf("pfb_dns_gateway: %v", err)
		return 1
	}
	select {
	case <-ctx.Done():
		srv.shutdown()
		return 0
	case err := <-srv.fatal():
		logger.Printf("pfb_dns_gateway: %v", err)
		srv.shutdown()
		return 1
	}
}

func main() { os.Exit(realMain(os.Args[1:], os.Stderr)) }
