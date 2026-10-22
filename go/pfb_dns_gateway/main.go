// pfb_dns_gateway, the pfB-DNS network layer (issue #3513): serves plain DNS over UDP and TCP, and DoT, DoH and DoQ with the
// certificate pfBlockerNG writes from the pfB-DNS page's selection; applies the Resolver ACL before anyone is asked, lets the
// Python DNSBL decider (its child) decide every other query, and forwards to Unbound with a PROXYv2 header naming the client.
//
//	pfb_dns_gateway [flags] -- <decider command...>
//
// The decider command is started with the decision socket as fd 3; docs/misc/dns-gateway-protocol.md is the
// protocol, docs/misc/dns-gateway-transports.md the encrypted transports. Readiness lines on stderr, once the
// decider has sent READY:
//
//	listening udp+tcp <host>:<port>     one per bound --listen address
//	listening dot|doh|doq <host>:<port> one per bound TLS listener
//	ready upstream <host>:<port> pid <pid>
//
// --ready-file PATH: the gateway writes its own pid there, mode 0600, once it serves, and removes the file at stop
// while the file still names it. Just before, it writes PATH.sha256: the SHA-256 of its own executable as read at start,
// 64 lowercase hex digits and a newline, never removed (a failure to write it is logged; the gateway serves anyway).
// The ready upstream line logs the same pid the ready file holds.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	defaultReadyTimeout   = 300 * time.Second          // the decider boots the whole DNSBL database before it says READY
	defaultRestartTimeout = 30 * time.Second           // a decider restarted on the control socket: pfBlockerNG waits 40 s for the reply
	defaultKillAfter      = 3 * time.Second            // how long the decider gets to leave on EOF
	defaultShutdownBudget = 4 * time.Second            // all of shutdown: the rc stop sends KILL 5 s after TERM, which would leave a stale ready file
	defaultTLSPEM         = "/var/etc/pfb_dns/tls.pem" // the certificate and key pfBlockerNG writes from the pfB-DNS page's selection: root only
)

type config struct {
	listen      []string
	port        int
	upstream    string
	timeout     time.Duration
	unboundConf string
	user        string
	dotPort     int
	tlsPEM      string
	ctlSocket   string
	dotListen   []string
	dohListen   []string
	dohPort     int
	dohTrusted  []string
	doqListen   []string
	doqPort     int
	noModule    bool // pfB-DNS modes: the decider's own flags of the same names, handed on to it
	observer    bool
	replyLog    bool
	readyFile   string // --ready-file: the gateway's pid is published here once it serves; "" = none
	ddr         string // --ddr: the firewall FQDN that DDR (RFC 9462) designates; "" = DDR off
	ddrDoH443   bool   // --ddr-doh-443: the DDR DoH record carries no port, whatever port DoH is bound on; needs ddr
	decider     []string

	// Test seams; the zero value is production.
	drop           func() error      // replaces the privilege drop to --user
	trace          func(step string) // called after bind, decider start and READY (the drop hook records itself)
	readyTimeout   time.Duration
	restartTimeout time.Duration
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
		tlsPEM: defaultTLSPEM, ctlSocket: defaultCtlSocket, dotPort: defaultDoTPort, dohPort: 4443, doqPort: 853,
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
	fs.IntVar(&cfg.dotPort, "dot-port", cfg.dotPort, "DoT port; 0 picks one per address")
	fs.StringVar(&cfg.tlsPEM, "tls-pem", cfg.tlsPEM, "certificate chain and private key of DoT, DoH and DoQ, one PEM file, read once at start while still root")
	fs.StringVar(&cfg.ctlSocket, "ctl-socket", cfg.ctlSocket, "Unix socket on which root pushes a renewed certificate; made in a root-only directory before the privilege drop")
	var dotListen, dohListen, dohTrusted, doqListen listFlag
	fs.Var(&dotListen, "dot-listen", "DoT address, repeatable; none = DoT off")
	fs.Var(&dohListen, "doh-listen", "DoH address (HTTPS GET and POST on /dns-query), repeatable; none = DoH off")
	fs.IntVar(&cfg.dohPort, "doh-port", cfg.dohPort, "DoH port; 0 picks one per address")
	fs.Var(&dohTrusted, "doh-trusted", "front end trusted to send PROXYv2 and X-Forwarded-For to DoH (CIDR or address), repeatable")
	fs.Var(&doqListen, "doq-listen", "DoQ (RFC 9250) address, repeatable; none = DoQ off")
	fs.IntVar(&cfg.doqPort, "doq-port", cfg.doqPort, "DoQ UDP port; 0 picks one per address")
	fs.BoolVar(&cfg.noModule, "no-module", false, "pfB-DNS without DNSBL: the decider boots no module and forwards every query")
	fs.BoolVar(&cfg.observer, "observer", false, "DNSBL on, Resolver forwarding: the decider listens for the upstream observer's reports")
	fs.BoolVar(&cfg.replyLog, "reply-log", false, "the decider logs each relayed reply to dns_reply.log (needs --no-module)")
	fs.StringVar(&cfg.readyFile, "ready-file", "", "write the gateway's pid here, mode 0600, once it serves; removed at stop while it still names the gateway")
	fs.StringVar(&cfg.ddr, "ddr", "", "answer resolver.arpa. itself and designate the encrypted transports (DDR, RFC 9462); the firewall's FQDN the records name; empty = off")
	fs.BoolVar(&cfg.ddrDoH443, "ddr-doh-443", false, "DDR leaves the port out of the DoH record, so clients use 443 (a reverse proxy in front of DoH); needs --ddr")
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
	cfg.listen, cfg.dotListen, cfg.dohListen, cfg.dohTrusted, cfg.doqListen = listen, dotListen, dohListen, dohTrusted, doqListen
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
	if slices.Contains(c.dotListen, "") {
		return errors.New("--dot-listen must not be empty")
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
	if c.ctlSocket == "" {
		return errors.New("--ctl-socket must not be empty")
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
	if c.ddr == "" && c.ddrDoH443 {
		return errors.New("--ddr-doh-443 needs --ddr")
	}
	if c.ddr != "" {
		if _, err := ddrName(c.ddr); err != nil {
			return err
		}
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
	killProcess func() error          // cmd.Process.Kill; a test makes it refuse
	waiting     func(d time.Duration) // test seam: called with the bound of every wait for the decider to leave
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
	if c.waiting != nil {
		c.waiting(d)
	}
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
	failed  chan error
	stopped chan struct{}
	once    sync.Once

	mu       sync.Mutex // guards the fields below: a restart replaces the active decider, the shutdown takes them all
	dec      *Decider   // the active decider, the one g asks: only its end is fatal
	child    *child
	swapped  chan struct{}       // closed, and replaced, when a restart makes another decider the active one
	retiring map[*child]*Decider // deciders a restart replaced that are not gone yet
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
	if cfg.restartTimeout == 0 {
		cfg.restartTimeout = defaultRestartTimeout
	}
	if cfg.killAfter == 0 {
		cfg.killAfter = defaultKillAfter
	}
	if cfg.shutdownBudget == 0 {
		cfg.shutdownBudget = defaultShutdownBudget
	}
	var binSum string
	var binErr error
	if cfg.readyFile != "" {
		binSum, binErr = executableSHA256() // now: an update replaces the file this process was started from
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
	var ctl *ctlServer
	closeListeners := func() {
		for _, l := range listeners {
			l.close()
		}
		secure.close()
		if ctl != nil {
			_ = ctl.ln.Close()
		}
	}
	if len(listeners) == 0 {
		return nil, errors.New("no address could be bound")
	}
	secure = bindTLS(cfg, logf) // the certificate file is read, and the sockets are bound, before the privilege drop
	if cfg.ctlSocket != "" {    // in every mode: a decider restart needs it as much as a certificate renewal does
		var err error
		var certs *certStore
		if secure != nil {
			certs = secure.certs
		}
		if ctl, err = bindCtl(cfg.ctlSocket, certs, logf); err != nil {
			logf("control socket: %v; the certificate cannot be renewed without a restart, nor the decider restarted alone", err)
		}
	}
	var ddrAnswers *ddr
	if cfg.ddr != "" {
		var err error
		if ddrAnswers, err = ddrOnListeners(cfg, secure); err != nil {
			closeListeners()
			return nil, err
		}
	}
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
	if err := awaitReady(dec, ch, cfg.interrupt, cfg.readyTimeout); errors.Is(err, errGivenUp) {
		return abort(errInterrupted)
	} else if err != nil {
		return abort(fmt.Errorf("decider %w", err))
	}
	trace("ready")

	g := newGateway(acl, dec, newUpstream(cfg.upstream, cfg.timeout), cfg.timeout, logf)
	g.ddr = ddrAnswers
	s := &server{cfg: cfg, logf: logf, g: g, dec: dec, child: ch, failed: make(chan error, 1), stopped: make(chan struct{}),
		swapped: make(chan struct{}), retiring: map[*child]*Decider{}}
	for _, l := range listeners {
		g.serve(l)
	}
	secure.serve(g, cfg.dohTrusted)
	if ctl != nil {
		ctl.restart = s.restartDecider
		ctl.serve(g)
	}
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
	if cfg.readyFile != "" {
		err := binErr
		if err == nil {
			err = replaceFile(cfg.readyFile+".sha256", []byte(binSum+"\n"))
		}
		if err != nil { // pfBlockerNG reads a missing record as a changed binary: the next update restarts the pair
			logf("cannot record the SHA-256 of the gateway binary: %v", err)
		}
	}
	if err := publishReady(cfg.readyFile); err != nil {
		s.shutdown()
		return nil, err
	}
	for _, l := range listeners {
		logf("listening udp+tcp %s", l.addr())
	}
	secure.report(logf)
	if ctl != nil {
		logf("control socket %s", ctl.path)
	}
	logf("ready upstream %s pid %d", cfg.upstream, os.Getpid())
	go s.watch()
	return s, nil
}

var errGivenUp = errors.New("was given up: the gateway is stopping")

// awaitReady waits at most bound for the decider's READY; its session ending, its exit and stop end the wait first.
func awaitReady(dec *Decider, ch *child, stop <-chan struct{}, bound time.Duration) error {
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-dec.Ready():
		return nil
	case <-dec.Done():
		return fmt.Errorf("failed before READY: %w", dec.Err())
	case <-ch.exited:
		return fmt.Errorf("exited before READY: %v", ch.err)
	case <-stop:
		return errGivenUp
	case <-t.C:
		return fmt.Errorf("sent no READY within %s", bound)
	}
}

// restartDecider starts a new decider with the first one's argv and, once it is READY, makes it the active one and
// retires the old one. A new decider that does not get READY is closed and killed; the old one stays active.
func (s *server) restartDecider() error {
	conn, end, err := newSocketpair()
	if err != nil {
		return err
	}
	ch, err := startDecider(s.cfg.decider, end)
	if err != nil {
		_ = conn.Close()
		return err
	}
	dec := NewDecider(conn, s.logf)
	pid := ch.cmd.Process.Pid
	giveUp := func(err error) error {
		dec.Close()
		ch.kill(s.logf, s.cfg.killAfter)
		return fmt.Errorf("the new decider (pid %d) %w", pid, err)
	}
	if err := awaitReady(dec, ch, s.stopped, s.cfg.restartTimeout); err != nil {
		return giveUp(err)
	}
	s.mu.Lock()
	select {
	case <-s.stopped: // the shutdown has taken the deciders it reaps: this one is not among them
		s.mu.Unlock()
		return giveUp(errGivenUp)
	default:
	}
	oldDec, oldChild := s.dec, s.child
	s.dec, s.child = dec, ch
	s.g.dec.Store(dec)
	oldDec.markRetired() // after the store: a query that still read the old one is handed to this one
	s.retiring[oldChild] = oldDec
	close(s.swapped)
	s.swapped = make(chan struct{})
	s.mu.Unlock()
	s.logf("decider restarted: pid %d took over from pid %d", pid, oldChild.cmd.Process.Pid)
	go s.retire(oldDec, oldChild)
	return nil
}

// retire lets a replaced decider finish what it holds (as long as a query may take), then closes and reaps it.
func (s *server) retire(dec *Decider, ch *child) {
	drain := time.NewTimer(2*s.cfg.timeout + s.g.grace)
	defer drain.Stop()
	select {
	case <-dec.drained():
	case <-dec.Done():
	case <-drain.C:
		s.logf("the replaced decider (pid %d) still holds queries after %s: closing it", ch.cmd.Process.Pid, 2*s.cfg.timeout+s.g.grace)
	case <-s.stopped:
		return
	}
	dec.Close()
	leave := time.NewTimer(s.cfg.killAfter)
	defer leave.Stop()
	select {
	case <-ch.exited:
	case <-leave.C:
		s.logf("the replaced decider (pid %d) did not exit within %s of EOF: killing it", ch.cmd.Process.Pid, s.cfg.killAfter)
		ch.kill(s.logf, s.cfg.killAfter)
	case <-s.stopped:
		return
	}
	s.mu.Lock()
	delete(s.retiring, ch)
	s.mu.Unlock()
}

// watch turns the end of the active decider's session, or of its process, into a fatal error. A decider a restart
// replaced may end as it likes.
func (s *server) watch() {
	for {
		s.mu.Lock()
		dec, ch, swapped := s.dec, s.child, s.swapped
		s.mu.Unlock()
		var err error
		select {
		case <-s.stopped:
			return
		case <-swapped:
			continue
		case <-dec.Done():
			err = fmt.Errorf("decider session ended: %w", dec.Err())
		case <-ch.exited:
			err = fmt.Errorf("decider exited: %v", ch.err)
		}
		if cur, _ := s.active(); cur != dec { // replaced while this waited: its end is the retirement's
			continue
		}
		select {
		case <-s.stopped: // our own shutdown made the decider leave
		default:
			s.failed <- err
		}
		return
	}
}

// fatal delivers the reason the gateway can no longer serve; a requested shutdown delivers nothing.
func (s *server) fatal() <-chan error { return s.failed }

func (s *server) active() (*Decider, *child) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dec, s.child
}

// shutdown stops accepting, closes the decision sockets of the active decider and of any being retired (each reads EOF
// and exits), and waits for them, killing those that do not leave in time. Everything in it, the transports' stop
// included, fits in shutdownBudget: the deciders' patience for EOF is whatever the transports left, less an eighth of
// the budget that the kills and their reaps keep.
func (s *server) shutdown() {
	s.once.Do(func() {
		deadline := time.Now().Add(s.cfg.shutdownBudget)
		s.mu.Lock()
		close(s.stopped) // under mu: a restart has either made its decider active, or sees this and gives it up
		decs, children := []*Decider{s.dec}, []*child{s.child}
		for ch, dec := range s.retiring {
			decs, children = append(decs, dec), append(children, ch)
		}
		s.mu.Unlock()
		if err := removeReady(s.cfg.readyFile); err != nil {
			s.logf("cannot remove the ready file: %v", err)
		}
		for _, dec := range decs {
			dec.Close() // first: queries blocked writing to a decider that reads nothing would hold g.stop() up to the write deadline
		}
		s.g.stop()
		patience := max(min(s.cfg.killAfter, time.Until(deadline)-s.cfg.shutdownBudget/8), 0)
		eof := time.Now().Add(patience)
		for _, ch := range children {
			if !ch.waitExit(max(time.Until(eof), 0)) {
				s.logf("the decider did not exit within %s of EOF: killing it", patience.Round(time.Millisecond))
				ch.kill(s.logf, time.Until(deadline))
			}
		}
	})
}

// publishReady writes the gateway's pid to path, mode 0600. An empty path publishes nothing.
func publishReady(path string) error {
	if path == "" {
		return nil
	}
	if err := replaceFile(path, fmt.Appendf(nil, "%d\n", os.Getpid())); err != nil {
		return fmt.Errorf("cannot write the ready file: %w", err)
	}
	return nil
}

// replaceFile writes data to a temporary file, mode 0600, in path's directory and renames it over path, so a reader sees
// all of it or none, and a symlink planted at path is replaced rather than written through.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

// executableSHA256 is the SHA-256 of the running binary, in lowercase hex.
func executableSHA256() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
