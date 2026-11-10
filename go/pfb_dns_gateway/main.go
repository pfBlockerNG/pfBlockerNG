// pfb_dns_gateway, the pfB-DNS network layer (issue #3513): serves plain DNS over UDP and TCP, and DoT, DoH and DoQ with the
// certificate pfBlockerNG writes from the pfB-DNS settings' selection; applies the Resolver ACL before anyone is asked, lets
// the DNSBL decider it boots in its own process (package decider) decide every other query, and forwards to Unbound with a
// PROXYv2 header naming the client. It is one binary: there is no separate decider process.
//
//	pfb_dns_gateway [flags]
//
// docs/misc/dns-gateway-transports.md is the encrypted transports. Log lines on stderr:
//
//	starting pid <pid>                  the first line of every start, before the decider boots
//	listening udp+tcp <host>:<port>     one per bound --listen address, once the decider has booted
//	listening dot|doh|doq <host>:<port> one per bound TLS listener
//	ready upstream <host>:<port> pid <pid>
//
// While it serves, the control socket adds a listener (`listening <kind> <host>:<port>`) or removes one
// (`stopped listening <kind> <host>:<port>`).
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
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

const (
	defaultReadyTimeout   = 300 * time.Second          // the decider boots the whole DNSBL database before the gateway serves
	defaultShutdownBudget = 4 * time.Second            // all of shutdown: the rc stop sends KILL 5 s after TERM, which would leave a stale ready file
	defaultTLSPEM         = "/var/etc/pfb_dns/tls.pem" // the certificate and key pfBlockerNG writes from the pfB-DNS settings' selection: root only
	defaultModuleDir      = "/var/unbound"             // where the DNSBL module's ini, manifest and feed files are
	defaultLogDir         = "/var/log/pfblockerng"     // where the decider writes dnsbl.log and dns_reply.log
)

type config struct {
	listen             []string
	listen53           []string
	port               int
	upstream           string
	timeout            time.Duration
	unboundConf        string
	user               string
	dotPort            int
	tlsPEM             string
	ctlSocket          string
	dotListen          []string
	dotListen853       []string
	dohListen          []string
	dohPort            int
	dohTrusted         []string
	doqListen          []string
	doqListen853       []string
	doqPort            int
	dotPort6           int // zero inherits the IPv4 port
	dohPort6           int
	doqPort6           int
	moduleDir          string // --module-dir: the DNSBL module's directory (and the observer socket's)
	logDir             string // --log-dir: where the decider writes dnsbl.log and dns_reply.log
	noModule           bool   // pfB-DNS modes: decider.Options' fields of the same names
	observer           bool
	replyLog           bool
	readyFile          string   // --ready-file: the gateway's pid is published here once it serves; "" = none
	dnsName            string   // --dns-name: DDR's target and the name answered A and AAAA; "" = none
	nameAnswers        []string // --dns-name-answer: LOCAL=ADDR[,ADDR] values, each parsed by newNameAnswers; need dnsName
	ddr                bool     // --ddr: answer resolver.arpa. and designate the encrypted transports (RFC 9462); needs dnsName
	ddrDoH443          []string // --ddr-doh-443: addresses DDR advertises DoH on without a port, each parsed by doh443Set; need ddr
	dohListen443       []string // --doh-listen-443: addresses DoH is bound on port 443
	listenerInterfaces []string

	// Test seams; the zero value is production.
	drop           func() error      // replaces the privilege drop to --user
	trace          func(step string) // called after bind and the privilege drop, and when the decider has booted (the drop hook records itself)
	readyTimeout   time.Duration
	shutdownBudget time.Duration
	interrupt      <-chan struct{} // closed on SIGINT/SIGTERM: start stops waiting for the decider
	doh443Port     int             // the port --doh-listen-443 binds, and DDR advertises as 443; zero is 443. A test cannot bind 443
	plain53Port    int             // zero is 53; tests bind a free port instead
	tls853Port     int             // zero is 853; tests bind a free port instead
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// parseConfig reads the command line. -h writes the flag defaults to usage and returns flag.ErrHelp.
func parseConfig(args []string, usage io.Writer) (config, error) {
	cfg := config{
		port: 53, upstream: "127.0.0.1:5353", timeout: 5 * time.Second, unboundConf: "/var/unbound/unbound.conf",
		tlsPEM: defaultTLSPEM, ctlSocket: defaultCtlSocket, dotPort: defaultDoTPort, dohPort: 4443, doqPort: 853,
	}
	fs := flag.NewFlagSet("pfb_dns_gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var listen, listen53 listFlag
	fs.Var(&listen, "listen", "plain DNS address (UDP and TCP), repeatable")
	fs.Var(&listen53, "listen-53", "plain DNS address on port 53 (UDP and TCP), repeatable")
	fs.IntVar(&cfg.port, "port", cfg.port, "plain DNS port; 0 picks one per address")
	fs.StringVar(&cfg.upstream, "upstream", cfg.upstream, "Unbound's proxy-protocol HOST:PORT")
	fs.DurationVar(&cfg.timeout, "timeout", cfg.timeout, "wait for Unbound per exchange")
	fs.StringVar(&cfg.unboundConf, "unbound-conf", cfg.unboundConf, "Unbound's config: the access-control rows of it and of every file it includes are the ACL")
	fs.StringVar(&cfg.user, "user", "", "give up root for this user once the sockets are bound")
	fs.IntVar(&cfg.dotPort, "dot-port", cfg.dotPort, "DoT port; 0 picks one per address")
	fs.StringVar(&cfg.tlsPEM, "tls-pem", cfg.tlsPEM, "certificate chain and private key of DoT, DoH and DoQ, one PEM file, read once at start while still root")
	fs.StringVar(&cfg.ctlSocket, "ctl-socket", cfg.ctlSocket, "Unix socket on which root pushes a renewed certificate; made in a root-only directory before the privilege drop")
	var dotListen, dotListen853, dohListen, dohTrusted, doqListen, doqListen853 listFlag
	fs.Var(&dotListen, "dot-listen", "DoT address, repeatable; no DoT addresses = DoT off")
	fs.Var(&dotListen853, "dot-listen-853", "DoT address on port 853, repeatable")
	fs.Var(&dohListen, "doh-listen", "DoH address (HTTPS GET and POST on /dns-query), repeatable; none = DoH off")
	fs.IntVar(&cfg.dohPort, "doh-port", cfg.dohPort, "DoH port; 0 picks one per address")
	fs.Var(&dohTrusted, "doh-trusted", "front end trusted to send PROXYv2 and X-Forwarded-For to DoH (CIDR or address), repeatable")
	fs.Var(&doqListen, "doq-listen", "DoQ (RFC 9250) address, repeatable; none = DoQ off")
	fs.Var(&doqListen853, "doq-listen-853", "DoQ address on UDP port 853, repeatable")
	fs.IntVar(&cfg.doqPort, "doq-port", cfg.doqPort, "DoQ UDP port; 0 picks one per address")
	fs.IntVar(&cfg.dotPort6, "dot-port6", 0, "IPv6 DoT port; 0 inherits --dot-port")
	fs.IntVar(&cfg.dohPort6, "doh-port6", 0, "IPv6 DoH port; 0 inherits --doh-port")
	fs.IntVar(&cfg.doqPort6, "doq-port6", 0, "IPv6 DoQ port; 0 inherits --doq-port")
	fs.StringVar(&cfg.moduleDir, "module-dir", defaultModuleDir, "the DNSBL module's directory: its ini, manifest and feed files; the observer's socket is made here")
	fs.StringVar(&cfg.logDir, "log-dir", defaultLogDir, "where the decider writes dnsbl.log and dns_reply.log")
	fs.BoolVar(&cfg.noModule, "no-module", false, "pfB-DNS without DNSBL: boot no module and forward every query")
	fs.BoolVar(&cfg.observer, "observer", false, "DNSBL on, Resolver forwarding: listen for the upstream observer's reports")
	fs.BoolVar(&cfg.replyLog, "reply-log", false, "log each relayed reply to dns_reply.log (needs --no-module)")
	fs.StringVar(&cfg.readyFile, "ready-file", "", "write the gateway's pid here, mode 0600, once it serves; removed at stop while it still names the gateway")
	fs.StringVar(&cfg.dnsName, "dns-name", "", "the firewall's DNS name: DDR's target, and the one name answered (A and AAAA) from the address the query reached; empty = none")
	fs.BoolVar(&cfg.ddr, "ddr", false, "answer resolver.arpa. itself and designate the encrypted transports (DDR, RFC 9462), naming --dns-name; needs --dns-name")
	var answers listFlag
	fs.Var(&answers, "dns-name-answer", "LOCAL=ADDR[,ADDR], repeatable: a query for --dns-name that reached LOCAL is answered with the ADDR of the family asked; needs --dns-name")
	var ddrDoH443, dohListen443 listFlag
	fs.Var(&ddrDoH443, "ddr-doh-443", "ADDR, repeatable: DDR leaves the port out of the DoH record on ADDR, so clients use 443 (something on 443 in front of DoH); needs --ddr")
	fs.Var(&dohListen443, "doh-listen-443", "DoH address on port 443, repeatable")
	var interfaces listFlag
	fs.Var(&interfaces, "listener-interface", "IP=BASE64UTF8 interface description for a listener address, repeatable")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(usage)
			fs.PrintDefaults()
		}
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	cfg.listen, cfg.dotListen, cfg.dohListen, cfg.dohTrusted, cfg.doqListen = listen, dotListen, dohListen, dohTrusted, doqListen
	cfg.nameAnswers, cfg.ddrDoH443, cfg.dohListen443 = answers, ddrDoH443, dohListen443
	cfg.listenerInterfaces = interfaces
	cfg.listen53, cfg.dotListen853, cfg.doqListen853 = listen53, dotListen853, doqListen853
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (c config) validate() error {
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
	if len(c.listen) == 0 && len(c.listen53) == 0 {
		return errors.New("--listen or --listen-53 is required: the addresses to serve plain DNS on")
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
	for _, p := range []struct {
		name string
		port int
	}{{"dot-port6", c.dotPort6}, {"doh-port6", c.dohPort6}, {"doq-port6", c.doqPort6}} {
		if p.port < 0 || p.port > 65535 {
			return fmt.Errorf("--%s %d is outside 0..65535", p.name, p.port)
		}
	}
	if !c.ddr && len(c.ddrDoH443) > 0 {
		return errors.New("--ddr-doh-443 needs --ddr")
	}
	if c.ddr && c.dnsName == "" {
		return errors.New("--ddr needs --dns-name")
	}
	if c.dnsName == "" && len(c.nameAnswers) > 0 {
		return errors.New("--dns-name-answer needs --dns-name")
	}
	if c.dnsName != "" {
		if _, err := newNameAnswers(c.dnsName, c.nameAnswers); err != nil {
			return err
		}
	}
	if _, err := doh443Set(c.ddrDoH443); err != nil {
		return err
	}
	for _, fixed := range []struct {
		flag   string
		values []string
	}{{"listen-53", c.listen53}, {"dot-listen-853", c.dotListen853}, {"doh-listen-443", c.dohListen443}, {"doq-listen-853", c.doqListen853}} {
		for _, host := range fixed.values {
			if host == "" {
				return fmt.Errorf("--%s must not be empty", fixed.flag)
			}
			if _, err := parseNameIP(host); err != nil {
				return fmt.Errorf("--%s %.64q: %w", fixed.flag, host, err)
			}
		}
	}
	host, port, err := net.SplitHostPort(c.upstream)
	if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		return fmt.Errorf("--upstream %q: want HOST:PORT", c.upstream)
	}
	return nil
}

// frontend is the decider the gateway asks: (*decider.Frontend) in production.
type frontend interface {
	Resolve(wire []byte, clientIP string, fwd func([]byte) []byte, transport, listenerIP, listenerInterface string) []byte
	Close()
}

// openFrontend boots the decider. A test replaces it with a fake.
var openFrontend = func(opts decider.Options) (frontend, error) {
	f, err := decider.Open(opts)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// server is a started gateway: listeners bound, decider booted, serving.
type server struct {
	cfg      config
	logf     func(format string, args ...any)
	g        *gateway
	frontend frontend
	once     sync.Once
}

// start logs `starting pid`, binds every --listen address (one that fails is logged and skipped), gives up root, boots the
// decider in this process, reports readiness and begins serving. On any error nothing is left running or bound.
func start(cfg config, logf func(format string, args ...any)) (*server, error) {
	logf("starting pid %d", os.Getpid()) // first, so that a reader of the log finds where this start begins
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
	if cfg.shutdownBudget == 0 {
		cfg.shutdownBudget = defaultShutdownBudget
	}
	var binSum string
	var binErr error
	if cfg.readyFile != "" {
		binSum, binErr = executableSHA256() // now: an update replaces the file this process was started from
	}

	acl := NewACL(cfg.unboundConf, logf)
	refused := map[string]string{} // start-time bind refusals, for the list verb
	var listeners []*plainListener
	for _, requested := range []struct {
		hosts []string
		port  int
	}{{cfg.listen, cfg.port}, {cfg.listen53, cfg.port53()}} {
		for _, host := range requested.hosts {
			ap, _ := bindAddr(host, requested.port)
			if slices.ContainsFunc(listeners, func(l *plainListener) bool { return l.addr() == ap }) {
				continue
			}
			l, err := bindPlain(host, requested.port)
			if err != nil {
				logf("%v", err)
				refuse(refused, "udp+tcp", host, requested.port, err)
				continue
			}
			listeners = append(listeners, l)
		}
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
	secure = bindTLS(cfg, logf, refused) // the certificate file is read, and the sockets are bound, before the privilege drop
	if cfg.ctlSocket != "" {             // in every mode
		var err error
		var certs *certStore
		if secure != nil {
			certs = secure.certs
		}
		if ctl, err = bindCtl(cfg.ctlSocket, certs, logf); err != nil {
			logf("control socket: %v; the certificate cannot be renewed without a restart", err)
		}
	}
	var names *nameAnswers
	if cfg.dnsName != "" {
		var err error
		if names, err = newNameAnswers(cfg.dnsName, cfg.nameAnswers); err != nil {
			closeListeners()
			return nil, err
		}
	}
	var ddrAnswers *ddr
	if cfg.ddr {
		var err error
		if ddrAnswers, err = ddrOnListeners(cfg, secure); err != nil {
			closeListeners()
			return nil, err
		}
	}
	trace("bind")

	// The drop comes before the boot, as the Python decider's did: the module opens its files as the unprivileged user.
	if drop != nil {
		if err := drop(); err != nil {
			closeListeners()
			return nil, err
		}
	}
	fe, err := bootDecider(cfg)
	if err != nil {
		closeListeners()
		return nil, err
	}
	trace("ready")

	g := newGateway(acl, fe.Resolve, newUpstream(cfg.upstream, cfg.timeout), cfg.timeout, logf)
	g.ddr, g.names = ddrAnswers, names
	interfaces := listenerInterfaceTable(cfg.listenerInterfaces, logf)
	g.listenerInterfaces.Store(&interfaces)
	s := &server{cfg: cfg, logf: logf, g: g, frontend: fe}
	set := newListenerSet(g, cfg, secure)
	set.refused = refused // the binds above record into it before the set exists
	for _, l := range listeners {
		set.track("udp+tcp", l.addr(), g.serve(l))
	}
	secure.serve(set)
	if ctl != nil {
		ctl.listeners, ctl.names, ctl.ddr = set, names, ddrAnswers
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
	return s, nil
}

// bootDecider boots the decider, giving up after readyTimeout or when cfg.interrupt closes (errInterrupted). Open runs on
// its own goroutine so that neither waits for it; a result that arrives after the wait ended is Closed.
func bootDecider(cfg config) (frontend, error) {
	type booted struct {
		f   frontend
		err error
	}
	done := make(chan booted, 1)
	go func() {
		f, err := openFrontend(decider.Options{ModuleDir: cfg.moduleDir, LogDir: cfg.logDir, NoModule: cfg.noModule, ReplyLog: cfg.replyLog, Observer: cfg.observer})
		done <- booted{f, err}
	}()
	bound := time.NewTimer(cfg.readyTimeout)
	defer bound.Stop()
	var err error
	select {
	case b := <-done:
		if b.err != nil {
			return nil, fmt.Errorf("decider: %w", b.err)
		}
		return b.f, nil
	case <-cfg.interrupt:
		err = errInterrupted
	case <-bound.C:
		err = fmt.Errorf("decider did not boot within %s", cfg.readyTimeout)
	}
	go func() {
		if b := <-done; b.f != nil {
			b.f.Close()
		}
	}()
	return nil, err
}

// shutdown stops accepting and drains the queries in flight, then closes the decider: Close does not wait for a query
// and stops what a query writes to. Everything in it fits in shutdownBudget; a decider that is not closed by then is
// left to the exit of the process.
func (s *server) shutdown() {
	s.once.Do(func() {
		deadline := time.Now().Add(s.cfg.shutdownBudget)
		if err := removeReady(s.cfg.readyFile); err != nil {
			s.logf("cannot remove the ready file: %v", err)
		}
		s.g.stop()
		closed := make(chan struct{})
		go func() { s.frontend.Close(); close(closed) }()
		left := time.NewTimer(max(time.Until(deadline), 0))
		defer left.Stop()
		select {
		case <-closed:
		case <-left.C:
			s.logf("the decider did not close within %s: leaving it to the exit", s.cfg.shutdownBudget)
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

var errInterrupted = errors.New("interrupted while the decider booted")

func realMain(args []string, stderr io.Writer) int {
	logger := log.New(stderr, "", 0)
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		logger.Printf("pfb_dns_gateway: %v\nusage: pfb_dns_gateway [flags]   (-h lists the flags)", err)
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
	<-ctx.Done()
	srv.shutdown()
	return 0
}

func main() { os.Exit(realMain(os.Args[1:], os.Stderr)) }
