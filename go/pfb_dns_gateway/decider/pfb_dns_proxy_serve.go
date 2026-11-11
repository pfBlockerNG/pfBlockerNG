// Ported from serve_decisions and parse_args' two flag rules of src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py (removed in #3791),
// with the decision protocol and its socket left out: the gateway calls Resolve in its own process. Open is what
// serve_decisions did before it served (the module boot, the reply log, the observer socket), Close its `finally`.
package decider

import (
	"errors"
	"fmt"
)

// Options are the flags of pfb_dns_proxy.py (removed in #3791).
type Options struct {
	ModuleDir string // the module dir (/var/unbound): pfb_unbound.ini, manifest, feed files; observer socket lives here
	NoModule  bool   // boot no module: every query is forwarded (Python --no-module)
	ReplyLog  bool   // with NoModule: log each relayed reply to dns_reply.log (Python --reply-log)
	Observer  bool   // listen for pfb_upstream_observer.py's reports on <ModuleDir>/pfb_upstream.sock
	LogDir    string // where the module and the reply log write dnsbl.log and dns_reply.log; empty is /var/log/pfblockerng
}

// Open boots the decider: the module (unless NoModule), then the reply log (ReplyLog), then the observer socket
// (Observer). A flag combination argparse refuses (ReplyLog without NoModule, Observer with it) or a module that cannot
// initialise is the returned error, with nothing left running. A reply log or an observer socket that cannot be opened is
// logged once and the decider serves without it: DNS must not go down with them.
func Open(opts Options) (*Frontend, error) {
	if opts.ReplyLog && !opts.NoModule {
		return nil, errors.New("--reply-log needs --no-module: the module logs its own replies")
	}
	if opts.Observer && opts.NoModule {
		return nil, errors.New("--observer cannot be used with --no-module")
	}
	var module *pfbUnbound
	if !opts.NoModule {
		var err error
		if module, err = boot(opts.ModuleDir, opts.LogDir); err != nil {
			return nil, err
		}
	}
	f := newFrontend(module)
	if opts.ReplyLog {
		f.replyLog = openReplyLog(opts.LogDir)
	}
	if opts.Observer {
		// before the gateway serves: it serves only once the module can hear Unbound
		observer, err := f.listenObserver(opts.ModuleDir)
		if err != nil {
			logErr(fmt.Sprintf("upstream-block detection is off: cannot listen on %s: %v", observerSocketName, err))
		}
		f.observer = observer
	}
	return f, nil
}

// Close shuts down what Open started, in serve_decisions's `finally` order: the observer stops (its socket closed and
// unlinked, its reader ended, so that no report meets a closed module), the module deinits, the reply log closes. The waits
// for the observer reader and the reload, control and query watchers are each bounded by watcherStopWait, and the one for the
// database worker by dbStopWait: what does not stop in time is logged and left. The log writer's stop (it writes what is
// queued), the database close and the GeoIP reader's close (it waits for the lookups in flight) wait without a bound. Close is
// idempotent. A query still inside Resolve when Close runs (the gateway closes the decider after its drain bound, whatever a
// query is doing) is safe: it writes no log row, its counter write finds the database closed, and a GeoIP lookup of it
// finishes before the reader closes.
func (f *Frontend) Close() {
	f.closeOnce.Do(func() {
		if f.observer != nil {
			f.observer.close()
		}
		if f.module != nil {
			f.module.deinit()
		}
		if f.replyLog != nil {
			f.replyLog.closeReplyLog()
		}
	})
}
