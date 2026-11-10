// Go translation of serve_decisions and parse_args' two flag rules of src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py,
// with the decision protocol and its socket left out: the gateway calls Resolve in its own process. Open is what
// serve_decisions did before it served (the module boot, the reply log, the observer socket), Close its `finally`.
package decider

import (
	"errors"
	"fmt"
)

// Options are pfb_dns_proxy.py's flags.
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
// unlinked, its reader ended, so that no report meets a closed module), the module deinits, the reply log closes. Each of
// the four waits (observer reader, reload, control and query watchers) is bounded by watcherStopWait, so Close takes at
// most four times it: what does not stop in time is logged and left. Close is idempotent. The caller stops calling
// Resolve before it: a query in flight meets a module whose log writer and databases are closing.
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
