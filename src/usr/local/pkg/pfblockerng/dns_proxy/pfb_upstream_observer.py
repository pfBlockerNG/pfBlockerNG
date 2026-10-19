# pfb_upstream_observer.py
# pfBlockerNG - Unbound python script for upstream-block detection while the DNS proxy hosts pfb_unbound.py
#
# part of pfSense (https://www.pfsense.org)
# Licensed under the Apache License, Version 2.0, as pfb_unbound.py.

"""Reports each RAW upstream response to the DNS proxy (issue #267); runs inside Unbound, changes nothing.

In proxy mode pfb_unbound.py runs in the proxy, and Unbound rewrites every reply it sends: RA set, AA clear, the
upstream's EDNS options (Extended DNS Errors) dropped. Only a callback on the raw upstream response can tell an upstream
block (NXRA, EDE 15/17) from an ordinary answer, so while the Resolver forwards Unbound runs this script as its python
module. It relays the facts and nothing else; the proxy classifies and logs them with the module's own code.

One JSON datagram per upstream response, at most MAX_REPORT_BYTES, sent to the Unix socket SOCKET:
    {"client": address, "qname": text, "qtype": number, "flags": wire header flags (RCODE in the low 4 bits),
     "opts": [[EDNS option code, data as hex], ...]}

Installed as /var/unbound/pfb_upstream_observer.py and named by `python-script:`. SOCKET is relative to Unbound's
working directory (its chroot, /var/unbound), where the proxy creates it (pfb_dns_proxy.py OBSERVER_SOCKET) when it is
started with --observer. Without that file the script does nothing, so it may stay loaded whenever the proxy is not
listening for reports. An answer is never delayed or changed: the send does not block, and a proxy that stops
listening just loses the report.
Standard library only.
"""

import json
import os
import socket
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Names Unbound's embedded Python injects into a script's globals; imported only so type checkers can resolve them.
    from unboundmodule import (  # noqa: F401
        MODULE_ERROR,
        MODULE_EVENT_MODDONE,
        MODULE_EVENT_NEW,
        MODULE_EVENT_PASS,
        MODULE_FINISHED,
        MODULE_WAIT_MODULE,
        log_warn,
        register_inplace_cb_query_response,
    )

SOCKET = "pfb_upstream.sock"
# Mirror of the decider's limits (pfb_dns_proxy.py); test_upstream_observer checks the copies agree. One report is one
# datagram, and 2 KiB is the default AF_UNIX datagram size on FreeBSD (net.local.dgram.maxdgram; not probed on a box).
MAX_REPORT_BYTES = 2048
MAX_REPORT_OPTIONS = 8
MAX_REPORT_OPTION_HEX = 1024
EDE_OPTION = 15  # RFC 8914 Extended DNS Error: what classifies an upstream block

_sock: socket.socket | None = None
_warned = False
_lost = 0  # reports the proxy did not get, since Unbound loaded the script
_losing = False  # inside a burst of losses: one warning for the burst


def init_standard(id, env):
    global _sock
    try:
        _sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        _sock.setblocking(False)
    except OSError as exc:
        log_warn(f"pfb_upstream_observer: no socket, upstream blocks will not be logged: {exc}")
        return True  # Unbound must start either way
    if not register_inplace_cb_query_response(relay_upstream_response, env, id):
        log_warn("pfb_upstream_observer: cannot register the upstream response callback")
    return True


def deinit(id):
    if _sock is not None:
        _sock.close()
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
    elif event == MODULE_EVENT_MODDONE:
        qstate.ext_state[id] = MODULE_FINISHED
    else:
        qstate.ext_state[id] = MODULE_ERROR
    return True


def _encoded(report: dict, opts: list) -> bytes:
    return json.dumps(dict(report, opts=opts)).encode()


def _datagram(report: dict) -> bytes | None:
    """The report as one datagram the decider accepts, or None when it cannot be sent whole. Extended DNS Error options
    go first and the rest keep their order; an option the decider would refuse is left out. The EDE option is the block
    itself, so a report that cannot carry it is lost."""
    kept: list = []
    for code, data in sorted(report["opts"], key=lambda opt: opt[0] != EDE_OPTION):
        option = [code, data]
        fits = (
            len(kept) < MAX_REPORT_OPTIONS
            and len(data) <= MAX_REPORT_OPTION_HEX
            and len(_encoded(report, [*kept, option])) <= MAX_REPORT_BYTES
        )
        if fits:
            kept.append(option)
        elif code == EDE_OPTION:
            return None
    datagram = _encoded(report, kept)
    return datagram if len(datagram) <= MAX_REPORT_BYTES else None


def _report_lost(reason: str) -> None:
    """Count one report that did not reach the proxy; one warning for each burst of such losses."""
    global _lost, _losing
    _lost += 1
    if not _losing:  # one warning for a burst of losses, however many reports it takes
        _losing = True
        log_warn(f"pfb_upstream_observer: upstream report lost ({reason}); {_lost} lost so far")


def relay_upstream_response(qstate, response, **kwargs):
    global _warned, _losing
    # No socket file: no proxy asked for reports, so build nothing (this runs for every upstream response).
    if not os.path.exists(SOCKET):
        return True
    try:
        reply_list = qstate.mesh_info.reply_list
        report = {
            "client": str(reply_list.query_reply.addr) if reply_list is not None else "",
            "qname": qstate.qinfo.qname_str,
            "qtype": qstate.qinfo.qtype,
            "flags": response.rep.flags,
            "opts": [[int(opt.code), bytes(opt.data).hex()] for opt in qstate.edns_opts_back_in_iter],
        }
        if _sock is not None:
            datagram = _datagram(report)
            if datagram is None:
                _report_lost(f"does not fit a datagram of {MAX_REPORT_BYTES} bytes")
            else:
                _sock.sendto(datagram, SOCKET)
                _losing = False
    except OSError as exc:
        # the proxy is not listening, or its socket is full: the report is lost, the answer is not
        _report_lost(str(exc))
    except Exception as exc:  # noqa: BLE001
        if not _warned:  # once: this runs for every upstream response
            _warned = True
            log_warn(f"pfb_upstream_observer: cannot report an upstream response: {exc!r}")
    return True
