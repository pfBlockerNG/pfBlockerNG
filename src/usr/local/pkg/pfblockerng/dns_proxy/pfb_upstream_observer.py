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

One JSON datagram per upstream response, sent to the Unix socket SOCKET:
    {"client": address, "qname": text, "qtype": number, "flags": wire header flags (RCODE in the low 4 bits),
     "opts": [[EDNS option code, data as hex], ...]}

Installed as /var/unbound/pfb_upstream_observer.py and named by `python-script:`. SOCKET is relative to Unbound's
working directory (its chroot, /var/unbound), where the proxy creates it (pfb_dns_proxy.py OBSERVER_SOCKET).
An answer is never delayed or changed: the send does not block, and a proxy that is not listening just loses the report.
Standard library only.
"""

import json
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

_sock: socket.socket | None = None
_warned = False


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


def relay_upstream_response(qstate, response, **kwargs):
    global _warned
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
            _sock.sendto(json.dumps(report).encode(), SOCKET)
    except OSError:
        pass  # the proxy is not listening, or its socket is full: the report is lost, the answer is not
    except Exception as exc:  # noqa: BLE001
        if not _warned:  # once: this runs for every upstream response
            _warned = True
            log_warn(f"pfb_upstream_observer: cannot report an upstream response: {exc!r}")
    return True
