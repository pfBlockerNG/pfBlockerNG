"""The DNS Reply log of pfB-DNS with DNSBL off (issue #3515), written by the shipped pfb_unbound.py's own row writer.

`pfb_dns_proxy.py --no-module --reply-log` stays a plain forwarder: no feed is read, no query is decided, none of the
module's DNSBL lifecycle runs. For each reply it relays, it fills the row the module fills in module mode (the same
get_details_reply(), so the same columns, escaping and r_addr values) and writes it to the same file through the same
asynchronous pipeline, so Reports and Stats read it like a module row. The rows are the module mode's, call for call:
the pass after Unbound's reply (MODDONE) logs a "reply" row, and a SERVFAIL (Unbound's, or the proxy's own when Unbound
stays silent) goes through the module's servfail callback as it does in module mode, which makes a SERVFAIL Unbound
sent two rows there and here.

What init_standard() would have set up for that one function is all that is set up here: the DNS Reply Logging switch,
the RCODE names, an empty noAAAA table, the GeoIP reader (as the module opens it, when its database is installed) and
the log pipeline. pfb_unbound.py is imported from the shipped source, never from --module-dir, which --no-module need
not even have. The module is imported unchanged and read-only; nothing in it is patched.
"""

from __future__ import annotations

import os
import traceback
from collections import defaultdict
from typing import Any

import dnswire
import unbound_shim as shim

SHIPPED_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # where pfb_unbound.py ships
GEOIP_DB = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb"  # init_standard() sets pfb["maxminddb"] to this
RCODE_SERVFAIL = 2
RCODES = {  # init_standard() builds rcodeDB from this table; a test holds the two equal
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDOMAIN",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
    11: "DSOTYPENI",
    16: "BADVERS",
    17: "BADKEY",
    18: "BADTIME",
    19: "BADMODE",
    20: "BADNAME",
    21: "BADALG",
    22: "BADTRUNC",
    23: "BADCOOKIE",
}


class ReplyLog:
    """The module's reply logging, set up for a proxy that hosts no module. Call it with each query, its client and
    Unbound's reply (None when Unbound said nothing); close() when the proxy stops, which flushes the queued rows."""

    def __init__(self) -> None:
        here = os.getcwd()
        try:
            self.module: Any = shim.install(SHIPPED_DIR)  # imports it; --no-module keeps its working directory
        finally:
            os.chdir(here)
        self._failed = False
        try:
            self._setup()
        except BaseException:
            shim.uninstall()
            raise

    def _setup(self) -> None:
        module = self.module
        module.pfb.update(python_reply=True, python_maxmind=False, sqlite3_resolver_con=False)
        module.rcodeDB = RCODES
        module.noAAAADB = defaultdict(str)
        if module.pfb["mod_maxminddb"] and os.path.isfile(GEOIP_DB):
            try:
                module.maxmindReader = module.maxminddb.open_database(GEOIP_DB)
                module.pfb["python_maxmind"] = True
            except Exception as exc:
                shim.log_err(f"GeoIP database {GEOIP_DB} not opened, the GeoIP column stays unk: {exc}")
        module.pfb_setup_logging()
        if not module.pfb["log_listener"]:  # it said why on stderr; the fallback would append from the event loop
            if module.pfb["python_maxmind"]:
                module.maxmindReader.close()
            raise RuntimeError("the log pipeline did not start")
        shim.register_inplace_cb_reply_servfail(module.inplace_cb_reply_servfail, shim.module_env(), shim.MODULE_ID)
        shim.log_info("DNS Reply logging is on: pfb_unbound.py is loaded for its row writer only, no DNSBL runs")

    def close(self) -> None:
        module = self.module
        try:
            module.pfb_log_listener.stop()  # writes what is still queued
            if module.pfb["python_maxmind"]:
                module.maxmindReader.close()
        finally:
            shim.uninstall()

    def __call__(self, query: dnswire.Message, client_ip: str, reply: bytes | None) -> None:
        """Log one answered query. Never raises: a log that fails costs a row and one error line, never the answer."""
        try:
            self._log(query, client_ip, reply)
        except Exception:
            if not self._failed:
                self._failed = True
                shim.log_err(f"DNS Reply logging failed, further failures are silent: {traceback.format_exc()}")

    def _log(self, query: dnswire.Message, client_ip: str, reply: bytes | None) -> None:
        question = query.questions[0]
        qstate = shim.module_qstate(
            shim.query_info(question.name, question.qtype, question.qclass), client_ip, 0, query.flags
        )
        if reply is None:  # Unbound did not answer: the proxy sends the client a SERVFAIL
            qstate.return_rcode = RCODE_SERVFAIL
            shim.fire_reply_callback("reply_servfail", qstate, None, RCODE_SERVFAIL)
            return
        parsed = dnswire.parse(reply)  # a reply that does not parse is relayed as it is and logs nothing
        # As the proxy's module mode: an error rcode is the return_rcode, NXDOMAIN stays in the reply flags.
        rcode = parsed.rcode if parsed.rcode not in (shim.RCODE_NOERROR, shim.RCODE_NXDOMAIN) else 0
        message = qstate.return_msg = shim.DnsMsg.from_message(parsed, question)
        qstate.return_rcode = rcode
        self.module.get_details_reply("reply", None, qstate, message.rep, {"pfb_addr": client_ip})
        if rcode == RCODE_SERVFAIL:
            shim.fire_reply_callback("reply_servfail", qstate, message.rep, rcode)
