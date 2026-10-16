"""Research harness for #3508: do clients with different access-control tags
share an in-flight Unbound mesh state? A Python module bypasses 127.0.0.2 and
127.0.0.5 (both tagged "bypass") and
answers NXDOMAIN to every other client; overlapping and sequential queries
show which client's answer each recipient receives.

Usage:
    PYTHONPATH=<unbound>/pythonmod [BYPASS_NO_CACHE=1]
    python3 3508-mesh-harness.py <unbound binary> <yes|no|absent>
"""

import os
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import Counter

UB = sys.argv[1]
ISOLATE = sys.argv[2]  # "yes" / "no" / "absent"
D = "/tmp/ubtest/run-" + ISOLATE
os.makedirs(D, exist_ok=True)
UP_PORT, UB_PORT = 15399, 15353
upstream = Counter()


def qname_of(pkt: bytes, off: int = 12) -> tuple[str, int]:
    labels = []
    while pkt[off]:
        n = pkt[off]
        labels.append(pkt[off + 1 : off + 1 + n].decode())
        off += 1 + n
    return ".".join(labels), off + 1


def stub() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UP_PORT))

    seq = [0]

    def answer(pkt: bytes, addr: tuple) -> None:
        name, off = qname_of(pkt)
        qtype = struct.unpack("!H", pkt[off : off + 2])[0]
        upstream[(name, qtype)] += 1
        seq[0] += 1
        n = seq[0]
        time.sleep(1.0)
        q = pkt[12 : off + 4]
        if qtype == 1:
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, n])
            body, an, ns = q + rr, 1, 0
        elif qtype == 16:
            txt = str(n).encode()
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 300, len(txt) + 1) + bytes([len(txt)]) + txt
            body, an, ns = q + rr, 1, 0
        else:
            soa = b"\x00\x00" + struct.pack("!IIIII", n, 1, 1, 1, 300)
            rr = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, 300, len(soa)) + soa
            body, an, ns = q + rr, 0, 1
        hdr = pkt[:2] + struct.pack("!HHHHH", 0x8180, 1, an, ns, 0)
        s.sendto(hdr + body, addr)

    while True:
        pkt, addr = s.recvfrom(4096)
        threading.Thread(target=answer, args=(pkt, addr), daemon=True).start()


MOD = (
    """
import os
def init(id, cfg): return True
def deinit(id): return True
def inform_super(id, qstate, superqstate, qdata): return True
def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW:
        ips = []
        r = qstate.mesh_info.reply_list if qstate.mesh_info else None
        while r:
            if r.query_reply: ips.append(r.query_reply.addr)
            r = r.next
        with open("%s/operate.log", "a") as f:
            f.write("%%s %%d %%s\\n" %% (qstate.qinfo.qname_str, qstate.qinfo.qtype, ",".join(ips)))
        # policy: tagged 127.0.0.2 and 127.0.0.5 bypass, every other client is blocked (NXDOMAIN)
        if ips and ips[0] not in ("127.0.0.2", "127.0.0.5") and not qstate.qinfo.qname_str.startswith("ready."):
            qstate.return_rcode = RCODE_NXDOMAIN
            qstate.no_cache_store = 1
            qstate.ext_state[id] = MODULE_FINISHED
            return True
        if os.environ.get("BYPASS_NO_CACHE") == "1":
            qstate.no_cache_store = 1  # bypassed answers never enter the shared cache
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True
    if event == MODULE_EVENT_MODDONE:
        qstate.ext_state[id] = MODULE_FINISHED
        return True
    qstate.ext_state[id] = MODULE_WAIT_MODULE
    return True
"""
    % D
)

open(f"{D}/mod.py", "w").write(MOD)
open(f"{D}/operate.log", "w").close()
opt = "" if ISOLATE == "absent" else f"    mesh-isolate-client-tags: {ISOLATE}\n"
open(f"{D}/unbound.conf", "w").write(f"""server:
    interface: 127.0.0.1
    port: {UB_PORT}
    username: ""
    chroot: ""
    directory: "{D}"
    pidfile: "{D}/unbound.pid"
    use-syslog: no
    logfile: "{D}/unbound.log"
    verbosity: 1
    unknown-server-time-limit: 4000
    num-threads: 1
    do-not-query-localhost: no
    module-config: "python iterator"
    access-control: 127.0.0.0/8 allow
    define-tag: "bypass"
    access-control-tag: 127.0.0.2/32 "bypass"
    access-control-tag: 127.0.0.5/32 "bypass"
{opt}python:
    python-script: "{D}/mod.py"
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@{UP_PORT}
""")
chk = subprocess.run([UB + "-checkconf", f"{D}/unbound.conf"], capture_output=True, text=True)
print("checkconf:", chk.returncode, (chk.stdout + chk.stderr).strip())
threading.Thread(target=stub, daemon=True).start()
proc = subprocess.Popen([UB, "-d", "-c", f"{D}/unbound.conf"])
deadline = time.time() + 15
while True:
    try:
        ask_ready = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ask_ready.settimeout(3)
        q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x05ready\x07example\x00" + struct.pack("!HH", 1, 1)
        ask_ready.sendto(q, ("127.0.0.1", UB_PORT))
        ask_ready.recvfrom(4096)
        break
    except OSError:
        if time.time() > deadline:
            raise


answers: dict[str, str] = {}


def ask(src: str, name: str, qtype: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.settimeout(10)
    q = struct.pack("!HHHHHH", os.getpid() & 0xFFFF, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q += struct.pack("!HH", qtype, 1)
    s.sendto(q, ("127.0.0.1", UB_PORT))
    try:
        r, _ = s.recvfrom(4096)
    except TimeoutError:
        answers[src] = "TIMEOUT"
        return
    rcode = r[3] & 0xF
    # last bytes carry the per-upstream-query sequence (A octet / TXT / SOA serial)
    answers[src] = f"rcode={rcode} tail={r[-24:].hex()[-12:]}"


CASES = [
    ("mixed", ["127.0.0.2", "127.0.0.3"]),  # bypass first, then blocked client
    ("rev", ["127.0.0.3", "127.0.0.2"]),  # blocked client first, then bypass
    ("sametag", ["127.0.0.2", "127.0.0.5"]),  # two bypass clients, same tag
    ("later", ["127.0.0.2", "127.0.0.3"]),  # sequential: bypass resolves, blocked client asks after
]
try:
    for label, srcs in CASES:
        for qtype in (1, 16, 65):
            name = f"{label}-{qtype}.example"
            answers.clear()
            ts = [threading.Thread(target=ask, args=(src, name, qtype)) for src in srcs]
            for t in ts:
                t.start()
                if label == "later":
                    t.join()
                time.sleep(0.05)
            for t in ts:
                t.join()
            print(
                f"{label:5} qtype={qtype:<3} upstream={upstream[(name, qtype)]} "
                + " ".join(f"{k}:{v}" for k, v in sorted(answers.items()))
            )
finally:
    proc.terminate()
    proc.wait()
print(open(f"{D}/operate.log").read())
