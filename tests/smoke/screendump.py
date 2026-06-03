#!/usr/bin/env python3
"""Capture the guest VGA framebuffer via QEMU's QMP socket.

Used by the ADR-04 smoke-spike workflow to diagnose a stuck/headless boot.
QEMU runs with ``-display none``, so when a boot wedges and the image has no
serial console enabled, the VGA framebuffer is the only window in. This
connects to QEMU's QMP control socket and issues ``screendump``, preferring a
PNG and falling back to the always-supported PPM if the QEMU build rejects the
``format`` argument (added in QEMU 7.1).

Stdlib only (socket + json) — no third-party deps, same discipline as the
shipped plugin.
"""

from __future__ import annotations

import json
import socket
import sys
import time
from typing import TextIO


def _connect(path: str, timeout: float = 30.0) -> socket.socket:
    """Connect to the QMP unix socket, retrying until QEMU has created it."""
    deadline = time.monotonic() + timeout
    last: OSError | None = None
    while time.monotonic() < deadline:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(path)
            return sock
        except OSError as exc:
            last = exc
            sock.close()
            time.sleep(0.5)
    raise SystemExit(f"screendump: could not connect to QMP socket {path}: {last}")


def _recv_json(stream: TextIO) -> dict:
    line = stream.readline()
    if not line:
        raise SystemExit("screendump: QMP socket closed unexpectedly")
    return json.loads(line)


def _execute(sock: socket.socket, stream: TextIO, command: str, arguments: dict | None = None) -> dict:
    """Send one QMP command and return the first non-event reply."""
    msg: dict = {"execute": command}
    if arguments:
        msg["arguments"] = arguments
    sock.sendall((json.dumps(msg) + "\r\n").encode())
    while True:
        reply = _recv_json(stream)
        if "event" in reply:  # asynchronous events are noise here
            continue
        return reply


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: screendump.py <qmp-unix-socket> <out-file>", file=sys.stderr)
        return 2
    qmp_path, out = argv[1], argv[2]

    sock = _connect(qmp_path)
    with sock, sock.makefile("r", encoding="utf-8") as stream:
        _recv_json(stream)  # QMP greeting
        _execute(sock, stream, "qmp_capabilities")

        reply = _execute(sock, stream, "screendump", {"filename": out, "format": "png"})
        if "error" in reply:
            # Older QEMU without the `format` arg: retry as PPM.
            ppm = out.rsplit(".", 1)[0] + ".ppm"
            reply = _execute(sock, stream, "screendump", {"filename": ppm})
            if "error" in reply:
                print(f"screendump: failed: {reply['error']}", file=sys.stderr)
                return 1
            print(f"screendump: wrote {ppm} (PPM fallback)")
            return 0
        print(f"screendump: wrote {out}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
