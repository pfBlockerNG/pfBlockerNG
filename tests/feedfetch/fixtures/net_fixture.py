#!/usr/bin/env python3
"""Network stand-ins of the feed-transfer parity corpus (tests/feedfetch/fixtures/parity): a forward proxy and a TLS
front. Both corpus runners start this script, so the PHP side and the Go side meet one implementation; stdlib only,
loopback only (every socket binds 127.0.0.1, every outgoing connection goes to 127.0.0.1).

  net_fixture.py proxy --name NAME --log FILE [--user U --password P]
      A forward proxy: an absolute-form request (http) is relayed to 127.0.0.1:<the target's port> in origin form, a
      CONNECT (https) is tunnelled to 127.0.0.1:<the target's port>. The target's host name is never resolved: the
      corpus's names are fictional and the port alone names the origin server. With --user and --password the proxy
      demands Basic credentials: any other request, with or without Proxy-Authorization, is answered 407 with a Basic
      challenge. Each request is recorded in the log, before it is answered, as {"server", "method", "target"} plus
      "proxy_authorization" (the header's value) when one was sent.

  net_fixture.py tls --name NAME --log FILE --cert PEM --key PEM --backend PORT [--plain-too]
      A TLS terminator: every TLS connection is recorded, before the handshake starts, as {"server", "tls": "connect"}
      (a handshake the client aborts is still a connection; recording first is what lets a runner count it without a
      race), then the decrypted stream is relayed to the plain HTTP server on 127.0.0.1:PORT. With --plain-too the
      first byte of a connection decides (0x16 is a TLS handshake) and anything else is relayed as plain HTTP,
      unrecorded: one port that serves both schemes, so a redirect can change the scheme and nothing else.

Readiness: once the listening socket is bound the script prints one line, "ready <port>", on stdout and flushes it.
Connections idle for 30 s are dropped; the runners terminate the process when the scenario ends.
"""

import argparse
import base64
import json
import os
import socket
import socketserver
import ssl
import threading
from typing import Any, cast

IDLE = 30
HEAD_LIMIT = 65536

BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
NEEDS_AUTH = (
    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
    b'Proxy-Authenticate: Basic realm="corpus"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
)


def record(path: str, rec: dict[str, str]) -> None:
    # One O_APPEND write per record: the PHP router, the Go servers and this script share the log.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(rec, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)


def read_head(conn: socket.socket) -> tuple[str | None, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk or len(buf) + len(chunk) > HEAD_LIMIT:
            return None, b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode("latin-1"), rest


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except (OSError, ValueError):
            pass


def relay(a: socket.socket, b: socket.socket) -> None:
    """Copy both ways until both directions end."""
    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()


def dial(port: str | int) -> socket.socket | None:
    try:
        return socket.create_connection(("127.0.0.1", int(port)), timeout=IDLE)
    except (OSError, ValueError):
        return None


class Fixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, handler: type[socketserver.BaseRequestHandler], opts: argparse.Namespace) -> None:
        self.opts = opts
        self.context: ssl.SSLContext | None = None
        super().__init__(("127.0.0.1", 0), handler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client that vanished mid-flight is not the fixture's failure


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        o = cast(Fixture, self.server).opts
        conn: socket.socket = self.request
        conn.settimeout(IDLE)
        head, rest = read_head(conn)
        if head is None:
            return
        lines = head.split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            return
        headers = []
        auth = None
        for line in lines[1:]:
            name = line.partition(":")[0].strip().lower()
            if name == "proxy-authorization":
                auth = line.partition(":")[2].strip()
            elif name not in ("proxy-connection", "connection"):
                headers.append(line)
        rec = {"server": o.name, "method": method, "target": target}
        if auth is not None:
            rec["proxy_authorization"] = auth
        record(o.log, rec)

        if o.user is not None:
            want = "Basic " + base64.b64encode(f"{o.user}:{o.password}".encode()).decode()
            if auth != want:
                conn.sendall(NEEDS_AUTH)
                return

        if method == "CONNECT":
            upstream = dial(target.rsplit(":", 1)[-1])
            if upstream is None:
                conn.sendall(BAD_GATEWAY)
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            with upstream:
                if rest:
                    upstream.sendall(rest)
                relay(conn, upstream)
            return

        # Absolute form: http://host:port/path becomes /path on the origin at 127.0.0.1:port.
        if not target.lower().startswith("http://"):
            conn.sendall(BAD_REQUEST)
            return
        authority, _, path = target[len("http://") :].partition("/")
        upstream = dial(authority.rsplit(":", 1)[-1] if ":" in authority else 80)
        if upstream is None:
            conn.sendall(BAD_GATEWAY)
            return
        request = f"{method} /{path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        with upstream:
            upstream.sendall(request.encode("latin-1") + rest)
            relay(conn, upstream)


class TlsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(Fixture, self.server)
        o = server.opts
        assert server.context is not None
        conn: socket.socket = self.request
        if not (o.plain_too and conn.recv(1, socket.MSG_PEEK) != b"\x16"):
            record(o.log, {"server": o.name, "tls": "connect"})
            try:
                conn = server.context.wrap_socket(conn, server_side=True)
            except (OSError, ssl.SSLError):
                return  # the client refused the certificate (or the protocol): the connection record is the evidence
        with conn:
            conn.settimeout(IDLE)
            upstream = dial(o.backend)
            if upstream is None:
                return
            with upstream:
                relay(conn, upstream)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("proxy", "tls"))
    p.add_argument("--name", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--cert")
    p.add_argument("--key")
    p.add_argument("--backend", type=int)
    p.add_argument("--plain-too", action="store_true")
    o = p.parse_args()
    if o.mode == "proxy":
        server = Fixture(ProxyHandler, o)
    else:
        server = Fixture(TlsHandler, o)
        server.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.context.load_cert_chain(o.cert, o.key)
    print(f"ready {server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
