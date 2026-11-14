#!/usr/bin/env python3
"""FTP server of the feed-transfer parity corpus (tests/feedfetch/fixtures/parity), on 127.0.0.1 only.

Usage: ftp_server.py CONFIG LOG

Both corpus runners start it, read the one line "PORT <n>" it prints once it listens, and stop it by closing its stdin
(it also exits when the runner dies). CONFIG is a JSON file read afresh for every connection, so a step may rewrite it:

    name        the server's name, copied into every record.
    users       null or absent: any login is accepted; else {user: password} and any other login gets 530.
    epsv        default true; false answers EPSV with 502, so a client falls back to PASV.
    pasv_host   default 127.0.0.1: the address a PASV reply names (EPSV names none). The data listener is on 127.0.0.1
                only, so a client that dials another named address finds nothing there and fails.
    replies     {command: reply} replaces a command's reply with the text given (one line, "<code> <text>"): USER PASS
                CWD TYPE SIZE MDTM EPSV PASV, and RETR_END, the reply after the data (default "226 transfer complete").
                {port}, {hi} and {lo} in an EPSV or PASV reply are the data port and its two PASV octets.
    quirk       "" or one of: "overlong" (the 220 greeting is a single 1 MiB line), "multiline" (greeting, 331 and 226
                replies are multi-line, with a continuation line that looks like a final one), "pasv_garbage" (the PASV
                reply has a non-numeric field).
    files       {absolute path: {body, size, mdtm, cut}}: body (text, UTF-8); size (number: the SIZE reply instead of
                the body length; false: SIZE is refused with 502); mdtm (Unix seconds: the MDTM reply, absent: 550);
                cut (number: send only that many bytes, then drop the data and control connections without a 226).
                CWD succeeds into any directory that holds a file; RETR resolves its argument against the CWD.

LOG gets one JSON line, {"server", "command"}, per command of USER PASS CWD TYPE EPSV PASV SIZE MDTM RETR, in arrival
order, plus DELE, which no client of this corpus may send: it shows an injected command, and the connection is dropped
at once so that nothing after it, which would depend on how the client reacts, is recorded. Commands that libcurl adds
or drops between versions (PWD, QUIT) are answered but not recorded. After each accepted data connection it also gets
{"server", "data_to"}: the local address the client dialled.
"""

import datetime
import json
import os
import posixpath
import socket
import sys
import threading
from typing import Any

CONFIG, LOG = sys.argv[1], sys.argv[2]
RECORDED = {"USER", "PASS", "CWD", "TYPE", "EPSV", "PASV", "SIZE", "MDTM", "RETR", "DELE"}
SESSION_IDLE = 30  # a stalled client frees its thread


def record(rec: dict[str, str]) -> None:
    # One write on an O_APPEND descriptor, as the HTTP router's LOCK_EX append: lines never interleave.
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(rec, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)


class Session:
    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.cfg: dict[str, Any] = json.load(open(CONFIG))
        self.cwd = "/"
        self.user: str | None = None
        self.data: socket.socket | None = None
        self.buf = b""

    def send(self, *lines: str) -> None:
        self.conn.sendall(b"".join(line.encode() + b"\r\n" for line in lines))

    def reply(self, code: int, text: str, cmd: str | None = None) -> None:
        if (custom := (self.cfg.get("replies") or {}).get(cmd)) is not None:
            self.send(custom)
        elif self.cfg.get("quirk") == "multiline" and code in (220, 331, 226):
            self.send(f"{code}-{text}", f" {code} is not the end of this reply", f"{code} {text}")
        else:
            self.send(f"{code} {text}")

    def readline(self) -> str | None:
        while b"\r\n" not in self.buf:
            chunk = self.conn.recv(4096)
            if not chunk:
                return None
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line.decode("latin-1")

    def file(self, arg: str) -> dict[str, Any] | None:
        return (self.cfg.get("files") or {}).get(posixpath.normpath(posixpath.join(self.cwd, arg)))

    def run(self) -> None:
        if self.cfg.get("quirk") == "overlong":
            self.send("220 " + "x" * (1 << 20))
        else:
            self.reply(220, "pfb corpus ftp")
        while (line := self.readline()) is not None:
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if cmd in RECORDED:
                record({"server": self.cfg["name"], "command": line})
            if cmd == "DELE":
                return
            if cmd == "QUIT":
                self.reply(221, "bye")
                return
            if not self.dispatch(cmd, arg):
                return

    def dispatch(self, cmd: str, arg: str) -> bool:
        users = self.cfg.get("users")
        if cmd == "USER":
            self.user = arg
            self.reply(331, "password required", "USER")
        elif cmd == "PASS":
            if users is None or users.get(self.user) == arg:
                self.reply(230, "logged in", "PASS")
            else:
                self.reply(530, "login incorrect", "PASS")
        elif cmd == "PWD":
            self.reply(257, '"/" is the current directory')
        elif cmd == "CWD":
            target = posixpath.normpath(posixpath.join(self.cwd, arg))
            if any(p.startswith(target.rstrip("/") + "/") for p in self.cfg.get("files") or {}):
                self.cwd = target
                self.reply(250, "directory changed", "CWD")
            else:
                self.reply(550, "no such directory")
        elif cmd == "TYPE":
            self.reply(200, f"type set to {arg}", "TYPE")
        elif cmd in ("EPSV", "PASV"):
            return self.passive(cmd)
        elif cmd == "SIZE":
            f = self.file(arg)
            if f is None:
                self.reply(550, "no such file")
            elif f.get("size") is False:
                self.reply(502, "SIZE not implemented")
            else:
                self.reply(213, str(f.get("size", len(f["body"].encode()))), "SIZE")
        elif cmd == "MDTM":
            f = self.file(arg)
            if f is None or "mdtm" not in f:
                self.reply(550, "no modification time")
            else:
                when = datetime.datetime.fromtimestamp(f["mdtm"], datetime.timezone.utc)
                self.reply(213, when.strftime("%Y%m%d%H%M%S"), "MDTM")
        elif cmd == "RETR":
            return self.retrieve(arg)
        else:
            self.reply(502, "command not implemented")
        return True

    def passive(self, cmd: str) -> bool:
        if cmd == "EPSV" and self.cfg.get("epsv", True) is False:
            self.reply(502, "EPSV not implemented")
            return True
        if self.data:
            self.data.close()
        self.data = socket.socket()
        self.data.bind(("127.0.0.1", 0))
        self.data.listen(1)
        self.data.settimeout(SESSION_IDLE)
        port = self.data.getsockname()[1]
        hi, lo = ("ab", "cd") if self.cfg.get("quirk") == "pasv_garbage" else (port >> 8, port & 255)
        if (custom := (self.cfg.get("replies") or {}).get(cmd)) is not None:
            self.send(custom.format(port=port, hi=hi, lo=lo))
        elif cmd == "EPSV":
            self.send(f"229 Entering Extended Passive Mode (|||{port}|)")
        else:
            host = self.cfg.get("pasv_host", "127.0.0.1").replace(".", ",")
            self.send(f"227 Entering Passive Mode ({host},{hi},{lo})")
        return True

    def retrieve(self, arg: str) -> bool:
        f = self.file(arg)
        if f is None:
            self.reply(550, "no such file")
            return True
        if self.data is None:
            self.reply(425, "use PASV first")
            return True
        self.send("150 opening BINARY mode data connection")
        try:
            data, _ = self.data.accept()
        except OSError:
            self.reply(425, "no data connection")
            return True
        record({"server": self.cfg["name"], "data_to": data.getsockname()[0]})
        body = f["body"].encode()
        cut = f.get("cut")
        try:
            data.sendall(body if cut is None else body[:cut])
        except OSError:
            pass
        data.close()
        self.data.close()
        self.data = None
        if cut is not None:
            return False  # dropped mid-transfer: no 226, the control connection goes too
        self.reply(226, "transfer complete", "RETR_END")
        return True


def serve(conn: socket.socket) -> None:
    conn.settimeout(SESSION_IDLE)
    session = Session(conn)
    try:
        session.run()
    except OSError:
        pass
    finally:
        if session.data:
            session.data.close()
        conn.close()


def main() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    # The runner owns this process: its stdin closing, however the runner ends, ends the server.
    threading.Thread(target=lambda: (sys.stdin.read(), os._exit(0)), daemon=True).start()
    print(f"PORT {listener.getsockname()[1]}", flush=True)
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
