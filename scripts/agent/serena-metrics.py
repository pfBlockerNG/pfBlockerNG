#!/usr/bin/env python3
"""List live Serena dashboards for a local Tailscale Serve backend."""

from __future__ import annotations

import argparse
import html
import http.client
import http.server
import ipaddress
import json
import socket
import subprocess
import time
import urllib.parse
from collections.abc import Mapping
from typing import Any

HOST = "127.0.0.1"
DEFAULT_PORT = 24182
SERENA_BASE_PORT = 24282
LSOF_TIMEOUT = 0.5
REQUEST_TIMEOUT = 0.5
READ_LIMIT = 64 * 1024


class _DeadlineSocket(socket.socket):
    def __init__(self, family: socket.AddressFamily, deadline: float) -> None:
        super().__init__(family, socket.SOCK_STREAM)
        self._deadline = deadline

    def _apply_deadline(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Serena request deadline exceeded")
        self.settimeout(remaining)

    def connect_with_deadline(self, address: tuple[Any, ...]) -> None:
        self._apply_deadline()
        self.connect(address)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._apply_deadline()
        return super().recv_into(buffer, nbytes, flags)


def _request_json(host: str, port: int, path: str) -> object | None:
    deadline = time.monotonic() + REQUEST_TIMEOUT
    deadline_socket: _DeadlineSocket | None = None
    connection: http.client.HTTPConnection | None = None
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)
        if not addresses:
            return None
        family, _, _, _, address = addresses[0]
        deadline_socket = _DeadlineSocket(family, deadline)
        connection = http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT)
        deadline_socket.connect_with_deadline(address)
        connection.sock = deadline_socket
        deadline_socket._apply_deadline()
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != http.client.OK:
            return None
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return None
        content_length_header = response.getheader("Content-Length")
        content_length = None
        if content_length_header is not None:
            try:
                content_length = int(content_length_header)
                if content_length < 0 or content_length > READ_LIMIT:
                    return None
            except ValueError:
                return None
        body = response.read(READ_LIMIT + 1)
        if len(body) > READ_LIMIT or (content_length is not None and len(body) != content_length):
            return None
        return json.loads(body.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError, http.client.HTTPException, json.JSONDecodeError):
        return None
    finally:
        if connection is not None:
            connection.close()
        if deadline_socket is not None:
            deadline_socket.close()


def _strings(
    value: object,
    keys: tuple[str, ...],
    nullable: tuple[str, ...] = (),
) -> dict[str, str | None] | None:
    if not isinstance(value, Mapping):
        return None
    strings: dict[str, str | None] = {}
    for key in keys:
        if key not in value:
            return None
        item = value[key]
        if not isinstance(item, str) and not (item is None and key in nullable):
            return None
        strings[key] = item
    return strings


def _allowed_host(host: str) -> str | None:
    if not host.isascii() or "%" in host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if (
        address.is_loopback
        or address in ipaddress.ip_network("100.64.0.0/10")
        or address in ipaddress.ip_network("fd7a:115c:a1e0::/48")
    ):
        return str(address)
    return None


def _parse_endpoint(line: str) -> tuple[str, int] | None:
    if not line.startswith("n") or any(character.isspace() or not character.isprintable() for character in line):
        return None
    value = line[1:]
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1 or closing + 1 >= len(value) or value[closing + 1] != ":":
            return None
        host, port_text = value[1:closing], value[closing + 2 :]
    elif ":" in value:
        host, port_text = value.rsplit(":", 1)
    else:
        return None
    if not port_text.isascii() or not port_text.isdigit():
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not SERENA_BASE_PORT <= port <= 65535:
        return None
    normalized_host = _allowed_host(host)
    return None if normalized_host is None else (normalized_host, port)


def _listening_endpoints() -> list[tuple[str, int]]:
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "n"],
            capture_output=True,
            timeout=LSOF_TIMEOUT,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired, TimeoutError):
        return []
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return []
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeError:
        return []
    return sorted({endpoint for line in output.split("\n") if (endpoint := _parse_endpoint(line)) is not None})


def _dashboard_url(host: str, port: int) -> str:
    url_host = f"[{host}]" if ":" in host else host
    return f"http://{url_host}:{port}/dashboard/"


def _discover_endpoint(host: str, port: int) -> dict[str, Any] | None:
    if _request_json(host, port, "/heartbeat") != {"status": "alive"}:
        return None
    config = _request_json(host, port, "/get_config_overview")
    if not isinstance(config, Mapping):
        return None
    project_keys = ("name", "path", "language")
    project = _strings(config.get("active_project"), project_keys, nullable=project_keys)
    identity = _strings(config, ("current_client", "serena_version"), nullable=("current_client",))
    if project is None or identity is None:
        return None
    return {
        "host": host,
        "port": port,
        "dashboard_url": _dashboard_url(host, port),
        "active_project": project,
        **identity,
    }


def discover_instances() -> list[dict[str, Any]]:
    instances = (
        instance for host, port in _listening_endpoints() if (instance := _discover_endpoint(host, port)) is not None
    )
    return list(instances)


def _html_text(value: object) -> str:
    text = "unknown" if value is None else str(value)
    return html.escape("".join(character if character.isprintable() else " " for character in text), quote=True)


def _trusted_host(value: str | None) -> bool:
    if (
        value is None
        or value != value.strip()
        or any(not character.isprintable() or character.isspace() for character in value)
    ):
        return False
    try:
        parsed = urllib.parse.urlsplit(f"//{value}")
        parsed.port
    except ValueError:
        return False
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        return False
    hostname = (parsed.hostname or "").lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
        if hostname.endswith("."):
            return False
    if len(hostname) > 253:
        return False
    if hostname in {"127.0.0.1", "localhost"}:
        return True
    labels = hostname.split(".")
    valid_labels = all(
        0 < len(label) <= 63
        and label[0].isascii()
        and label[0].isalnum()
        and label[-1].isascii()
        and label[-1].isalnum()
        and all(character.isascii() and (character.isalnum() or character == "-") for character in label)
        for label in labels
    )
    return valid_labels and hostname.endswith(".ts.net")


def render_html(instances: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for instance in instances:
        project = instance["active_project"]
        rows.append(
            "<section>"
            f"<h2>{_html_text(project['name'])}</h2>"
            f"<p>Host: {_html_text(instance['host'])}; port: {_html_text(instance['port'])}; "
            f"path: {_html_text(project['path'])}; language: {_html_text(project['language'])}; "
            f"client: {_html_text(instance['current_client'])}; Serena: {_html_text(instance['serena_version'])}; "
            f'<a href="{_html_text(instance["dashboard_url"])}" target="_blank" '
            'rel="noopener noreferrer">Open dashboard</a></p></section>'
        )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Serena instances</title></head>"
        "<body><h1>Serena instances</h1>"
        + ("".join(rows) or "<p>No healthy Serena instances found.</p>")
        + "</body></html>"
    )


class DirectoryHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SerenaDirectory/1"

    def _send(self, status: int, body: bytes, content_type: str, allow: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        if allow is not None:
            self.send_header("Allow", allow)
        self.end_headers()
        self.wfile.write(body)

    def _reject_method(self) -> None:
        body = b"" if self.command == "HEAD" else b"method not allowed\n"
        self._send(405, body, "text/plain; charset=utf-8", "GET")

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._reject_method
        raise AttributeError(name)

    def do_GET(self) -> None:
        host_headers = self.headers.get_all("Host", [])
        if len(host_headers) != 1 or not _trusted_host(host_headers[0]):
            self._send(421, b"misdirected request\n", "text/plain; charset=utf-8")
            return
        if self.path == "/":
            body = render_html(discover_instances()).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
        elif self.path == "/api/instances":
            body = json.dumps({"instances": discover_instances()}, ensure_ascii=True, separators=(",", ":")).encode()
            self._send(200, body, "application/json; charset=utf-8")
        else:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")

    do_CONNECT = _reject_method
    do_DELETE = _reject_method
    do_HEAD = _reject_method
    do_OPTIONS = _reject_method
    do_PATCH = _reject_method
    do_POST = _reject_method
    do_PUT = _reject_method
    do_TRACE = _reject_method

    def log_message(self, format: str, *args: object) -> None:
        pass


class DirectoryServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(port: int = DEFAULT_PORT) -> DirectoryServer:
    return DirectoryServer((HOST, port), DirectoryHandler)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serena-directory",
        description="Read-only local Serena instance directory.",
        epilog=(
            f"Tailscale Serve: tailscale serve --bg http://{HOST}:{DEFAULT_PORT}; "
            "dashboard links use each Serena listener address."
        ),
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"directory port (default: {DEFAULT_PORT})")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 1
    server = make_server(args.port)
    print(f"Serena directory listening on http://{HOST}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
