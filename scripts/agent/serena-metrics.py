#!/usr/bin/env python3
"""Aggregate live Serena dashboard metrics for a local Tailscale Serve backend."""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import http.client
import http.server
import json
from collections.abc import Mapping
from typing import Any

HOST = "127.0.0.1"
DEFAULT_PORT = 24182
SCAN_START = 24282
SCAN_END = 24345
REQUEST_TIMEOUT = 0.5
READ_LIMIT = 64 * 1024
MAX_WORKERS = 8
COUNTERS = ("num_times_called", "input_tokens", "output_tokens")


def _request_json(port: int, path: str) -> object | None:
    connection = http.client.HTTPConnection(HOST, port, timeout=REQUEST_TIMEOUT)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != http.client.OK:
            return None
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return None
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                if int(content_length) > READ_LIMIT:
                    return None
            except ValueError:
                return None
        body = response.read(READ_LIMIT + 1)
        if len(body) > READ_LIMIT:
            return None
        return json.loads(body.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None
    finally:
        connection.close()


def _strings(
    value: object,
    keys: tuple[str, ...],
    nullable: tuple[str, ...] = (),
) -> dict[str, str | None] | None:
    if not isinstance(value, Mapping):
        return None
    strings: dict[str, str | None] = {}
    for key in keys:
        item = value.get(key)
        if not isinstance(item, str) and not (item is None and key in nullable):
            return None
        strings[key] = item
    return strings


def _counter_values(value: object) -> dict[str, int] | None:
    if not isinstance(value, Mapping):
        return None
    counters: dict[str, int] = {}
    for key in COUNTERS:
        counter = value.get(key)
        if type(counter) is not int or counter < 0:
            return None
        counters[key] = counter
    return counters


def _project_stats(value: object) -> dict[str, dict[str, int]] | None:
    if not isinstance(value, Mapping):
        return None
    stats = value.get("stats")
    if not isinstance(stats, Mapping):
        return None
    projected: dict[str, dict[str, int]] = {}
    for name, counters in stats.items():
        if not isinstance(name, str):
            return None
        parsed = _counter_values(counters)
        if parsed is None:
            return None
        projected[name] = parsed
    return dict(sorted(projected.items()))


def _totals(tools: Mapping[str, Mapping[str, int]]) -> dict[str, int]:
    return {key: sum(tool[key] for tool in tools.values()) for key in COUNTERS}


def _discover_port(port: int) -> dict[str, Any] | None:
    if _request_json(port, "/heartbeat") != {"status": "alive"}:
        return None
    config = _request_json(port, "/get_config_overview")
    if not isinstance(config, Mapping):
        return None
    project_keys = ("name", "path", "language")
    project = _strings(config.get("active_project"), project_keys, nullable=project_keys)
    identity = _strings(config, ("current_client", "serena_version"), nullable=("current_client",))
    stats = _project_stats(_request_json(port, "/get_tool_stats"))
    estimator = _strings(_request_json(port, "/get_token_count_estimator_name"), ("token_count_estimator_name",))
    if project is None or identity is None or stats is None or estimator is None:
        return None
    return {
        "port": port,
        "active_project": project,
        **identity,
        **estimator,
        "tools": stats,
        "totals": _totals(stats),
    }


def discover_instances() -> list[dict[str, Any]]:
    ports = range(SCAN_START, SCAN_END + 1)
    workers = min(MAX_WORKERS, len(ports))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        instances = [instance for instance in executor.map(_discover_port, ports) if instance is not None]
    return sorted(instances, key=lambda instance: instance["port"])


def aggregate(instances: list[dict[str, Any]]) -> dict[str, Any]:
    totals = _totals({str(index): instance["totals"] for index, instance in enumerate(instances)})
    return {"instances": instances, "totals": totals}


def _html_text(value: object) -> str:
    text = "unknown" if value is None else str(value)
    return html.escape("".join(character if character.isprintable() else " " for character in text), quote=True)


def _trusted_host(value: str | None) -> bool:
    if value is None:
        return False
    hostname = value.lower().partition(":")[0].rstrip(".")
    return hostname in {"127.0.0.1", "localhost"} or hostname.endswith(".ts.net")


def render_html(instances: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for instance in instances:
        project = instance["active_project"]
        tools = "".join(
            f"<li>{_html_text(name)}: calls={values['num_times_called']}, "
            f"input={values['input_tokens']}, output={values['output_tokens']}</li>"
            for name, values in instance["tools"].items()
        )
        rows.append(
            "<section>"
            f"<h2>Port {_html_text(instance['port'])}: {_html_text(project['name'])}</h2>"
            f"<p>Path: {_html_text(project['path'])}; language: {_html_text(project['language'])}; "
            f"client: {_html_text(instance['current_client'])}; Serena: {_html_text(instance['serena_version'])}; "
            f"estimator: {_html_text(instance['token_count_estimator_name'])}</p>"
            f"<p>Totals: {_html_text(instance['totals'])}</p><ul>{tools}</ul></section>"
        )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Serena metrics</title></head>"
        "<body><h1>Live Serena metrics</h1>"
        + ("".join(rows) or "<p>No healthy Serena dashboards found.</p>")
        + "</body></html>"
    )


class AggregatorHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SerenaMetrics/1"

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
        self._send(405, b"method not allowed\n", "text/plain; charset=utf-8", "GET")

    def do_GET(self) -> None:
        if not _trusted_host(self.headers.get("Host")):
            self._send(421, b"misdirected request\n", "text/plain; charset=utf-8")
            return
        if self.path == "/":
            body = render_html(discover_instances()).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
        elif self.path == "/api/instances":
            body = json.dumps(aggregate(discover_instances()), ensure_ascii=True, separators=(",", ":")).encode()
            self._send(200, body, "application/json; charset=utf-8")
        else:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_OPTIONS(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    def do_POST(self) -> None:
        self._reject_method()

    def do_PUT(self) -> None:
        self._reject_method()

    def log_message(self, format: str, *args: object) -> None:
        pass


class AggregatorServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(port: int = DEFAULT_PORT) -> AggregatorServer:
    return AggregatorServer((HOST, port), AggregatorHandler)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only local Serena metrics aggregator.",
        epilog=f"Tailscale Serve: tailscale serve --bg http://{HOST}:{DEFAULT_PORT}",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"aggregate port (default: {DEFAULT_PORT})")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    server = make_server(args.port)
    print(f"Serena metrics listening on http://{HOST}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
