from __future__ import annotations

import http.client
import http.server
import importlib.util
import json
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "agent" / "serena-metrics.py"


@pytest.fixture
def metrics() -> Any:
    assert SCRIPT.exists(), f"production script is missing: {SCRIPT}"
    spec = importlib.util.spec_from_file_location("serena_metrics", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SerenaHandler(http.server.BaseHTTPRequestHandler):
    response_map: dict[str, Any] = {}

    def do_GET(self) -> None:
        response = self.__class__.response_map.get(self.path)
        if callable(response):
            response(self)
            return
        if response is None:
            self.send_error(404)
            return
        status, body, content_type = response
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class IPv6SerenaServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


@contextmanager
def listener(responses: dict[str, Any], host: str = "127.0.0.1", port: int = 0) -> Iterator[tuple[str, int]]:
    handler = type("TestSerenaHandler", (SerenaHandler,), {"response_map": responses})
    server_class: type[http.server.ThreadingHTTPServer] = (
        IPv6SerenaServer if ":" in host else http.server.ThreadingHTTPServer
    )
    server = server_class((host, port), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield str(server.server_address[0]), int(server.server_address[1])
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def response(value: object, content_type: str = "application/json") -> tuple[int, bytes, str]:
    return 200, json.dumps(value).encode(), content_type


def healthy(project: str = "pfBlockerNG") -> dict[str, Any]:
    return {
        "/heartbeat": response({"status": "alive"}),
        "/get_config_overview": response(
            {
                "active_project": {"name": project, "path": "/repo", "language": "Python"},
                "current_client": "codex",
                "serena_version": "1.7.0",
            }
        ),
    }


def test_constants_keep_entry_point_and_remove_scan_metrics_contract(metrics: Any) -> None:
    assert metrics.HOST == "127.0.0.1"
    assert metrics.DEFAULT_PORT == 24182
    assert metrics.SERENA_BASE_PORT == 24282
    for old_name in ("SCAN_START", "SCAN_END", "SCAN_BATCH", "MAX_WORKERS", "COUNTERS"):
        assert not hasattr(metrics, old_name), f"obsolete full-scan constant remains: {old_name}"
    for old_name in ("aggregate", "_project_stats", "_totals", "_counter_values"):
        assert not hasattr(metrics, old_name), f"obsolete metrics helper remains: {old_name}"


def test_listening_endpoints_parses_filters_deduplicates_and_sorts(
    metrics: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = b"\n".join(
        [
            b"p1",
            b"n100.64.1.2:24284",
            b"n127.0.0.1:24282",
            b"n[fd7a:115c:a1e0::10]:24285",
            b"n[::1]:24283",
            b"n[::1%lo0]:24291",
            b"n[fd7a:115c:a1e0::10%utun0]:24292",
            b"n127.0.0.1:24282",
            b"n*:24286",
            b"n0.0.0.0:24287",
            b"n192.168.1.4:24288",
            b"n127.0.0.1",
            b"n127.0.0.1:bad",
            b"n127.0.0.1:24281",
            b"n127.0.0.1:65536",
            b"n 127.0.0.1:24289",
            b"n127.0.0.1:24290\x01",
        ]
    )

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        assert command == ["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "n"]
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == metrics.LSOF_TIMEOUT
        return SimpleNamespace(returncode=0, stdout=output)

    monkeypatch.setattr(metrics.subprocess, "run", run)
    assert metrics._listening_endpoints() == [
        ("100.64.1.2", 24284),
        ("127.0.0.1", 24282),
        ("::1", 24283),
        ("fd7a:115c:a1e0::10", 24285),
    ]


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError,
        lambda: TimeoutError("expired"),
        UnicodeError,
    ],
    ids=["missing", "timeout", "decode"],
)
def test_lsof_failures_return_bounded_empty_directory(
    metrics: Any, monkeypatch: pytest.MonkeyPatch, failure: Any
) -> None:
    def run(*args: object, **kwargs: object) -> object:
        raise failure()

    monkeypatch.setattr(metrics.subprocess, "run", run)
    assert metrics._listening_endpoints() == []


def test_lsof_timeout_expired_and_nonzero_or_nontext_output_are_empty(
    metrics: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeout = metrics.subprocess.TimeoutExpired("lsof", metrics.LSOF_TIMEOUT)
    for result in [
        timeout,
        SimpleNamespace(returncode=1, stdout=b"n127.0.0.1:24282"),
        SimpleNamespace(returncode=0, stdout=object()),
        SimpleNamespace(returncode=0, stdout=b"\xff"),
    ]:
        if isinstance(result, BaseException):

            def run(*args: object, **kwargs: object) -> object:
                raise result

        else:

            def run(*args: object, **kwargs: object) -> object:
                return result

        monkeypatch.setattr(metrics.subprocess, "run", run)
        assert metrics._listening_endpoints() == []


def test_only_lsof_candidates_are_probed_and_healthy_config_is_projected(
    metrics: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidates = [("127.0.0.1", 24282), ("::1", 24283)]
    monkeypatch.setattr(metrics, "_listening_endpoints", lambda: candidates)
    calls: list[tuple[str, int, str]] = []

    def request(host: str, port: int, path: str) -> object | None:
        calls.append((host, port, path))
        if port == 24282 and path == "/heartbeat":
            return {"status": "alive"}
        if port == 24282 and path == "/get_config_overview":
            return {
                "active_project": {"name": "pfBlockerNG", "path": "/repo", "language": "Python"},
                "current_client": "codex",
                "serena_version": "1.7.0",
            }
        return {"status": "not-serena"} if path == "/heartbeat" else None

    monkeypatch.setattr(metrics, "_request_json", request)
    assert metrics.discover_instances() == [
        {
            "host": "127.0.0.1",
            "port": 24282,
            "dashboard_url": "http://127.0.0.1:24282/dashboard/",
            "active_project": {"name": "pfBlockerNG", "path": "/repo", "language": "Python"},
            "current_client": "codex",
            "serena_version": "1.7.0",
        }
    ]
    assert calls == [
        ("127.0.0.1", 24282, "/heartbeat"),
        ("127.0.0.1", 24282, "/get_config_overview"),
        ("::1", 24283, "/heartbeat"),
    ]


@pytest.mark.parametrize(
    "heartbeat,config",
    [
        (
            {"status": "alive", "service": "other"},
            {"active_project": {}, "current_client": "x", "serena_version": "1"},
        ),
        ({"status": "alive"}, None),
        (
            {"status": "alive"},
            {"active_project": None, "current_client": "x", "serena_version": "1"},
        ),
        (
            {"status": "alive"},
            {"active_project": {"name": "x"}, "current_client": "x", "serena_version": "1"},
        ),
    ],
    ids=["extra-heartbeat", "disappearing-config", "null-project", "incomplete-config"],
)
def test_stale_non_serena_and_invalid_config_are_ignored(
    metrics: Any, monkeypatch: pytest.MonkeyPatch, heartbeat: object, config: object
) -> None:
    monkeypatch.setattr(metrics, "_listening_endpoints", lambda: [("127.0.0.1", 24282)])
    responses = {"/heartbeat": heartbeat, "/get_config_overview": config}
    monkeypatch.setattr(metrics, "_request_json", lambda host, port, path: responses[path])
    assert metrics.discover_instances() == []


def test_request_json_supports_ipv6(metrics: Any) -> None:
    with listener(healthy(), host="::1") as (host, port):
        assert host == "::1"
        assert metrics._request_json(host, port, "/heartbeat") == {"status": "alive"}


def test_discovery_brackets_tailscale_ipv6_dashboard_url(metrics: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    host = "fd7a:115c:a1e0::10"
    monkeypatch.setattr(metrics, "_listening_endpoints", lambda: [(host, 24282)])
    responses = {
        "/heartbeat": {"status": "alive"},
        "/get_config_overview": {
            "active_project": {"name": "pfBlockerNG", "path": "/repo", "language": "Python"},
            "current_client": None,
            "serena_version": "1.7.0",
        },
    }
    monkeypatch.setattr(metrics, "_request_json", lambda request_host, port, path: responses[path])

    assert metrics.discover_instances()[0]["dashboard_url"] == f"http://[{host}]:24282/dashboard/"


def test_request_json_rejects_oversized_content_length(metrics: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status = 200

        def getheader(self, name: str, default: str = "") -> str:
            return "application/json" if name == "Content-Type" else str(metrics.READ_LIMIT + 1)

        def read(self, limit: int) -> bytes:
            return b"{}"

    class FakeConnection:
        sock: Any = None

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def request(self, *args: object, **kwargs: object) -> None:
            pass

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(metrics.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(
        metrics.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 24282))],
    )
    assert metrics._request_json("127.0.0.1", 24282, "/heartbeat") is None


def test_html_uses_direct_safe_link_and_escapes_every_projected_string(metrics: Any) -> None:
    dangerous = '<script>alert("x")</script> & "quoted"\x01'
    instances = [
        {
            "host": "127.0.0.1",
            "port": 24282,
            "dashboard_url": "http://127.0.0.1:24282/dashboard/",
            "active_project": {"name": dangerous, "path": dangerous, "language": dangerous},
            "current_client": dangerous,
            "serena_version": dangerous,
        }
    ]
    page = metrics.render_html(instances)
    assert "<title>Serena instances</title>" in page
    assert "<h1>Serena instances</h1>" in page
    assert 'target="_blank"' in page
    assert 'rel="noopener noreferrer"' in page
    assert 'href="http://127.0.0.1:24282/dashboard/"' in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page
    assert "<script>" not in page
    assert "\x01" not in page
    assert "metrics" not in page.lower()


def test_http_directory_json_html_host_validation_and_get_only(metrics: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    instance = {
        "host": "::1",
        "port": 24282,
        "dashboard_url": "http://[::1]:24282/dashboard/",
        "active_project": {"name": "project", "path": "/repo", "language": "Python"},
        "current_client": "codex",
        "serena_version": "1.7.0",
    }
    monkeypatch.setattr(metrics, "discover_instances", lambda: [instance])
    server = metrics.make_server(0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request("GET", "/api/instances")
        api = connection.getresponse()
        assert api.status == 200
        assert json.loads(api.read()) == {"instances": [instance]}
        assert api.getheader("Content-Security-Policy") == "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"

        connection.request("GET", "/")
        page = connection.getresponse()
        assert page.status == 200
        assert "Serena instances" in page.read().decode()

        connection.request("GET", "/missing")
        assert connection.getresponse().status == 404

        connection.putrequest("GET", "/api/instances", skip_host=True)
        connection.putheader("Host", "attacker.example")
        connection.endheaders()
        assert connection.getresponse().status == 421

        connection.putrequest("GET", "/api/instances", skip_host=True)
        connection.putheader("Host", "localhost")
        connection.putheader("Host", "localhost")
        connection.endheaders()
        assert connection.getresponse().status == 421

        connection.request("POST", "/api/instances")
        rejected = connection.getresponse()
        assert rejected.status == 405
        assert rejected.getheader("Allow") == "GET"
    finally:
        connection.close()
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("method", ["HEAD", "TRACE", "CONNECT", "DELETE", "OPTIONS", "PATCH", "POST", "PUT", "FOO"])
def test_http_rejects_every_non_get_method(metrics: Any, monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    monkeypatch.setattr(metrics, "discover_instances", lambda: [])
    server = metrics.make_server(0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.request(method, "/api/instances")
        response = connection.getresponse()
        assert response.status == 405
        assert response.getheader("Allow") == "GET"
        response.read()
    finally:
        connection.close()
        server.shutdown()
        thread.join()
        server.server_close()


def test_help_describes_local_directory_and_tailscale_links_not_metrics(
    metrics: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    assert metrics.main(["--help"]) == 0
    output = capsys.readouterr().out.lower()
    assert "serena instance directory" in output
    assert "tailscale serve" in output
    assert "dashboard" in output
    assert "metric" not in output
    assert "aggregate" not in output
