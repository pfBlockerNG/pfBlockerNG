from __future__ import annotations

import http.client
import http.server
import importlib.util
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
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
    requests: list[str] = []

    def do_GET(self) -> None:
        self.__class__.requests.append(self.path)
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


@contextmanager
def listener(responses: dict[str, Any], port: int = 0) -> Iterator[tuple[int, type[SerenaHandler]]]:
    handler = type("TestSerenaHandler", (SerenaHandler,), {"response_map": responses, "requests": []})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_address[1], handler
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
        "/get_tool_stats": response(
            {
                "stats": {
                    "find_symbol": {"num_times_called": 2, "input_tokens": 11, "output_tokens": 7},
                    "replace_symbol": {"num_times_called": 1, "input_tokens": 5, "output_tokens": 3},
                }
            }
        ),
        "/get_token_count_estimator_name": response({"token_count_estimator_name": "tiktoken"}),
    }


def configure_scan(metrics: Any, start: int, end: int) -> None:
    metrics.SCAN_START = start
    metrics.SCAN_END = end
    metrics.REQUEST_TIMEOUT = 0.1


def test_healthy_instance_is_projected_with_tools_and_totals(metrics: Any) -> None:
    with listener(healthy()) as (port, _):
        configure_scan(metrics, port, port)
        instances = metrics.discover_instances()

    assert instances == [
        {
            "port": port,
            "active_project": {"name": "pfBlockerNG", "path": "/repo", "language": "Python"},
            "current_client": "codex",
            "serena_version": "1.7.0",
            "token_count_estimator_name": "tiktoken",
            "tools": {
                "find_symbol": {"num_times_called": 2, "input_tokens": 11, "output_tokens": 7},
                "replace_symbol": {"num_times_called": 1, "input_tokens": 5, "output_tokens": 3},
            },
            "totals": {"num_times_called": 3, "input_tokens": 16, "output_tokens": 10},
        }
    ]


def test_instance_without_project_or_client_is_still_listed(metrics: Any) -> None:
    responses = healthy()
    responses["/get_config_overview"] = response(
        {
            "active_project": {"name": None, "path": None, "language": None},
            "current_client": None,
            "serena_version": "1.7.0",
        }
    )
    responses["/get_tool_stats"] = response({"stats": {}})
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        instances = metrics.discover_instances()
        page = metrics.render_html(instances)

    assert instances == [
        {
            "port": port,
            "active_project": {"name": None, "path": None, "language": None},
            "current_client": None,
            "serena_version": "1.7.0",
            "token_count_estimator_name": "tiktoken",
            "tools": {},
            "totals": {"num_times_called": 0, "input_tokens": 0, "output_tokens": 0},
        }
    ]
    assert "unknown" in page


def test_multiple_instances_are_sorted_and_have_aggregate_totals(metrics: Any) -> None:
    with listener(healthy("second")) as (first_port, _):
        with listener(healthy("first")) as (second_port, _):
            low, high = sorted((first_port, second_port))
            configure_scan(metrics, low, high)
            instances = metrics.discover_instances()
            assert [instance["port"] for instance in instances] == sorted((first_port, second_port))
            aggregate = metrics.aggregate(instances)

    assert aggregate["totals"] == {"num_times_called": 6, "input_tokens": 32, "output_tokens": 20}


def test_closed_port_is_ignored(metrics: Any) -> None:
    with listener(healthy()) as (port, _):
        configure_scan(metrics, port, port + 1)
        instances = metrics.discover_instances()

    assert [instance["port"] for instance in instances] == [port]


def test_non_serena_listener_requires_exact_heartbeat_shape(metrics: Any) -> None:
    responses = healthy()
    responses["/heartbeat"] = response({"status": "alive", "service": "other"})
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []


def test_listener_that_fails_after_heartbeat_is_ignored(metrics: Any) -> None:
    responses = healthy()

    def fail(_: SerenaHandler) -> None:
        raise OSError("listener disappeared")

    responses["/get_config_overview"] = fail
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []


@pytest.mark.parametrize(
    "payload",
    [None, [], {"status": "alive"}, {"stats": {"tool": {"num_times_called": 1}}}],
    ids=["null", "array", "incomplete-config", "incomplete-stats"],
)
def test_invalid_or_incomplete_json_is_ignored(metrics: Any, payload: object) -> None:
    responses = healthy()
    responses["/get_config_overview"] = response(payload)
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []


def test_malformed_and_oversized_responses_are_ignored(metrics: Any) -> None:
    responses = healthy()
    responses["/get_config_overview"] = (200, b"{not-json", "application/json")
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []

    oversized = healthy()
    oversized["/get_config_overview"] = (200, b"x" * (metrics.READ_LIMIT + 1), "application/json")
    with listener(oversized) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []

    without_length = healthy()

    def oversized_without_length(handler: SerenaHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.end_headers()
        try:
            handler.wfile.write(b"x" * (metrics.READ_LIMIT + 1))
        except BrokenPipeError:
            pass

    without_length["/get_config_overview"] = oversized_without_length
    with listener(without_length) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []


def test_slow_listener_is_bounded_and_ignored(metrics: Any) -> None:
    responses = healthy()

    def slow(handler: SerenaHandler) -> None:
        body = b"{}"
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.flush()
        try:
            for byte in body:
                time.sleep(0.04)
                handler.wfile.write(bytes((byte,)))
                handler.wfile.flush()
        except BrokenPipeError:
            pass

    responses["/heartbeat"] = slow
    with listener(responses) as (port, _):
        metrics.REQUEST_TIMEOUT = 0.05
        assert metrics._request_json(port, "/heartbeat") is None


def test_html_escapes_metacharacters_and_removes_controls(metrics: Any) -> None:
    dangerous = healthy('<script>alert("x")</script> & "quoted"\x01')
    dangerous["/get_config_overview"] = response(
        {
            "active_project": {
                "name": '<script>alert("x")</script> & "quoted"\x01',
                "path": '<img src=x onerror="path">\x03',
                "language": "Python & <b>language</b>",
            },
            "current_client": "client\x02",
            "serena_version": "<svg onload=version>",
        }
    )
    dangerous["/get_tool_stats"] = response(
        {"stats": {"<script>tool</script>\x04": {"num_times_called": 1, "input_tokens": 2, "output_tokens": 3}}}
    )
    dangerous["/get_token_count_estimator_name"] = response(
        {"token_count_estimator_name": "<iframe>estimator</iframe>\x05"}
    )
    with listener(dangerous) as (port, _):
        configure_scan(metrics, port, port)
        html = metrics.render_html(metrics.discover_instances())

    assert "<script>" not in html
    assert "<img" not in html and "<b>" not in html and "<svg" not in html and "<iframe>" not in html
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html
    assert all(control not in html for control in ("\x01", "\x02", "\x03", "\x04", "\x05"))


def test_redirect_is_not_followed(metrics: Any) -> None:
    responses = healthy()
    with listener(healthy()) as (target_port, target_handler):

        def redirect(handler: SerenaHandler) -> None:
            handler.send_response(302)
            handler.send_header("Location", f"http://127.0.0.1:{target_port}/heartbeat")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        responses["/heartbeat"] = redirect
        with listener(responses) as (port, _):
            configure_scan(metrics, port, port)
            assert metrics.discover_instances() == []

    assert target_handler.requests == []


@pytest.mark.parametrize(
    "counter",
    [-1, 1.5, True],
    ids=["negative", "float", "bool"],
)
def test_negative_and_non_integer_counters_are_ignored(metrics: Any, counter: object) -> None:
    responses = healthy()
    responses["/get_tool_stats"] = response(
        {"stats": {"find_symbol": {"num_times_called": counter, "input_tokens": 1, "output_tokens": 1}}}
    )
    with listener(responses) as (port, _):
        configure_scan(metrics, port, port)
        assert metrics.discover_instances() == []


def test_http_surface_is_json_html_loopback_and_get_only(metrics: Any) -> None:
    with listener(healthy()) as (port, _):
        configure_scan(metrics, port, port)
        server = metrics.make_server(0)
        assert server.server_address[0] == "127.0.0.1"
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
            connection.request("GET", "/api/instances")
            api = connection.getresponse()
            assert api.status == 200
            assert api.getheader("Content-Type") == "application/json; charset=utf-8"
            content_security_policy = api.getheader("Content-Security-Policy")
            assert content_security_policy is not None
            assert "frame-ancestors 'none'" in content_security_policy
            assert json.loads(api.read())["instances"][0]["port"] == port
            connection.request("GET", "/")
            page = connection.getresponse()
            assert page.status == 200
            assert page.getheader("Content-Type") == "text/html; charset=utf-8"
            assert "pfBlockerNG" in page.read().decode()
            connection.request("GET", "/missing")
            assert connection.getresponse().status == 404
            connection.request("POST", "/api/instances")
            rejected = connection.getresponse()
            assert rejected.status == 405
            assert rejected.getheader("Allow") == "GET"
        finally:
            connection.close()
            server.shutdown()
            thread.join()
            server.server_close()


def test_http_surface_rejects_untrusted_host_and_accepts_tailnet_host(metrics: Any) -> None:
    with listener(healthy()) as (port, _):
        configure_scan(metrics, port, port)
        server = metrics.make_server(0)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
            connection.putrequest("GET", "/api/instances", skip_host=True)
            connection.putheader("Host", "attacker.example")
            connection.endheaders()
            rejected = connection.getresponse()
            assert rejected.status == 421
            rejected.read()

            connection.putrequest("GET", "/api/instances", skip_host=True)
            connection.putheader("Host", "serena.private-tailnet.ts.net")
            connection.endheaders()
            accepted = connection.getresponse()
            assert accepted.status == 200
            accepted.read()
        finally:
            connection.close()
            server.shutdown()
            thread.join()
            server.server_close()


@pytest.mark.parametrize(
    "host",
    [
        ".ts.net",
        "foo..ts.net",
        "foo.ts.net:",
        "foo.ts.net:bad",
        "foo.ts.net:443@evil",
        "127.0.0.1:bad",
        "foo.ts.net:443:evil",
        "evil@foo.ts.net",
    ],
)
def test_http_surface_rejects_malformed_host(metrics: Any, host: str) -> None:
    server = metrics.make_server(0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1])
        connection.putrequest("GET", "/api/instances", skip_host=True)
        connection.putheader("Host", host)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 421
        response.read()
    finally:
        connection.close()
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("method", ["HEAD", "TRACE", "CONNECT", "DELETE", "OPTIONS", "PATCH", "POST", "PUT", "FOO"])
def test_http_surface_rejects_every_non_get_method(metrics: Any, method: str) -> None:
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


def test_help_describes_loopback_and_tailscale_serve(metrics: Any, capsys: pytest.CaptureFixture[str]) -> None:
    assert metrics.main(["--help"]) == 0
    output = capsys.readouterr().out
    assert "127.0.0.1" in output
    assert "tailscale serve --bg" in output
