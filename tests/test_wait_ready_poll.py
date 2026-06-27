"""Pin wait_ready.sh's boot-readiness poll cadence and per-role gate (ADR-04).

``tests/smoke/wait_ready.sh`` is what the harness blocks on between "qemu launched"
and "guest usable". Its OLD shape probed from t=0 on an exponential 2s..15s backoff
and required SSH **and** (optionally) web — so a guest that became ready at ~20s was
not learned ready until a much later poll, and the suite "waited for nothing".

The new shape:

* an **8s initial grace** (no VM answers sooner) before the first probe;
* a **1s** poll while readiness is imminent (< 30s), relaxing to **5s** after;
* a **1s** connect timeout (local loopback — slower than that is dead);
* a **staggered liveness chain** for pfSense: a real ``ssh true`` floor (alive) logged once,
  then the web 200 (ready), so a slow-but-alive cold box is never misread as dead;
* a **per-role gate**: pfSense gates on the **web** server (admin panel; nginx+PHP
  come up after sshd, so a live panel implies SSH), civm on **SSH** (no web server).

These read wait_ready.sh as text (no VM) and pin that cadence + gate, so a regression
back to the slow exponential backoff or the SSH-and-web gate fails here. The real
boot-time win is proven by the live-VM smoke (boot-to-ready timing).
"""

from __future__ import annotations

from pathlib import Path

_WAIT_READY_SH = Path(__file__).resolve().parent.parent / "tests" / "smoke" / "wait_ready.sh"


def _wait_ready_text() -> str:
    return _WAIT_READY_SH.read_text(encoding="utf-8")


def test_initial_grace_skips_early_probes() -> None:
    """An 8s grace precedes the first probe — no VM answers sooner, so probing is waste.

    The grace is a real branch: while elapsed < INITIAL_GRACE the loop only sleeps
    (still watching the qemu PID) and continues, rather than firing an SSH/web probe.
    """
    text = _wait_ready_text()
    assert "INITIAL_GRACE=8" in text
    assert 'if [ "$ELAPSED" -lt "$INITIAL_GRACE" ]; then' in text


def test_poll_cadence_is_one_then_five_seconds_not_exponential() -> None:
    """Poll every 1s while readiness is plausible (< 75s), then every 5s — no backoff.

    The 75s window spans both a ~15s fast boot and a ~55-60s slow/contended one (so
    the real readiness is caught within 1s, not 5s). Pins both branches of the
    cadence (1s and 5s at the 75s boundary) AND that the old exponential backoff is
    gone: a `BACKOFF` doubling toward a 15s cap would reintroduce the overshoot.
    """
    text = _wait_ready_text()
    assert 'if [ "$ELAPSED" -lt 75 ]; then' in text
    assert "INTERVAL=1" in text
    assert "INTERVAL=5" in text
    # The exponential backoff (BACKOFF=2; BACKOFF*2; cap 15) must be gone.
    assert "BACKOFF" not in text


def test_connect_timeouts_are_one_second() -> None:
    """Probes CONNECT-time out after 1s — a local-loopback connect that slow is dead.

    The web probe additionally allows up to 2s TOTAL: a cold nested-KVM
    webConfigurator (CI) can take a couple of seconds to render its first response
    even though the connect succeeds immediately, so a 1s total cap would starve
    a live-but-slow server and time out the whole gate. Split connect (1s) from
    total (2s) so the dead-port fail-fast intent survives without that starvation.
    """
    text = _wait_ready_text()
    assert "ConnectTimeout=1" in text  # ssh connect
    assert "--connect-timeout 1" in text  # curl connect
    assert "--max-time 2" in text  # curl total: headroom for a cold nested-KVM response
    # The old 5s SSH connect timeout, and the too-tight 1s curl total, must be gone.
    assert "ConnectTimeout=5" not in text
    assert "--max-time 1" not in text


def test_pfsense_web_role_has_ssh_liveness_floor() -> None:
    """The pfSense/web role exercises a real ``ssh true`` liveness FLOOR, logged once.

    The staggered chain: a slow-but-alive box (web warming) is distinguishable from a dead
    one because the SSH floor is observed and logged before the web 200. A TCP/ping rung
    would be a false-green over SLIRP, so the floor is a real ssh command, not a connect.
    The floor only logs; the web 200 still owns the readiness exit (per-role gate unchanged).
    """
    text = _wait_ready_text()
    assert "WEB_SSH_SEEN" in text  # the floor-observed flag (logged once)
    assert '"root@${HOST}" true' in text  # the real ssh liveness probe
    assert "warming" in text  # the "alive — web warming" diagnostic that makes the state clear


def test_default_timeout_has_headroom_over_slow_boot() -> None:
    """The hard readiness ceiling defaults to ~3 min (was 600s).

    Web-ready is ~55-60s on a nested-KVM / low-power box and higher under
    parallel-lane CPU contention, so ~1 min was too tight; ~3 min leaves headroom.
    A dead qemu still fails the poll immediately via its PID watch, so the ceiling
    only bounds an alive-but-hung boot.
    """
    text = _wait_ready_text()
    assert 'TIMEOUT="${4:-180}"' in text


def test_pfsense_gates_on_web_and_civm_on_ssh() -> None:
    """Readiness is per-role: web-port set -> web gate; unset -> SSH gate.

    pfSense passes a web-port and is ready when the webConfigurator answers; civm
    passes none and is ready when SSH works. The OLD combined "SSH and web" gate
    (the `SSH_READY`/`WEB_READY` AND) must be gone — that is what made pfSense wait
    on SSH it does not need to gate on.
    """
    text = _wait_ready_text()
    # pfSense branch: web probe guarded by a non-empty WEB_PORT.
    assert 'if [ -n "$WEB_PORT" ]; then' in text
    assert "http://${HOST}:${WEB_PORT}/" in text
    # civm branch: the tcsh-safe bare-`true` SSH probe.
    assert '"root@${HOST}" true' in text
    # The old AND-gate is gone.
    assert "SSH_READY" not in text
    assert "WEB_READY" not in text
