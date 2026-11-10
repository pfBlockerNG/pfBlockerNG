import os
import sys
from collections.abc import Iterator

# Put the pkg dir on sys.path so tests can import the shipped pure-Python modules
# (pfb_dnsbl_regex_rules, dns_proxy.pfb_upstream_observer) from their repo location.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "usr", "local", "pkg", "pfblockerng"))

# Put scripts/ on sys.path so the hyphen-named tools loaded by path in the
# build-repo / gen_landing tests can resolve their shared `import pfb_pkg`
# (at CI runtime that dir is sys.path[0] because the tools are run directly).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pytest  # noqa: E402

from tests.timing import close_log, open_log  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _pfb_timing_log() -> Iterator[None]:
    """Open the per-step timing log once for the whole session, close it once at the end.

    issue #605: this is the single setup/teardown for the PFB_TIMING file sink —
    ``tests.timing._emit`` only writes to the already-open handle, never sets up per call.
    ``open_log`` is a no-op when ``PFB_DIAG_DIR`` is unset (the unit suite — terminal-only),
    so nothing is written there. At teardown, surface where the log landed and how many
    steps it captured.
    """
    open_log()
    yield
    path = close_log()
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                count = sum(1 for _ in handle)
            print(f"\nPFB_TIMING_SUMMARY {path} ({count} steps)", flush=True)
        except OSError:
            pass
