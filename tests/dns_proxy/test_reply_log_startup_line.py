"""The line the proxy's log gets when the reply log starts (issue #3515).

Loading pfb_unbound.py for its row writer makes the module log its own "script loaded" line into the proxy's log, which
on a box with DNSBL off reads as if DNSBL were running; the reply log says what it is right after it. Its own file: the
rows and the setup are pinned in test_reply_log.py, whose content is frozen.
"""

from __future__ import annotations

import pytest


def test_the_proxy_log_says_the_module_is_loaded_for_its_row_writer_only(capfd: pytest.CaptureFixture[str]) -> None:
    import dns_reply_log

    log = dns_reply_log.ReplyLog()
    try:
        assert "DNS Reply logging is on: pfb_unbound.py is loaded for its row writer only" in capfd.readouterr().err
    finally:
        log.close()
