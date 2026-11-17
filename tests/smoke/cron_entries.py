"""One matcher for "no pfBlockerNG cron entry of any kind" (issue #3996).

Core runs every pfBlockerNG schedule, so the Outpost installs no crontab entry: any
active line or config.xml ``cron/item`` command naming the CLI or a ``pfb_core_`` wrapper is a defect.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

ENTRY = re.compile(r"pfblockerng\.php|pfb_core_")
NO_ROOT_CRONTAB = "crontab: no crontab for root\n"


def root_crontab_text(returncode: int, stdout: str, stderr: str) -> str:
    """Return the root crontab body; only FreeBSD's exact "no crontab for root" is empty, the rest is fatal."""
    if returncode == 0:
        return stdout
    if returncode == 1 and stdout == "" and stderr == NO_ROOT_CRONTAB:
        return ""
    raise RuntimeError(f"unreadable root crontab: rc={returncode} stdout={stdout!r} stderr={stderr!r}")


def find_entries(sources: Iterable[str | bytes], config_commands: Iterable[str] = ()) -> list[str]:
    """Active crontab lines (comments skipped) and config commands that name pfBlockerNG, stripped."""
    found: list[str] = []
    for source in sources:
        text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        for line in text.splitlines():
            if not line.lstrip().startswith("#") and ENTRY.search(line):
                found.append(line.strip())
    found.extend(command.strip() for command in config_commands if ENTRY.search(command))
    return found
