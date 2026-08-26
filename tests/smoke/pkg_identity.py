"""The package NAME the branch under test installs as.

The built .pkg carries the name of the port the builder was pointed at
(``build-pkg-portable.py --channel`` -> ``net/pfSense-pkg-pfBlockerNG-<channel>``), so a
live-install case that spells the suffix by hand silently outlives every channel rename and
then fails on the VM at ``pkg install`` — issue #2166, where the workflows still asked for
the retired ``devel`` channel weeks after the ports tree had replaced it with
``testing``/``edge``/``nightly``.

Stdlib only, no relative imports: the default unit tier ``--ignore``s tests/smoke, so
tests/test_issue2166_workflow_channel_inputs.py loads this module BY PATH to pin it against
the workflows. Importing the smoke package instead would drag in conftest's dnspython and
requests, which that tier does not install.
"""

from __future__ import annotations

import re
from pathlib import Path

# The channel build-pkg-linux.yml builds, for the case where no artifact is in hand (a dev
# box collecting without SMOKE_PKG). test_issue2166_workflow_channel_inputs.py pins this to
# the workflow's own default, so the two can never drift apart unnoticed.
DEFAULT_CHANNEL = "edge"

# `<name>-<version>.pkg`: a FreeBSD pkg version never contains '-' and always starts with a
# digit, so the last '-' before a digit run ends the name.
_PKG_FILE = re.compile(r"^(?P<name>pfSense-pkg-pfBlockerNG(?:-[a-z]+)?)-\d[^-]*\.pkg$")


def branch_channel(pkg_path: str | None) -> str:
    """Return the channel the build installed from ``pkg_path`` reports on the box.

    `pfb_channel_from_pkgname()` derives the channel from the installed package NAME, so a
    live case asserting on the channel must read it from the same artifact the name comes
    from — a hard-coded ``"devel"`` outlives a rename exactly as silently as a hard-coded
    package name did (issue #2166).
    """
    suffix = branch_pkg_name(pkg_path)[len("pfSense-pkg-pfBlockerNG") :]
    return suffix.lstrip("-") or "stable"


def branch_pkg_name(pkg_path: str | None) -> str:
    """Return the pfBlockerNG package name ``pkg_path`` installs as.

    ``pkg_path`` is the built artifact (the harness hands it over as ``SMOKE_PKG``); pass
    ``None`` when there is no artifact to read and the caller only needs the name CI builds.

    An artifact whose name cannot be read raises: guessing there would hand the caller a name
    the .pkg does not have, which is the silent drift this module exists to stop.
    """
    if not pkg_path:  # unset or empty SMOKE_PKG — conftest treats both as "no artifact"
        return f"pfSense-pkg-pfBlockerNG-{DEFAULT_CHANNEL}"
    match = _PKG_FILE.match(Path(pkg_path).name)
    if not match:
        raise ValueError(f"not a pfBlockerNG package filename: {pkg_path!r}")
    return match.group("name")
