"""live_gate_matrix.py — pure matrix-building logic for the tagged ingestion
prepare-live-gate job (issue #2389): cross-reference what the pkg-owned stage
operation actually touched against the ci-metadata CI matrix's testable legs, so
validate-live-pages-install fans out exactly one live-VM install test per
(destination channel, testable varver) pair -- never more, never silently fewer.

Import-able normally (unlike build-repo-portable.py, which is hyphen-named): this
module is loaded BOTH by the workflow's inline ``python3 - <<'PY'`` step
(``from scripts.live_gate_matrix import compute_live_gate_matrix``) and directly by
tests/test_live_gate_matrix.py -- the same idiom scripts/release_version.py uses for
the resolve job's classify step (``from scripts.release_version import
derive_destinations_from_git``), so the workflow step and its test exercise the
identical code path, never a re-implementation of it.

stdlib-only, Python 3.11.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_THIS_DIR = Path(__file__).resolve().parent
_BUILD_REPO_PORTABLE_PATH = _THIS_DIR / "build-repo-portable.py"


def _load_build_repo_portable() -> Any:
    """Load build-repo-portable.py (hyphen-named, not import-able normally) to reuse
    its ONE source of truth for varver derivation (``catalog_name_from_version``) --
    never re-implemented here. Same loader idiom as
    scripts/build-dep-pkg-portable.py's ``_load_build_pkg_portable``."""
    # build-repo-portable.py itself does `from pfb_pkg import ...`, resolvable only
    # with scripts/ on sys.path. Only tests/conftest.py puts it there -- a bare
    # `python3 -c "from scripts.live_gate_matrix import ..."` (release-published.yml's
    # own prepare-live-gate step) has no conftest, so this insert is load-bearing
    # outside pytest, same idiom as the other path-loaded script helpers.
    if str(_THIS_DIR) not in sys.path:
        sys.path.insert(0, str(_THIS_DIR))
    spec = importlib.util.spec_from_file_location("build_repo_portable", _BUILD_REPO_PORTABLE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_brp = _load_build_repo_portable()
catalog_name_from_version = _brp.catalog_name_from_version


def compute_live_gate_matrix(
    destinations: Sequence[str],
    touched: Sequence[str],
    ci_matrix: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Cross-reference a publish's touched targets against the CI matrix.

    Returns ``(matrix, untestable, drifted)``:

    - ``matrix``: one row per (destination, CI leg) pair whose
      ``"<destination>/<varver>"`` is in ``touched`` -- the exact set of live-VM
      install legs ``validate-live-pages-install`` fans out over. Each row carries
      ``channel`` (the destination), ``varver``, and the leg's own
      ``pfsense_version``/``image_name``/``mac``/``freebsd_major``/``php_version``/
      ``py_flavor``/``extra_pkgs``.
    - ``untestable``: ``touched`` entries whose varver has NO CI-matrix leg
      producing it -- something this publish shipped but the live gate cannot
      install-test, regardless of destination.
    - ``drifted``: ``touched`` entries whose channel prefix is not even present in
      ``destinations`` -- state drift between what ``resolve`` classified and what
      the stage step actually wrote.

    ``ci_matrix`` rows are exactly ``read-version-matrix.sh --github-output``'s
    ``ci_matrix`` entries (one row per pfSense version, never deduped by
    freebsd_major); ``leg["variant"]`` is CE/Plus, unrelated to the destination
    ``channel`` in the returned rows.
    """
    per_leg_varver = [(leg, catalog_name_from_version(leg["pfsense_version"], leg["variant"])) for leg in ci_matrix]
    leg_varvers = {varver for _leg, varver in per_leg_varver}
    dest_set = set(destinations)

    drifted: list[str] = []
    untestable: list[str] = []
    for target in touched:
        channel, _, varver = target.partition("/")
        if channel not in dest_set:
            drifted.append(target)
        elif varver not in leg_varvers:
            untestable.append(target)

    touched_set = set(touched)
    matrix: list[dict[str, Any]] = []
    for destination in destinations:
        for leg, varver in per_leg_varver:
            target = f"{destination}/{varver}"
            if target not in touched_set:
                continue
            matrix.append(
                {
                    "channel": destination,
                    "varver": varver,
                    "pfsense_version": leg["pfsense_version"],
                    "image_name": leg["image_name"],
                    "mac": leg["mac"],
                    "freebsd_major": leg["freebsd_major"],
                    "php_version": leg["php_version"],
                    "py_flavor": leg["py_flavor"],
                    "extra_pkgs": leg.get("extra_pkgs", []),
                }
            )
    return matrix, untestable, drifted
