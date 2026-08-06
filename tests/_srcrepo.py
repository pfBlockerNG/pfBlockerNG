"""Resolve the pfBlockerNG source-repo checkout this suite uses as its engine.

Test-only convenience around ``scripts.publish_catalogues.load_engine``: reads
``PFB_SRC``, defaulting to this repository itself (the publisher and the engine it
loads now live in the same checkout), and raises a clear error before any test runs if
the engine checkout is missing or incomplete.
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


class SourceRepoError(RuntimeError):
    """The pfBlockerNG source-repo checkout used as the engine is missing or incomplete."""


def resolve_src_root() -> Path:
    raw = os.environ.get("PFB_SRC")
    root = Path(raw).expanduser() if raw else _REPO_ROOT
    required = (
        root / "scripts" / "pfb_pkg.py",
        root / "scripts" / "build-repo-portable.py",
        root / "scripts" / "nightly_provenance.py",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SourceRepoError(
            f"pfBlockerNG source-repo engine not found at {root} (set PFB_SRC to override); "
            f"missing: {', '.join(missing)}"
        )
    return root
