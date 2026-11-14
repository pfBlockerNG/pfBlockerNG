#!/usr/bin/env python3
"""Fail when the Nightly ports recipe's GH_TUPLE/GL_TUPLE disagree with what devel's Go modules need (#4007).

Usage: check_nightly_core_tuples.py MAKEFILE MODULES_TXT SOURCE_ROOT

Runs the portable builder's own tuple check (build-pkg-portable.py `_check_gh_tuple_parity`) at PR time instead of
at the next nightly: the gateway's tuples must name the modules of the recipe's modules.txt, and the tuples under
go/pfb_core/vendor/ exactly the modules go/pfb_core/go.mod requires beyond the gateway's (pfBlockerNG/xxh3).
Exit 1 with one `::error::` naming the ports follow-up on any disagreement.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    makefile, modules_txt, source_root = (Path(a) for a in argv)
    sys.path.insert(0, str(_SCRIPTS))
    spec = importlib.util.spec_from_file_location("build_pkg_portable", _SCRIPTS / "build-pkg-portable.py")
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = builder  # dataclasses resolve the module by name
    spec.loader.exec_module(builder)
    try:
        builder._check_gh_tuple_parity(
            builder.Makefile(makefile, {"FILESDIR": str(modules_txt.parent)}),
            modules_txt,
            builder._core_own_requires(source_root),
        )
    except builder.BuildError as exc:
        detail = str(exc).replace("\n", " ")
        print(
            f"::error::The Nightly ports recipe no longer carries what go/pfb_core and go/pfb_dns_gateway need: "
            f"{detail}. Follow-up ports change needed: a pfBlockerNG/FreeBSD-ports PR against pfblockerng/use-github "
            f"that moves the matching GH_TUPLE entries in net/pfSense-pkg-pfBlockerNG-nightly/Makefile "
            f"(example: pfBlockerNG/FreeBSD-ports#20). This check passes once that change is on pfblockerng/use-github."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
