"""The 3.3 release line carries one pinned, development-only packaging snapshot."""

from __future__ import annotations

import hashlib
from pathlib import Path


SOURCE_REVISION = "59450c63a2229779516eccd067ae9eaa54fa17b4"
EXPECTED = {
    "scripts/build-leg.sh": "2a570cc897e6cecf8faeb71e7c842dbc7d580324c03f4aa455bc8b7f704b48b8",
    "scripts/build-pkg-portable.py": "33211c4dfc686306bbce87336f7c49b5e47d387b3dc67682ec9c81a9b5d5a059",
    "scripts/lib/git-env-scrub.sh": "d9b324f0b543a6b47c9bdd9ffaf9b73ba4ebeb838ef6e49f4ebf2475f3f2f84b",
    "scripts/lib/run-id.sh": "c1fce16985e0f2a8efc68a9dc6f26c5e06687435868ce50a6d50e6dbe844485c",
    "scripts/pfb_pkg.py": "a8d2eb7278713b5cc2885699b7bcf8824290c733e70bca21bde1c1677e66b53e",
    "scripts/release_version.py": "bef92294f36c6553b52704ecb1168663db3ade6ae96699f20659180b899c54d5",
    "scripts/select-box.sh": "555dbceaa4e93f20da64fa7b5c3a24255069c5eceac29dc2b4699e1ea96258dd",
    "scripts/sparse-clone-ports.sh": "d1e1d6d62d6287485756811afc12f6d55f1bf16c1149d046913424b3c0a7c96c",
}


def test_release_tooling_matches_pinned_devel_snapshot() -> None:
    assert len(EXPECTED) == 8
    root = Path(__file__).parents[1]
    actual = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in EXPECTED
    }

    assert actual == EXPECTED, f"release tooling must match devel {SOURCE_REVISION}"
