"""Issue #2143 build-record destination annotation reproduction."""

from __future__ import annotations

import pfb_pkg


def test_release_build_record_carries_an_ordered_destination_tuple() -> None:
    record: dict[str, object] = {
        "schema": 1,
        "channel": "testing",
        "release_line": "release/4.0",
        "classification": "alpha",
        "source_tag": "v4.0.1.a1",
        "source_sha": "a" * 40,
        "canonical_package_version": "4.0.1.a1",
        "native_recipe_identity": "pfSense-pkg-pfBlockerNG-testing",
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": {
            "pfsense_version": "2.8",
            "channel": "CE",
            "freebsd_version": "15.0-RELEASE",
            "freebsd_major": "15",
            "php_version": "8.3",
            "py_flavor": "py311",
            "variant": "CE",
            "status": "active",
            "extra_pkgs": [],
        },
        "freebsd_ports_sha": "b" * 40,
        "route": "testing/ce-2.8",
        "source_date_epoch": 0,
        "destinations": ["testing", "edge"],
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    assert pfb_pkg.validate_build_record(record)["destinations"] == ["testing", "edge"]
