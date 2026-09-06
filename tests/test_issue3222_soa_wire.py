"""Issue #3222: dig/drill SOA presentation is tab-separated, not ' SOA '."""


def rr_has_type(raw: str, rtype: str) -> bool:
    """True if any RR line has ``rtype`` as the TYPE field (tab or space separated)."""
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3] == rtype:
            return True
    return False


def test_space_wrapped_soa_misses_tab_separated_dig() -> None:
    # Review B1: BIND dig and ldns drill print RR fields with tabs. A check for
    # the substring " SOA " never matches a correct Type-2 NODATA reply.
    raw = (
        ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0\n"
        "example.com.\t3600\tIN\tSOA\tpfb.invalid. nobody.invalid. 1 3600 1200 604800 3600\n"
    )
    assert " SOA " not in raw, f"fixture must be tab-separated, got {raw!r}"
    assert rr_has_type(raw, "SOA"), f"expected a TYPE-field SOA in {raw!r}"
