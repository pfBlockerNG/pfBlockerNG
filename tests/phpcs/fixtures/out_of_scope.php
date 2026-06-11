<?php

/*
 * PFBL-01 sniff fixture (NOT production code). A function whose name is NOT on the
 * in-scope allow-list: even with a raw, unfiltered exec sink the sniff MUST
 * stay silent, encoding the ADR's "legacy code paths are out of scope" carve-out
 * (scope is an explicit allow-list, never a blanket file scan). Pinned by
 * RequirePfbFilterSniffTest::testOutOfScopeFunctionIsNotFlagged.
 */

function some_legacy_helper($value)
{
    exec('/bin/echo ' . $value);
}
