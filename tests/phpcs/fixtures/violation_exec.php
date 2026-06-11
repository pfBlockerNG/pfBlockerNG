<?php

/*
 * PFBL-01 sniff fixture (NOT production code). In-scope function name + an
 * exec-family sink with NO preceding semantic-validation call -> the sniff MUST
 * flag it. Pinned by RequirePfbFilterSniffTest::testFlagsExecSinkWithoutValidator.
 */

function pfb_ss_resolve_target($target)
{
    $out = array();
    exec('/usr/bin/drill ' . escapeshellarg($target), $out);
    return $out;
}
