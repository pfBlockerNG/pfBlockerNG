<?php

/*
 * PFBL-01 sniff fixture (NOT production code). In-scope function name + a
 * json_encode() manifest sink with NO preceding validation -> the sniff MUST flag
 * it. Pinned by RequirePfbFilterSniffTest::testFlagsManifestSinkWithoutValidator.
 */

function pfb_unbound_python_sources($feeds)
{
    $header = $feeds[0]['header'];
    return json_encode(array('feed' => $header));
}
