<?php

/*
 * PFBL-01 sniff fixture (NOT production code). In-scope function name + a dynamic
 * filesystem-path build (interpolated string) with NO preceding validation -> the
 * sniff MUST flag it. Pinned by
 * RequirePfbFilterSniffTest::testFlagsPathBuildWithoutValidator.
 */

function pfb_manage_dnsbl_vip($mode)
{
    $iface = $_POST['if'];
    $path  = "/var/db/pfblockerng/{$iface}.txt";
    return $path;
}
