<?php

/*
 * PFBL-01 sniff fixture (NOT production code). A namespace-qualified exec sink
 * (root-namespaced \exec) inside an in-scope function with no preceding validator
 * MUST still be flagged: PHP tokenizes \exec as a single T_NAME_FULLY_QUALIFIED
 * token, so a T_STRING-only match would let it slip past (a gate bypass). No '/'
 * appears in any literal here, so only the exec-family branch can fire. Pinned by
 * RequirePfbFilterSniffTest::testFlagsNamespaceQualifiedExecSink.
 */

function pfb_ss_resolve_target($target)
{
	\exec('echo ' . $target);
}
