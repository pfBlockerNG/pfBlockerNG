<?php

/*
 * PFBL-01 sniff fixture (NOT production code). In-scope function name whose exec +
 * path sinks are all PRECEDED by a semantic-validation call -> the sniff MUST stay
 * silent. This is the before/after partner of violation_exec.php: same sink, the
 * only difference is the leading pfb_filter(), so a green result proves the
 * validator presence is what suppresses the finding. Pinned by
 * RequirePfbFilterSniffTest::testValidatorBeforeSinkPasses.
 */

function pfb_ss_resolve_target($target)
{
	$filtered = pfb_filter($target, PFB_FILTER_DOMAIN, 'pfb_ss_resolve_target');
	if (empty($filtered)) {
		return array('', '');
	}
	$out = array();
	exec('/usr/bin/drill ' . escapeshellarg($filtered), $out);
	return $out;
}
