<?php

declare(strict_types=1);

/**
 * Canonical log-type vocabulary, derived from pfb_cfg_registry()'s
 * log_max_<type> keys (pfblockerng_extra.inc) so CfgGatewayTest's
 * log_max_days_<type> coverage can never silently drift from the production
 * registry (issue #1037).
 *
 * @return list<string>
 */
function pfb_test_log_types(): array
{
	$types = [];
	foreach (array_keys(pfb_cfg_registry()) as $key) {
		if (str_starts_with($key, 'gen/log_max_') && !str_starts_with($key, 'gen/log_max_days_')) {
			$types[] = substr($key, strlen('gen/log_max_'));
		}
	}
	return $types;
}
