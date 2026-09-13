<?php

// CI-only: PHP exec() must preserve upstream failures through the extraction pipeline.
foreach ([7, 0] as $expected) {
	$output = [];
	exec("ulimit -f 4000000 || exit 1; set -o pipefail; "
		. "(printf 'header\\r\\npayload\\r\\n'; exit {$expected}) | sed '1d' | tr -d '\\r'",
		$output, $actual);
	if ($actual !== $expected || $output !== ['payload']) {
		fwrite(STDERR, "extraction shell: expected exit {$expected} and [\"payload\"], got exit {$actual} and "
			. json_encode($output) . "\n");
		exit(1);
	}
	echo "extraction shell: exit {$actual}, payload preserved\n";
}
