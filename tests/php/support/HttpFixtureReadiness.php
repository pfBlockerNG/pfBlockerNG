<?php

declare(strict_types=1);

function pfb_test_http_fixture_event_received(int $port, string $secret): bool
{
	$context = stream_context_create([
		'http' => ['timeout' => 0.05, 'ignore_errors' => TRUE],
	]);
	$body = @file_get_contents("http://127.0.0.1:{$port}/__pfb_ready", FALSE, $context);

	return is_string($body) && hash_equals($secret, $body);
}

/**
 * Bounded-polls $stderrPath (40 x 50ms) for the async `php -S 127.0.0.1:0`
 * banner; parses only `http://127.0.0.1:(\d+)\)`, tolerant of banner wording.
 * Returns 0 if no complete match lands within the bound.
 */
function pfb_test_http_fixture_port(string $stderrPath): int
{
	for ($poll = 0; $poll < 40; $poll++) {
		$banner = @file_get_contents($stderrPath);
		if (is_string($banner) && preg_match('#http://127\.0\.0\.1:(\d+)\)#', $banner, $matches) === 1) {
			return (int) $matches[1];
		}
		usleep(50000);
	}
	return 0;
}
