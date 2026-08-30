<?php

declare(strict_types=1);

/** @return resource */
function pfb_test_http_fixture_stream_context()
{
	return stream_context_create([
		'http' => ['timeout' => 0.05, 'ignore_errors' => TRUE],
	]);
}

function pfb_test_http_fixture_event_received(
	int $port,
	string $secret,
	?callable $request = NULL
): bool {
	$context = pfb_test_http_fixture_stream_context();
	$url = "http://127.0.0.1:{$port}/__pfb_ready";
	$body = $request === NULL
		? @file_get_contents($url, FALSE, $context)
		: $request($url, $context);

	return is_string($body) && hash_equals($secret, $body);
}
