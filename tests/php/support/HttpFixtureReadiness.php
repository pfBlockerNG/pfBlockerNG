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
