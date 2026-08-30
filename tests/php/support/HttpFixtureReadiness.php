<?php

declare(strict_types=1);

function pfb_test_http_fixture_event_received(int $port, string $nonce): bool
{
	$context = stream_context_create([
		'http' => ['timeout' => 0.05, 'ignore_errors' => TRUE],
	]);
	$body = @file_get_contents("http://127.0.0.1:{$port}/__pfb_ready/{$nonce}", FALSE, $context);

	return is_string($body) && hash_equals($nonce, $body);
}
