<?php

declare(strict_types=1);

/**
 * A stand-in for the Core API's Unix socket (go/pfb_core) for the tests of the pages that validate and push settings: serves
 * one connection after another until it is killed (it gives up after 120 s), answers each request from a script, and appends
 * one JSON line per request to the record file: {"method": "<Method>", "body": <the request's JSON object>}. Prints "ready"
 * once it listens.
 *
 *   php CoreSettingsStandIn.php <socket> <record file> <script JSON>
 *
 * The script maps a method to [status, reply object]: {"ValidateSettings": [200, {}], "GetSettings": [200, {...}]}. A method
 * the script does not name answers 404 with the API's `not_found` error envelope.
 */
[, $socket, $record, $scriptJson] = $argv + [NULL, NULL, NULL, '{}'];
$script = json_decode((string) $scriptJson, TRUE, 512, JSON_THROW_ON_ERROR);

$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");

$deadline = time() + 120;
while (time() < $deadline) {
	$conn = @stream_socket_accept($server, 1);
	if ($conn === FALSE) {
		continue;
	}
	stream_set_timeout($conn, 5);
	$request = '';
	while (!str_contains($request, "\r\n\r\n")) {
		$chunk = fread($conn, 8192);
		if ($chunk === FALSE || $chunk === '') {
			break;
		}
		$request .= $chunk;
	}
	if (!str_contains($request, "\r\n\r\n")) {
		fclose($conn);
		continue;
	}
	[$head, $body] = explode("\r\n\r\n", $request, 2);
	$length = preg_match('/^Content-Length:\s*(\d+)\s*$/mi', $head, $m) === 1 ? (int) $m[1] : 0;
	while (strlen($body) < $length) {
		$chunk = fread($conn, $length - strlen($body));
		if ($chunk === FALSE || $chunk === '') {
			break;
		}
		$body .= $chunk;
	}
	$method = preg_match('~^POST /v1/([A-Za-z]+) HTTP/~', $head, $m) === 1 ? $m[1] : '';
	file_put_contents($record, json_encode(['method' => $method, 'body' => json_decode($body, TRUE)]) . "\n", FILE_APPEND);
	[$status, $reply] = $script[$method] ?? [404, ['error' => ['code' => 'not_found', 'message' => "no such method: {$method}"]]];
	$payload = json_encode((object) $reply);
	fwrite($conn, "HTTP/1.1 {$status} Stand-in\r\nContent-Type: application/json\r\nContent-Length: " . strlen($payload)
		. "\r\nConnection: close\r\n\r\n{$payload}");
	fclose($conn);
}
@unlink($socket);
