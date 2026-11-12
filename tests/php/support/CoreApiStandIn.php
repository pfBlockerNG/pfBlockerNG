<?php

declare(strict_types=1);

/**
 * A stand-in for the Core API's Unix socket (go/pfb_core), for the tests of pfb_core_call(): listens, takes ONE connection,
 * reads one HTTP request (headers, then the Content-Length body), stores it raw in the record file, answers with the given
 * status and body as application/json, and exits. Prints "ready" once it listens.
 *
 *   php CoreApiStandIn.php <socket> <record file> <status> <body>
 */
[, $socket, $record, $status, $body] = $argv + [NULL, NULL, NULL, '200', ''];

$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");
$conn = @stream_socket_accept($server, 20);
if ($conn === FALSE) {
	exit(3);
}
$request = '';
while (!str_contains($request, "\r\n\r\n")) {
	$chunk = fread($conn, 8192);
	if ($chunk === FALSE || $chunk === '') {
		exit(4);
	}
	$request .= $chunk;
}
[$head, $rest] = explode("\r\n\r\n", $request, 2);
$length = preg_match('/^Content-Length:\s*(\d+)\s*$/mi', $head, $m) === 1 ? (int) $m[1] : 0;
while (strlen($rest) < $length) {
	$chunk = fread($conn, $length - strlen($rest));
	if ($chunk === FALSE || $chunk === '') {
		break;
	}
	$rest .= $chunk;
}
file_put_contents($record, "{$head}\r\n\r\n{$rest}");
fwrite($conn, "HTTP/1.1 {$status} Stand-in\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body)
	. "\r\nConnection: close\r\n\r\n{$body}");
fclose($conn);
@unlink($socket);
