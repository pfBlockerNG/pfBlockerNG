<?php

declare(strict_types=1);

/**
 * A stand-in for the Core API's Unix socket (go/pfb_core), for the tests of pfb_core_call() and the resource client. Prints
 * "ready" once it listens.
 *
 *   php CoreApiStandIn.php <socket> <record file> <status> <body>
 *     takes ONE connection, reads one HTTP request (headers, then the Content-Length body), stores it raw in the record file,
 *     answers with the given status and body as application/json, and exits.
 *
 *   php CoreApiStandIn.php <socket> <record file> script <script file>
 *     answers one connection per entry of the script file, a JSON list, in order, and exits 0 once every entry was served.
 *     An entry is {"status": int, "type": "<Content-Type>", "body": "<text>"} with four optional keys: "length", the
 *     Content-Length sent in place of the body's own (more than the body: a truncated reply); "close": TRUE, which sends no
 *     Content-Length, so the body ends where the connection closes; "hang": TRUE, which answers nothing and holds the
 *     connection until the client closes it; and "stall": TRUE, which sends the reply and then holds the connection until the
 *     client closes it (with a "length" over the body: a reply that goes silent part way); "interim": TRUE, which sends an
 *     HTTP 103 block with a Content-Length of 100000 before the reply; and "lengthFirst": TRUE, which sends the
 *     Content-Length before the Content-Type. An entry may also carry "if", the decoded request body it is matched against,
 *     and "then", another entry answered in its place when the request body is exactly "if". Each request is appended to the record file as one JSON line
 *     {"path": "<request path>", "params": <the decoded request body>}.
 */
[, $socket, $record, $status, $body] = $argv + [NULL, NULL, NULL, '200', ''];

/** One HTTP request read from $conn: [its header block, its body]; NULL when the client closed first. */
function standin_read_request($conn): ?array
{
	$request = '';
	while (!str_contains($request, "\r\n\r\n")) {
		$chunk = fread($conn, 8192);
		if ($chunk === FALSE || $chunk === '') {
			return NULL;
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
	return [$head, $rest];
}

$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");

if ($status === 'script') {
	$script = json_decode((string) file_get_contents($body), TRUE, 16, JSON_THROW_ON_ERROR);
	foreach ($script as $i => $reply) {
		$conn = @stream_socket_accept($server, 20);
		if ($conn === FALSE) {
			fwrite(STDERR, "entry {$i} of the script was never asked for\n");
			exit(3);
		}
		$request = standin_read_request($conn);
		if ($request === NULL) {
			fwrite(STDERR, "entry {$i}: the client closed before its request was read\n");
			exit(4);
		}
		$path = explode(' ', strtok($request[0], "\r\n") ?: '')[1] ?? '';
		$params = json_decode($request[1], TRUE);
		file_put_contents($record, json_encode(['path' => $path, 'params' => $params]) . "\n", FILE_APPEND);
		if (array_key_exists('if', $reply) && $params === $reply['if']) {
			$reply = $reply['then'];
		}
		if (empty($reply['hang'])) {
			$text = (string) $reply['body'];
			$length = empty($reply['close']) ? 'Content-Length: ' . ($reply['length'] ?? strlen($text)) : '';
			$headers = empty($reply['lengthFirst']) ? ["Content-Type: {$reply['type']}", $length] : [$length, "Content-Type: {$reply['type']}"];
			$interim = empty($reply['interim']) ? '' : "HTTP/1.1 103 Early Hints\r\nContent-Length: 100000\r\n\r\n";
			@fwrite($conn, $interim . "HTTP/1.1 {$reply['status']} Stand-in\r\n" . implode("\r\n", array_filter($headers))
				. "\r\nConnection: close\r\n\r\n{$text}");
		}
		if (!empty($reply['hang']) || !empty($reply['stall'])) {
			while (!feof($conn) && fread($conn, 8192) !== FALSE) {
			}
		}
		fclose($conn);
	}
	@unlink($socket);
	exit(0);
}

$conn = @stream_socket_accept($server, 20);
if ($conn === FALSE) {
	exit(3);
}
$request = standin_read_request($conn);
if ($request === NULL) {
	exit(4);
}
[$head, $rest] = $request;
file_put_contents($record, "{$head}\r\n\r\n{$rest}");
fwrite($conn, "HTTP/1.1 {$status} Stand-in\r\nContent-Type: application/json\r\nContent-Length: " . strlen($body)
	. "\r\nConnection: close\r\n\r\n{$body}");
fclose($conn);
@unlink($socket);
