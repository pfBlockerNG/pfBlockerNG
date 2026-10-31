<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket (go/pfb_dns_gateway, ctl.go), for the tests of the live listen-address verbs
 * and of everything that asks which listeners the gateway serves (docs/specs/pfb-dns-live-listen-addresses.md, D2): listens on a Unix
 * socket and takes connections until the test ends it. Each connection is one frame: four head bytes (FF FF FF FE add, FF FF FF FD
 * remove, FF FF FF FC list), and for add and remove a 4-byte big-endian length and that many bytes `<kind> <host:port>`, sent in ONE
 * sendmsg(2) with its SCM_RIGHTS descriptors; a list frame is the four head bytes alone. Per connection it records one JSON line
 * {"head": hex, "body": text, "fds": [{"type": "stream"|"dgram", "name": "host:port", "listening": bool}]} in <record file> BEFORE it
 * replies, so that what a test reads after the call under test returns is complete; then it closes every received descriptor and
 * writes the reply. Prints "ready" once it listens.
 *
 *   php ListenerControlServer.php <socket> <record file> <replies JSON> <served JSON>
 *
 * <replies JSON> is a list, one entry per add or remove connection in order: a reply line without its newline ("ok", "error: ..."),
 * or null to hang up with no reply; connections past the list's end are answered "ok". A list frame takes no entry of it. The test's
 * barrier is stdin: when it closes, the server ends.
 *
 * <served JSON> is what the gateway serves: {"listening": ["<kind> <host:port>", ...], "refused": {"<kind> <host:port>": "<reason>"},
 * "list": absent | null | "<reply>"}; the default serves nothing and refuses nothing. A list frame is answered with one
 * `listening <key>` line for each served listener (in the given order), one `refused <key> <reason>` line for each refusal and a final
 * `ok`; "list" as a string is the whole reply instead, byte for byte (nothing is added to it), and as null the connection is closed
 * with no reply. An add or remove answered `ok` also changes what is served: an added listener is served (and no longer refused), a
 * removed one is not.
 */
[, $socket, $record, $script, $servedJson] = $argv + [NULL, NULL, NULL, '[]', '{}'];
$replies = json_decode((string) $script, TRUE, 4, JSON_THROW_ON_ERROR);
$served = json_decode((string) $servedJson, TRUE, 4, JSON_THROW_ON_ERROR) + ['listening' => [], 'refused' => []];

$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");

// SO_ACCEPTCONN is not a constant of the sockets extension: 30 on Linux, 2 on FreeBSD
$acceptconn = (PHP_OS_FAMILY === 'Linux') ? 30 : 2;
$spell = static function (Socket $sock): string {
	socket_getsockname($sock, $address, $port);
	return (str_contains((string) $address, ':') ? "[{$address}]" : $address) . ":{$port}";
};

while (TRUE) {
	$waiting = [$server, STDIN];
	$write = $except = NULL;
	if (stream_select($waiting, $write, $except, 30) < 1 || in_array(STDIN, $waiting, TRUE)) {
		exit(0);
	}
	$stream = @stream_socket_accept($server, 5);
	if ($stream === FALSE) {
		exit(3);
	}
	$conn = socket_import_stream($stream);
	socket_set_option($conn, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
	$message = ['name' => [], 'buffer_size' => 264, 'controllen' => socket_cmsg_space(SOL_SOCKET, SCM_RIGHTS, 4)];
	$got = @socket_recvmsg($conn, $message, 0);
	$data = ($got === FALSE) ? '' : (string) $message['iov'][0];
	$head = bin2hex(substr($data, 0, 4));
	$length = (strlen($data) >= 8) ? unpack('N', substr($data, 4, 4))[1] : 0;
	// A list frame is its four head bytes alone: waiting for a length would cost the whole receive timeout
	$want = ($head === 'fffffffc') ? 4 : 8 + min($length, 256);
	while (strlen($data) < $want) {
		$more = @socket_read($conn, $want - strlen($data));
		if ($more === FALSE || $more === '') {
			break;
		}
		$data .= $more;
	}
	$fds = [];
	foreach ($message['control'] ?? [] as $control) {
		foreach ((array) ($control['data'] ?? []) as $fd) {
			$type = socket_get_option($fd, SOL_SOCKET, SO_TYPE);
			$fds[] = [
				'type' => ($type === SOCK_STREAM) ? 'stream' : (($type === SOCK_DGRAM) ? 'dgram' : "other {$type}"),
				'name' => $spell($fd),
				'listening' => ((int) socket_get_option($fd, SOL_SOCKET, $acceptconn)) === 1,
			];
		}
	}
	$body = substr($data, 8, $length);
	file_put_contents($record, json_encode(['head' => $head, 'body' => $body, 'fds' => $fds], JSON_THROW_ON_ERROR) . "\n", FILE_APPEND);

	if ($head === 'fffffffc') {
		if (!array_key_exists('list', $served)) {
			$lines = array_map(static fn (string $key): string => "listening {$key}", $served['listening']);
			foreach ($served['refused'] as $key => $reason) {
				$lines[] = "refused {$key} {$reason}";
			}
			$wire = implode("\n", [...$lines, 'ok']) . "\n";
		} else {
			$wire = $served['list'];
		}
	} else {
		$reply = array_key_exists(0, $replies) ? array_shift($replies) : 'ok';
		if ($reply === 'ok' && $head === 'fffffffe') {
			$served['listening'] = array_values(array_unique([...$served['listening'], $body]));
			unset($served['refused'][$body]);
		} elseif ($reply === 'ok' && $head === 'fffffffd') {
			$served['listening'] = array_values(array_diff($served['listening'], [$body]));
		}
		$wire = ($reply === NULL) ? NULL : "{$reply}\n";
	}
	unset($message, $fd, $control);
	if ($wire !== NULL) {
		@socket_write($conn, $wire);
	}
	fclose($stream);
	unset($conn);
}
