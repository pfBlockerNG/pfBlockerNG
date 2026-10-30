<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket (go/pfb_dns_gateway, ctl.go), for the tests of the live listen-address verbs
 * (docs/specs/pfb-dns-live-listen-addresses.md, D2): listens on a Unix socket and takes connections until the test ends it. Each
 * connection is one frame: four head bytes (FF FF FF FE add, FF FF FF FD remove), a 4-byte big-endian length and that many bytes
 * `<kind> <host:port>`, sent in ONE sendmsg(2) with its SCM_RIGHTS descriptors. Per connection it records one JSON line
 * {"head": hex, "body": text, "fds": [{"type": "stream"|"dgram", "name": "host:port", "listening": bool}]} in <record file> BEFORE it
 * replies, so that what a test reads after the call under test returns is complete; then it appends `listening <body>` (add) or
 * `stopped listening <body>` (remove) to <gateway log> when the reply is `ok` (what the real gateway logs), closes every received
 * descriptor and writes the reply. Prints "ready" once it listens.
 *
 *   php ListenerControlServer.php <socket> <record file> <gateway log> <replies JSON>
 *
 * <replies JSON> is a list, one entry per connection in order: a reply line without its newline ("ok", "error: ...", or "ok silent":
 * `ok` with nothing logged), or null to hang up with no reply; connections past the list's end are answered "ok". The test's barrier
 * is stdin: when it closes, the server ends.
 */
[, $socket, $record, $log, $script] = $argv + [NULL, NULL, NULL, NULL, '[]'];
$replies = json_decode((string) $script, TRUE, 4, JSON_THROW_ON_ERROR);

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
	$length = (strlen($data) >= 8) ? unpack('N', substr($data, 4, 4))[1] : 0;
	while (strlen($data) < 8 + min($length, 256)) {
		$more = @socket_read($conn, 8 + min($length, 256) - strlen($data));
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
	$head = bin2hex(substr($data, 0, 4));
	$body = substr($data, 8, $length);
	file_put_contents($record, json_encode(['head' => $head, 'body' => $body, 'fds' => $fds], JSON_THROW_ON_ERROR) . "\n", FILE_APPEND);

	$reply = array_key_exists(0, $replies) ? array_shift($replies) : 'ok';
	// "ok silent": a gateway that takes the frame and does not log it (the test of the log wait)
	$silent = ($reply === 'ok silent');
	$reply = $silent ? 'ok' : $reply;
	if ($reply === 'ok' && !$silent && $head === 'fffffffe') {
		file_put_contents($log, "listening {$body}\n", FILE_APPEND);
	} elseif ($reply === 'ok' && !$silent && $head === 'fffffffd') {
		file_put_contents($log, "stopped listening {$body}\n", FILE_APPEND);
	}
	unset($message, $fd, $control);
	if ($reply !== NULL) {
		@socket_write($conn, "{$reply}\n");
	}
	fclose($stream);
	unset($conn);
}
