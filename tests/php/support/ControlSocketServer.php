<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket (go/pfb_dns_gateway, ctl.go), for the tests of
 * pfb_dns_proxy_certificate_push(): listens on a Unix socket, takes ONE connection, reads the frame (4-byte big-endian length,
 * then that many bytes), stores the raw frame in a file, and answers as told. Prints "ready" once it listens.
 *
 *   php ControlSocketServer.php <socket> <record file> <ok | error:<text> | silent | close>
 *
 * silent: reads the frame, never answers, and exits when its stdin closes (the test's barrier). close: hangs up without a reply.
 */
[, $socket, $record, $mode] = $argv + [NULL, NULL, NULL, 'ok'];

$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");
// Wait for the one connection, or for the test to close our stdin (it is done with us: nothing was pushed)
$waiting = [$server, STDIN];
$write = $except = NULL;
if (stream_select($waiting, $write, $except, 30) < 1 || !in_array($server, $waiting, TRUE)) {
	exit(3);
}
$conn = @stream_socket_accept($server, 5);
if ($conn === FALSE) {
	exit(3);
}
$read = static function ($stream, int $want): string {
	$got = '';
	while (strlen($got) < $want) {
		$chunk = fread($stream, $want - strlen($got));
		if ($chunk === FALSE || $chunk === '') {
			break;
		}
		$got .= $chunk;
	}
	return $got;
};
$head = $read($conn, 4);
$length = (strlen($head) === 4) ? unpack('N', $head)[1] : 0;
file_put_contents($record, $head . $read($conn, $length));

if ($mode === 'ok') {
	fwrite($conn, "ok\n");
} elseif ($mode === 'partial' || $mode === 'partial-close') {
	fwrite($conn, 'ok');
	if ($mode === 'partial') {
		fgets(STDIN);
	}
} elseif ($mode === 'long-reply') {
	fwrite($conn, str_repeat('a', 512));
	fgets(STDIN);
} elseif (str_starts_with($mode, 'error:')) {
	fwrite($conn, 'error: ' . substr($mode, 6) . "\n");
} elseif ($mode === 'trickle') {
	foreach (str_split("ok\n") as $byte) {
		usleep(150000);
		if (@fwrite($conn, $byte) === FALSE) {
			break;
		}
	}
} elseif ($mode === 'silent') {
	fgets(STDIN);
}
fclose($conn);
