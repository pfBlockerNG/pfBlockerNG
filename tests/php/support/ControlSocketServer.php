<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket (go/pfb_dns_gateway, ctl.go), for the tests of
 * pfb_dns_proxy_certificate_push(): listens on a Unix socket, takes ONE connection, reads the frame (4-byte big-endian length,
 * then that many bytes), stores the raw frame in a file, and then writes only what the test releases. Prints "ready" once it listens.
 *
 *   php ControlSocketServer.php <socket> <record file>
 *
 * Each stdin line is one command: `x<hex>` writes those bytes, and `close` hangs up. Each is acknowledged on stdout once it has
 * happened, so the test knows the bytes are in the socket before PHP polls again. The test's barrier is stdin: when it closes
 * with no command pending, the server ends.
 */
[, $socket, $record] = $argv + [NULL, NULL, NULL];

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

while (($command = fgets(STDIN)) !== FALSE) {
	if ($command === "close\n") {
		fclose($conn);
		fwrite(STDOUT, "ack\n");
		exit(0);
	}
	if (preg_match('/\Ax([0-9a-f]*)\n\z/', $command, $hex) !== 1) {
		fwrite(STDERR, 'unknown command: ' . var_export($command, TRUE) . "\n");
		exit(4);
	}
	if (@fwrite($conn, (string) hex2bin($hex[1])) === FALSE) {
		break;
	}
	fwrite(STDOUT, "ack\n");
}
fclose($conn);
