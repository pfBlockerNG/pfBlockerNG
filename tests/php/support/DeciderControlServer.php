<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket for the decider-restart request (pfb_dns_proxy_decider_restart()): listens on
 * a Unix socket and takes connections until the test ends it. A connection that sends the listener-list request (FF FF FF FC, which
 * every pass makes before and after it acts: issue #3625) is answered as a gateway older than that verb answers it, a bad message
 * length, and is not recorded. Any other connection has every byte the client sends before it hangs up recorded in <record file>
 * (absent when no such connection came), and is answered once, when the 4-byte request is complete, with the bytes the test chose.
 * Prints "ready" once it listens.
 *
 *   php DeciderControlServer.php <socket> <record file> <reply hex | ->
 *
 * `-` as the reply = never answer (a gateway that hangs). The test's barrier is stdin: the server ends when it closes.
 */
[, $socket, $record, $replyHex] = $argv + [NULL, NULL, NULL, '-'];

@unlink((string) $socket);
$server = stream_socket_server("unix://{$socket}", $errno, $errstr);
if ($server === FALSE) {
	fwrite(STDERR, "listen: {$errstr}\n");
	exit(2);
}
fwrite(STDOUT, "ready\n");

$list = "\xFF\xFF\xFF\xFC";
while (TRUE) {
	$waiting = [$server, STDIN];
	$write = $except = NULL;
	if (stream_select($waiting, $write, $except, 30) < 1 || in_array(STDIN, $waiting, TRUE)) {
		exit(0);
	}
	$conn = @stream_socket_accept($server, 5);
	if ($conn === FALSE) {
		exit(3);
	}

	$got = '';
	$answered = FALSE;
	while (TRUE) {
		$waiting = [$conn, STDIN];
		$write = $except = NULL;
		if (stream_select($waiting, $write, $except, 30) < 1) {
			break;
		}
		if (in_array(STDIN, $waiting, TRUE)) {
			$stdin = fread(STDIN, 8192);
			if ($stdin === FALSE || $stdin === '') {
				break;
			}
		}
		if (!in_array($conn, $waiting, TRUE)) {
			continue;
		}
		$chunk = fread($conn, 8192);
		if ($chunk === FALSE || $chunk === '') {
			break;
		}
		$got .= $chunk;
		if ($got === $list) {
			fwrite($conn, "error: a message of 4294967292 bytes is not between 1 and 65536\n");
			break;
		}
		file_put_contents($record, $got);
		if (!$answered && strlen($got) >= 4 && $replyHex !== '-') {
			fwrite($conn, (string) hex2bin($replyHex));
			$answered = TRUE;
		}
	}
	if ($got !== $list && $got !== '') {
		file_put_contents($record, $got);
	}
	fclose($conn);
}
