<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket for the decider-restart request (pfb_dns_proxy_decider_restart()): listens on
 * a Unix socket, takes ONE connection, records every byte the client sends before it hangs up, and answers once, when the 4-byte
 * request is complete, with the bytes the test chose. Prints "ready" once it listens; the record file is absent when nobody connected.
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

$waiting = [$server, STDIN];
$write = $except = NULL;
if (stream_select($waiting, $write, $except, 30) < 1 || !in_array($server, $waiting, TRUE)) {
	exit(3);
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
	file_put_contents($record, $got);
	if (!$answered && strlen($got) >= 4 && $replyHex !== '-') {
		fwrite($conn, (string) hex2bin($replyHex));
		$answered = TRUE;
	}
}
file_put_contents($record, $got);
fclose($conn);
