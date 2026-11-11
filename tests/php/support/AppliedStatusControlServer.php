<?php

declare(strict_types=1);

[, $socket, $record, $response] = $argv;
$server = stream_socket_server("unix://{$socket}", $errno, $error);
if ($server === FALSE) {
	fwrite(STDERR, $error);
	exit(2);
}
fwrite(STDOUT, "ready\n");
while (TRUE) {
	$read = [$server, STDIN];
	$write = $except = NULL;
	if (stream_select($read, $write, $except, 30) !== 1 || in_array(STDIN, $read, TRUE)) {
		break;
	}
	$conn = stream_socket_accept($server, 5);
	if ($conn === FALSE) {
		exit(3);
	}
	$head = fread($conn, 4);
	file_put_contents($record, bin2hex($head) . "\n", FILE_APPEND);
	$wire = base64_decode($response, TRUE);
	if ($wire !== FALSE) {
		fwrite($conn, $wire);
	}
	fclose($conn);
}
