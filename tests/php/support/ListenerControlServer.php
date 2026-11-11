<?php

declare(strict_types=1);

/**
 * A stand-in for the pfB-DNS gateway's control socket (go/pfb_dns_gateway, ctl.go), for the tests of the live listen-address verbs
 * and of everything that asks which listeners the gateway serves (docs/specs/pfb-dns-live-listen-addresses.md, D2): listens on a Unix
 * socket and takes connections until the test ends it. Each connection is one frame: four head bytes (FF FF FF FE add, FF FF FF FD
 * remove, FF FF FF FC list, FF FF FF FA status), and for add and remove a 4-byte big-endian length and that many bytes `<kind> <host:port>`,
 * sent in ONE sendmsg(2) with its SCM_RIGHTS descriptors; list and status frames are the four head bytes alone.
 * Each connection records one JSON line {"head": hex, "body": text, "fds": [{"type": "stream"|"dgram", "name": "host:port", "listening": bool}]} in <record file> BEFORE it
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
 * Status (FF FF FF FA) uses the version-1 snapshot in <socket>.status when present, else the served `status` key; live listener and
 * accepted address-table state is overlaid on that applied seed. `list` answers status too (a gateway that gives no list gives no
 * status). `status_later` answers every status request after the first, so a gateway can serve readiness and then not its inventory.
 * `status_wire` overrides the wire for unavailable/malformed-response tests.
 */
[, $socket, $record, $script, $servedJson] = $argv + [NULL, NULL, NULL, '[]', '{}'];
$replies = json_decode((string) $script, TRUE, 4, JSON_THROW_ON_ERROR);
$served = json_decode((string) $servedJson, TRUE, 16, JSON_THROW_ON_ERROR) + ['listening' => [], 'refused' => []];
$answers = NULL;
$statusAnswers = 0;

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
	socket_set_option($conn, SOL_SOCKET, SO_SNDTIMEO, ['sec' => 5, 'usec' => 0]);
	socket_set_option($conn, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
	$message = ['name' => [], 'buffer_size' => 264, 'controllen' => socket_cmsg_space(SOL_SOCKET, SCM_RIGHTS, 4)];
	$got = @socket_recvmsg($conn, $message, 0);
	$data = ($got === FALSE) ? '' : (string) $message['iov'][0];
	$head = bin2hex(substr($data, 0, 4));
	$length = (strlen($data) >= 8) ? unpack('N', substr($data, 4, 4))[1] : 0;
	// A list frame is its four head bytes alone: waiting for a length would cost the whole receive timeout
	$want = in_array($head, ['fffffffc', 'fffffffa'], TRUE) ? 4 : 8 + min($length, ($head === 'fffffffb') ? 65536 : 256);
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

	if ($head === 'fffffffa' && array_key_exists('list', $served)) {
		// A gateway that gives no list gives no applied status either: the same answer, byte for byte
		$wire = $served['list'];
	} elseif ($head === 'fffffffa' && $statusAnswers++ > 0 && array_key_exists('status_later', $served)) {
		// The first status answer serves the readiness check; a gateway that cannot yet answer its inventory says so from then on
		$wire = $served['status_later'];
	} elseif ($head === 'fffffffa') {
		$statusFile = $socket . '.status';
		$status = is_file($statusFile) ? json_decode(file_get_contents($statusFile), TRUE, 32, JSON_THROW_ON_ERROR) : ($served['status'] ?? NULL);
		if (is_array($status)) {
			$status['listeners'] = [];
			foreach ($served['listening'] as $key) {
				[$kind, $address] = explode(' ', $key, 2);
				$status['listeners'][] = ['kind' => $kind, 'address' => $address, 'state' => 'listening', 'reason' => ''];
			}
			foreach ($served['refused'] as $key => $reason) {
				[$kind, $address] = explode(' ', $key, 2);
				$status['listeners'][] = ['kind' => $kind, 'address' => $address, 'state' => 'refused', 'reason' => $reason];
			}
			usort($status['listeners'], static fn (array $a, array $b): int => [$a['kind'], $a['address']] <=> [$b['kind'], $b['address']]);
			if ($answers !== NULL) {
				$status['name_answers'] = $answers;
			}
			$advertisements = (array) $status['advertisements'];
			$locals = array_keys((array) $status['name_answers']);
			foreach ($status['listeners'] as $listener) {
				if ($listener['state'] === 'listening') {
					$locals[] = trim(substr($listener['address'], 0, strrpos($listener['address'], ':')), '[]');
				}
			}
			$status['advertisements'] = (object) array_intersect_key($advertisements, array_flip($locals));
			foreach (array_unique($locals) as $local) {
				$status['advertisements']->{$local} ??= ['records' => [], 'additional' => []];
			}
			$status['name_answers'] = (object) $status['name_answers'];
		}
		$wire = array_key_exists('status_wire', $served) ? $served['status_wire'] : json_encode($status, JSON_THROW_ON_ERROR) . "\nok\n";
		if (!array_key_exists('status_wire', $served) && strlen($wire) > 65536) {
			$wire = "error: status exceeds response limit\n";
		}
	} elseif ($head === 'fffffffc') {
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
		if ($reply === 'ok' && $head === 'fffffffb') {
			$answers = [];
			foreach (explode("\n", $body) as $line) {
				if (!str_starts_with($line, 'dns-name-answer ')) {
					continue;
				}
				[$local, $values] = explode('=', substr($line, 16), 2);
				$answers[$local] = ['a' => [], 'aaaa' => []];
				foreach (array_filter(explode(',', $values), 'strlen') as $value) {
					$answers[$local][str_contains($value, ':') ? 'aaaa' : 'a'][] = $value;
				}
			}
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
