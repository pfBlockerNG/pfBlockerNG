<?php

declare(strict_types=1);

/**
 * What the tests of the live listen-address verbs and of the listener list share (docs/specs/pfb-dns-live-listen-addresses.md): the
 * stand-in gateway of support/ListenerControlServer.php as a real process on a real Unix socket, the frames it recorded, the listeners
 * it serves and refuses (what `list` answers), and ports that are free to bind.
 */
trait LiveListenerStandIn
{
	/** @var list<array{resource,array<int,resource>}> */
	private array $standIns = [];
	/** @var list<resource|Socket> sockets a test holds so that a bind of their address fails */
	private array $held = [];

	/**
	 * A gateway that takes frames on $socket until $this->standInsStop(), and replies per $replies and $served (see ListenerControlServer.php).
	 *
	 * @param list<string|null> $replies
	 * @param array{listening?:list<string>,refused?:array<string,string>,list?:string|null} $served what `list` answers: `<kind> <host:port>`
	 *        entries, refusals with their reasons, and optionally the whole reply (a string) or a hang-up (null); [] = serves nothing
	 * @return string the file its frames are recorded in; it does not exist until the first frame
	 */
	private function standIn(string $socket, array $replies = [], array $served = []): string
	{
		@unlink($socket);
		$record = $socket . '.frames.' . count($this->standIns);
		$proc = proc_open(
			[PHP_BINARY, __DIR__ . '/ListenerControlServer.php', $socket, $record, json_encode($replies, JSON_THROW_ON_ERROR), json_encode($served, JSON_THROW_ON_ERROR)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($proc);
		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 15), 'the stand-in gateway did not start listening');
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->standIns[] = [$proc, $pipes];
		return $record;
	}

	/** Let every stand-in gateway go (its stdin closes), and free what the test held. */
	private function standInsStop(): void
	{
		foreach ($this->standIns as [$proc, $pipes]) {
			@fclose($pipes[0]);
			@fclose($pipes[1]);
			@fclose($pipes[2]);
			proc_close($proc);
		}
		$this->standIns = [];
		foreach ($this->held as $socket) {
			if (is_resource($socket)) {
				fclose($socket);
			}
		}
		$this->held = [];
	}

	/**
	 * The gateway as pfb_dns_proxy_listener_list() sees it: a stand-in on $GLOBALS['pfb']['dns_proxy_ctl'] that serves $listening and
	 * refuses $refused. The one a test started before is stopped first; no gateway at all is standInsStop().
	 *
	 * @param list<string> $listening `<kind> <host:port>`
	 * @param array<string,string> $refused `<kind> <host:port>` => reason
	 */
	private function gatewayServes(array $listening, array $refused = []): void
	{
		$this->standInsStop();
		$this->standIn($GLOBALS['pfb']['dns_proxy_ctl'], [], ['listening' => $listening, 'refused' => $refused]);
	}

	/** A gateway that answers a list request with exactly $reply (NULL: it hangs up), as gatewayServes() starts it. */
	private function gatewayAnswers(?string $reply): void
	{
		$this->standInsStop();
		$this->standIn($GLOBALS['pfb']['dns_proxy_ctl'], [], ['list' => $reply]);
	}

	/** @return list<array{head:string,body:string,fds:list<array{type:string,name:string,listening:bool}>}> the frames the stand-in got, in order */
	private static function frames(string $record): array
	{
		$lines = (is_file($record)) ? (array) file($record, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
		return array_map(static fn (string $line): array => json_decode($line, TRUE, 8, JSON_THROW_ON_ERROR), $lines);
	}

	/**
	 * Distinct ports above 1024 that a TCP and a UDP socket on loopback both bind now (a CI user that is not root binds them too).
	 *
	 * @return list<int>
	 */
	private static function freePorts(int $count): array
	{
		$ports = $open = [];
		for ($try = 0; count($ports) < $count && $try < 200; $try++) {
			$tcp = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
			if ($tcp === FALSE) {
				continue;
			}
			$name = (string) stream_socket_get_name($tcp, FALSE);
			$port = (int) substr($name, (int) strrpos($name, ':') + 1);
			$udp = @stream_socket_server("udp://127.0.0.1:{$port}", $errno, $errstr, STREAM_SERVER_BIND);
			if ($port > 1024 && $udp !== FALSE) {
				array_push($open, $tcp, $udp);
				$ports[] = $port;
			} else {
				fclose($tcp);
			}
		}
		foreach ($open as $socket) {
			fclose($socket);
		}
		if (count($ports) !== $count) {
			throw new RuntimeException('no free port');
		}
		return $ports;
	}

	private static function freePort(): int
	{
		return self::freePorts(1)[0];
	}

	/** Whether this host takes a TCP and a UDP bind on $at ("host:port") now; the sockets are closed at once. */
	private static function binds(string $at): bool
	{
		$tcp = @stream_socket_server("tcp://{$at}", $errno, $errstr);
		if ($tcp === FALSE) {
			return FALSE;
		}
		fclose($tcp);
		$udp = @stream_socket_server("udp://{$at}", $errno, $errstr, STREAM_SERVER_BIND);
		if ($udp === FALSE) {
			return FALSE;
		}
		fclose($udp);
		return TRUE;
	}

	/** Hold the TCP port of $at, so that a bind of it fails with `address in use` until standInsStop(). */
	private function hold(string $at): void
	{
		$socket = @stream_socket_server("tcp://{$at}", $errno, $errstr);
		$this->assertNotFalse($socket, "the test could not take {$at}: {$errstr}");
		$this->held[] = $socket;
	}

	/** Hold the UDP port of $host: unlike PHP's own binds this socket does not allow the address to be shared, so a UDP bind of it fails. */
	private function holdUdp(string $host, int $port): void
	{
		$socket = socket_create(str_contains($host, ':') ? AF_INET6 : AF_INET, SOCK_DGRAM, SOL_UDP);
		$this->assertTrue(@socket_bind($socket, trim($host, '[]'), $port), "the test could not take udp {$host}:{$port}");
		$this->held[] = $socket;
	}

	/** Why a TCP bind of $at ("host:port") fails now, as PHP words it; '' when it binds. */
	private static function bindError(string $at): string
	{
		$socket = @stream_socket_server("tcp://{$at}", $errno, $errstr);
		if ($socket !== FALSE) {
			fclose($socket);
			return '';
		}
		return $errstr;
	}

	/** How many descriptors this process holds (Linux). */
	private static function openDescriptors(): int
	{
		return count((array) scandir('/proc/self/fd')) - 2;
	}
}
