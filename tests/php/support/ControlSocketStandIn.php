<?php

declare(strict_types=1);

require_once __DIR__ . '/PfbFlockClockFixture.php';

/**
 * What the tests of the gateway's control-socket exchange (pfb_dns_proxy_ctl_exchange()) share: the stand-in gateway of
 * support/ControlSocketServer.php as a real process on a real Unix socket, and the virtual clock the exchange's deadlines count on,
 * so that no test waits. The using test sets $this->dir (a directory it owns) and $this->socket (a path in it) in setUp() and calls
 * finish() in tearDown().
 */
trait ControlSocketStandIn
{
	/** The largest piece the stand-in writes in one go: a bigger single write can block it while PHP waits for its ack. */
	private const RELEASE_PIECE = 16384;

	private string $dir = '';
	private string $socket = '';
	/** @var list<array{resource,array<int,resource>}> */
	private array $servers = [];
	/** @var list<PfbFlockClockFixture> kept for the whole test: a loaded body reaches its clock through a weak reference */
	private array $clocks = [];

	/** A gateway that listens on the control socket and takes one frame; it writes only what the test releases (see support/ControlSocketServer.php). Returns the file its frame is recorded in. */
	private function listen(): string
	{
		@unlink($this->socket);
		$record = "{$this->dir}/frame." . count($this->servers);
		$proc = proc_open([PHP_BINARY, __DIR__ . '/ControlSocketServer.php', $this->socket, $record], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($proc);
		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 15), 'the stand-in gateway did not start listening');
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$proc, $pipes];
		return $record;
	}

	/** Let every stand-in gateway go: its stdin closes, which is all a silent one waits for. */
	private function finish(): void
	{
		foreach ($this->servers as [$proc, $pipes]) {
			@fclose($pipes[0]);
			@fclose($pipes[1]);
			@fclose($pipes[2]);
			proc_close($proc);
		}
		$this->servers = [];
	}

	/**
	 * Loads $functions onto a virtual clock, against the gateway listen() started last. $script is what that gateway writes, in
	 * order: [seconds after the previous write, bytes], or [seconds, NULL] to hang up. Each write is released by the test, so the
	 * clock, not the host, decides when it arrives. The clock lives until tearDown(), which the loaded bodies need.
	 *
	 * @param list<string> $functions
	 * @param list<array{float,?string}> $script
	 * @return array{0: string, 1: PfbFlockClockFixture} the namespace the functions were loaded into, and the clock
	 */
	private function onVirtualClock(array $functions, array $script): array
	{
		$this->assertNotEmpty($this->servers, 'a gateway must be listening before an exchange');
		$pipes = end($this->servers)[1];
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain($functions);
		$clock->setIdle(function (float $wait) use (&$script, $pipes): ?float {
			if ($script === [] || $script[0][0] > $wait) {
				return NULL;
			}
			[$delay, $bytes] = array_shift($script);
			$this->release($pipes, $bytes);

			return $delay;
		});
		$this->clocks[] = $clock;

		return [$namespace, $clock];
	}

	/** The stand-in gateway writes $bytes now (or hangs up, for NULL), and acknowledges once it has: PHP's next poll sees the result. */
	private function release($pipes, ?string $bytes): void
	{
		foreach ($bytes === NULL ? [NULL] : str_split($bytes, self::RELEASE_PIECE) as $piece) {
			fwrite($pipes[0], ($piece === NULL ? 'close' : 'x' . bin2hex($piece)) . "\n");
			fflush($pipes[0]);
			stream_set_timeout($pipes[1], 10);
			$ack = fgets($pipes[1]);
			if ($ack !== "ack\n") {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in gateway did not acknowledge its write: ' . var_export($ack, TRUE));
			}
		}
	}
}
