<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';

/**
 * #3773: an IP Stats view reads a private time-window copy of its log. When that copy cannot be made for a log that
 * exists (full /tmp, unreadable log), the view must not silently read as "No events found": the failure is logged. A
 * valid empty window and an absent log stay quiet. The page's own collector region is evaluated; the failing copy is a
 * unix socket where the log should be (it exists, but cannot be opened, whoever runs the test).
 */
final class IpStatsWindowCopyFailureTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';
	private const SINCE = '2030-01-15 12:00:00';

	/** @var string[] */
	private array $tmpfiles = [];
	/** @var array<string, mixed> */
	private array $saved = [];
	/** @var resource|null */
	private $socket = NULL;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		foreach (['log', 'errlog'] as $key) {
			$this->saved[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : FALSE;
			$GLOBALS['pfb'][$key] = $this->tempFile("pfb_ipwin_{$key}_");
		}
	}

	protected function tearDown(): void
	{
		if (is_resource($this->socket)) {
			fclose($this->socket);
		}
		foreach ($this->saved as $key => $previous) {
			if ($previous === FALSE) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $previous;
			}
		}
		foreach ($this->tmpfiles as $file) {
			if (file_exists($file)) {
				unlink($file);
			}
		}
		$this->tmpfiles = [];
	}

	public function testAWindowCopyThatFailsForAnExistingLogIsLoggedAndTheViewStaysEmpty(): void
	{
		$socket = $this->tempPath('pfb_ipwin_sock_');
		unlink($socket);
		$this->socket = stream_socket_server("unix://{$socket}", $errno, $errstr);
		$this->assertIsResource($this->socket, "could not create the fixture socket: {$errstr}");
		$this->tmpfiles[] = $socket;
		$this->assertFileExists($socket);
		$this->assertFalse(@fopen($socket, 'rb'), 'fixture: the log exists but cannot be opened');

		$stats = $this->collect($socket);

		$this->assertSame(0, $stats['count']['ip_block_stat'], 'the failed copy reads as an empty window, as before');
		$this->assertSame([], $stats['ip_block_stat']['ipfeed']);
		foreach (['log', 'errlog'] as $key) {
			$logged = (string) file_get_contents($GLOBALS['pfb'][$key]);
			$this->assertStringContainsString($socket, $logged, "{$key}: the log path");
			$this->assertStringContainsString('time-window copy', $logged, "{$key}: what failed");
		}
	}

	public function testAValidEmptyWindowAndAnAbsentLogStayQuiet(): void
	{
		$empty = $this->tempFile('pfb_ipwin_empty_');
		file_put_contents($empty, "2030-01-10 08:00:00,old\n"); // a log with nothing in the window
		$stats = $this->collect($empty);
		$this->assertSame(0, $stats['count']['ip_block_stat']);

		$stats = $this->collect($empty . '.absent');
		$this->assertSame(0, $stats['count']['ip_block_stat']);

		foreach (['log', 'errlog'] as $key) {
			$this->assertSame('', (string) file_get_contents($GLOBALS['pfb'][$key]), "{$key}: nothing to report");
		}
	}

	/**
	 * Run the page's own stats collector for the IP Block view over $log in the window starting at SINCE.
	 *
	 * @return array<string, mixed> `$alert_stats`
	 */
	private function collect(string $log): array
	{
		$code = pfb_test_page_region(self::PAGE, '// Collect Alert Statistics', "if (\$stats_data) {\n\t\$stats_payload = [");
		$scope = pfb_test_page_eval($code, [
			'stats_data' => FALSE,
			'alert_summary' => TRUE,
			'alert_view' => 'ip_block_stat',
			'alert_log' => $log,
			'stats_since' => self::SINCE,
			'pfbdnsblstat' => [],
			'pfbdnsblreplystat' => [],
			'pfbblockstat' => [],
			'pfbpermitstat' => [],
			'pfbmatchstat' => [],
			'local_hosts' => [],
			'pfb' => $GLOBALS['pfb'] + ['cut' => 'cut', 'grep' => 'grep', 'sed' => 'sed', 'awk' => 'awk', 'asn_reporting' => 'disabled'],
		]);
		return $scope['alert_stats'];
	}

	private function tempPath(string $prefix): string
	{
		$file = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertIsString($file);
		return $file;
	}

	private function tempFile(string $prefix): string
	{
		$file = $this->tempPath($prefix);
		$this->tmpfiles[] = $file;
		return $file;
	}
}
