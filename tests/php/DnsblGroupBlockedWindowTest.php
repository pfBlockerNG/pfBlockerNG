<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';

/**
 * #3773: DNSBL Block Stats "Top Blocked Group" must follow the shared time range. Its SQLite source (dnsbl.counter) is
 * cumulative, so a bounded window counts the group column of the windowed dnsbl.log instead; All time keeps the counter.
 * "Top Group Count" (list sizes) is not time based and stays SQLite. The page's own collector region is evaluated against
 * a real dnsbl.log and a real SQLite dnsbl table.
 */
final class DnsblGroupBlockedWindowTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';
	private const SINCE = '2030-01-15 12:00:00';
	private const LOG_STATS = [
		'dnsblwebtype', 'dnsbldate', 'dnsblchart', 'dnsbldatehr', 'dnsbldatehrmin', 'dnsbldomain', 'dnsbltld', 'dnsblip',
		'dnsblagent', 'dnsblmode', 'dnsblevald', 'dnsblfeed',
	];

	/** @var string[] */
	private array $tmpfiles = [];
	/** @var array<string, mixed> */
	private array $saved = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		foreach (['dnsbl_info', 'sqlite_timeout', 'errlog'] as $key) {
			$this->saved[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : FALSE;
		}
		$GLOBALS['pfb']['dnsbl_info'] = $this->tempFile('pfb_gp_sqlite_');
		$GLOBALS['pfb']['sqlite_timeout'] = 2000;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_gp_errlog_');
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER )');
		// GroupOld blocked a lot, but only before the window; GroupOff is disabled in the lists.
		foreach ([['GroupOld', 10, 500], ['GroupNew', 20, 40], ['GroupOff', 'disabled', 9]] as [$name, $entries, $counter]) {
			$statement = $db->prepare('INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES (:g, :t, :e, :c)');
			$statement->bindValue(':g', $name);
			$statement->bindValue(':t', '2030-01-01 00:00:00');
			$statement->bindValue(':e', $entries);
			$statement->bindValue(':c', $counter, SQLITE3_INTEGER);
			$statement->execute();
		}
		$db->close();
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $key => $previous) {
			if ($previous === FALSE) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $previous;
			}
		}
		foreach ($this->tmpfiles as $file) {
			foreach ([$file, "{$file}-wal", "{$file}-shm"] as $path) {
				if (is_file($path)) {
					unlink($path);
				}
			}
		}
		$this->tmpfiles = [];
	}

	public function testABoundedWindowCountsTheBlocksInsideIt(): void
	{
		$stats = $this->collect(self::SINCE, []);
		$this->assertSame(
			['GroupOff&emsp;(Disabled)' => 5, 'GroupNew' => 2, 'GroupDeleted' => 1],
			$stats['dnsbl_stat']['dnsblgpblock'],
			'GroupOld (old blocks only) must be absent; a group with no entry in SQLite still counts; rows without a group do not'
		);
		$this->assertSame(
			['GroupNew' => 20, 'GroupOld' => 10, 'GroupOff&emsp;(Disabled)' => 0],
			$stats['dnsbl_stat']['dnsblgptotal'],
			'list sizes are not time based'
		);
		$this->assertSame(9, $stats['count']['dnsbl_stat'], 'the total counts the window\'s rows, whether or not the group panel is on');
	}

	public function testAllTimeKeepsTheCumulativeSqliteCounters(): void
	{
		$stats = $this->collect(NULL, []);
		$this->assertSame(
			['GroupOld' => 500, 'GroupNew' => 40, 'GroupOff&emsp;(Disabled)' => 9],
			$stats['dnsbl_stat']['dnsblgpblock']
		);
		$this->assertSame(['GroupNew' => 20, 'GroupOld' => 10, 'GroupOff&emsp;(Disabled)' => 0], $stats['dnsbl_stat']['dnsblgptotal']);
	}

	public function testAHiddenGroupPanelIsNotScannedForTheWindow(): void
	{
		$stats = $this->collect(self::SINCE, ['dnsblgpblock']);
		$this->assertSame(
			['GroupOld' => 500, 'GroupNew' => 40, 'GroupOff&emsp;(Disabled)' => 9],
			$stats['dnsbl_stat']['dnsblgpblock'],
			'a hidden panel is never rendered and must not make the collector scan the log for it'
		);
	}

	public function testTheGroupPanelAloneCountsTheWindowButNeverInventsATotal(): void
	{
		$stats = $this->collect(self::SINCE, self::LOG_STATS);
		$this->assertSame(
			['GroupOff&emsp;(Disabled)' => 5, 'GroupNew' => 2, 'GroupDeleted' => 1],
			$stats['dnsbl_stat']['dnsblgpblock']
		);
		$this->assertArrayNotHasKey('count', $stats, 'every log category is hidden: the total stays uncomputed (null), as before');
	}

	/**
	 * Run the page's own stats collector (through the widget statistics) over a seeded dnsbl.log.
	 *
	 * @param string[] $hidden stat ids hidden by the Reports preference
	 * @return array<string, mixed> `$alert_stats`
	 */
	private function collect(?string $since, array $hidden): array
	{
		$line = static fn (string $date, string $group): string => "DNSBL-python,{$date},blocked.example,192.0.2.1,Python,DNSBL,{$group},blocked.example,Feed,+,A\n";
		$log = $this->tempFile('pfb_gp_dnsbl_');
		file_put_contents(
			$log,
			str_repeat($line('2030-01-10 08:00:00', 'GroupOld'), 3) . $line('2030-01-10 09:00:00', 'GroupNew') // before the window
			. str_repeat($line('2030-01-16 08:00:00', 'GroupOff'), 5) . str_repeat($line('2030-01-16 09:00:00', 'GroupNew'), 2)
			. $line('2030-01-16 10:00:00', 'GroupDeleted') . $line('2030-01-16 11:00:00', '')
		);
		$code = pfb_test_page_region(self::PAGE, '// Collect Alert Statistics', "if (\$stats_data) {\n\t\$stats_payload = [");
		$scope = pfb_test_page_eval($code, [
			'stats_data' => TRUE,
			'alert_summary' => TRUE,
			'alert_view' => 'dnsbl_stat',
			'alert_log' => $log,
			'stats_since' => $since,
			'pfbdnsblstat' => $hidden,
			'pfbdnsblreplystat' => [],
			'pfbblockstat' => [],
			'pfbpermitstat' => [],
			'pfbmatchstat' => [],
			'local_hosts' => [],
			'pfb' => $GLOBALS['pfb'] + ['cut' => 'cut', 'grep' => 'grep', 'sed' => 'sed', 'awk' => 'awk'],
		]);
		$stats = $scope['alert_stats'];
		foreach (['dnsblgptotal', 'dnsblgpblock'] as $id) {
			// SQLite counts arrive as numeric strings (pfb_filter NUM); the panels treat them as numbers.
			$stats['dnsbl_stat'][$id] = array_map('intval', $stats['dnsbl_stat'][$id]);
		}
		return $stats;
	}

	private function tempFile(string $prefix): string
	{
		$file = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertIsString($file);
		$this->tmpfiles[] = $file;
		return $file;
	}
}
