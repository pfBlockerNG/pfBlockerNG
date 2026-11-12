<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3879: the built-in Upstream group is enabled in the DNSBL statistics (the widget's row) whenever the Update
 * runs with upstream-block detection active, and disabled otherwise. pfb_unbound.py detects upstream blocks while the
 * Resolver forwards, in both pfB-DNS modes: hosted by the DNS proxy (pfB-DNS on, Unbound runs the observer) or by
 * Unbound itself (pfB-DNS off). So an Update with forwarding on must leave the row enabled and one with forwarding off
 * must mark it disabled, with pfB-DNS on or off.
 *
 * The Update's built-in-group region is eval-extracted verbatim from the REAL pfblockerng_apply.inc (house precedent:
 * tests/php/DnsblAbpRegexIp4CidrsTest.php) and followed by the real dnsbl_save_stats(), so the rows pin the wiring
 * by behaviour, not by naming the code.
 */
#[CoversFunction('dnsbl_save_stats')]
final class DnsblUpstreamGroupStateTest extends TestCase
{
	private const START = "\t\t// Add DNSBL Python options to widget statistics.";
	private const END = "\n\t}\n\n\t// Collect all DNSBL IP feeds";

	private static string $builtinRegion;

	private string $root;
	private array $priorPfb;
	private array $priorConfig;

	public static function setUpBeforeClass(): void
	{
		$src = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$start = strpos($src, self::START);
		$end = $start === FALSE ? FALSE : strpos($src, self::END, $start);
		if ($start === FALSE || $end === FALSE) {
			throw new RuntimeException('test bootstrap: the Update\'s built-in DNSBL group region was not found');
		}
		self::$builtinRegion = substr($src, $start, $end - $start);
	}

	protected function setUp(): void
	{
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [];
		$this->root = sys_get_temp_dir() . '/pfb_dnsbl_upstream_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700));
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], [
			'dnsbl_info' => "{$this->root}/dnsbl.sqlite",
			'log' => "{$this->root}/pfblockerng.log",
			'errlog' => "{$this->root}/error.log",
			'metrics_lock' => "{$this->root}/metrics.lock",
			'sqlite_timeout' => 2000,
			// Only the Upstream built-in is under test: every other built-in feature is off.
			'dnsbl_idn' => PfbIdnMode::Off,
			'dnsbl_tld_allow' => PfbToggle::Off,
			'dnsbl_regex' => PfbToggle::Off,
			'unbound_py_regex_count' => "{$this->root}/pfb_py_regex_count",
			'alias_dnsbl_configured' => ['DNSBL_A'],
			'alias_dnsbl_all' => ['DNSBL_A'],
		]);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->priorPfb;
		$GLOBALS['config'] = $this->priorConfig;
		rmdir_recursive($this->root);
	}

	/** Seed the statistics table as the gateway and an earlier Update left it, with the Upstream row in $upstreamEntries. */
	private function seed(string $upstreamEntries): void
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		try {
			$this->assertTrue($db->exec('CREATE TABLE dnsbl (groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER)'));
			$stmt = $db->prepare("INSERT INTO dnsbl VALUES ('DNSBL_A', 'old', 5, 1), ('Upstream', 'old', :entries, 4)");
			$stmt->bindValue(':entries', $upstreamEntries, SQLITE3_TEXT);
			$this->assertNotFalse($stmt->execute(), $db->lastErrorMsg());
		} finally {
			$db->close();
		}
	}

	private function upstream(string $column): mixed
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info'], SQLITE3_OPEN_READONLY);
		try {
			return $db->querySingle("SELECT {$column} FROM dnsbl WHERE groupname = 'Upstream'");
		} finally {
			$db->close();
		}
	}

	/** One Update over the seeded database: load the statistics as the Update does, run its built-in region, save. */
	private function update(): void
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info'], SQLITE3_OPEN_READONLY);
		try {
			$GLOBALS['pfb']['dnsbl_info_stats'] = [];
			$result = $db->query('SELECT * FROM dnsbl;');
			while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
				$GLOBALS['pfb']['dnsbl_info_stats'][] = $row;
			}
		} finally {
			$db->close();
		}
		(static function (string $region): void {
			global $pfb;
			eval($region);
		})(self::$builtinRegion);
		$this->assertTrue(dnsbl_save_stats(), 'the statistics save succeeds');
	}

	/** @return array<string, array{0: PfbToggle}> */
	public static function pfbDnsModes(): array
	{
		return ['pfB-DNS on (the DNS proxy hosts the module)' => [PfbToggle::On], 'pfB-DNS off (Unbound hosts the module)' => [PfbToggle::Off]];
	}

	#[DataProvider('pfbDnsModes')]
	public function testAnUpdateWithTheResolverForwardingEnablesTheUpstreamRow(PfbToggle $pfbDns): void
	{
		// Given a row an earlier Update marked disabled, and the Resolver forwarding (upstream-block detection active)
		$GLOBALS['pfb']['pfb_dns'] = $pfbDns;
		$this->seed('disabled');
		$this->assertSame('disabled', $this->upstream('entries'), 'before: the Upstream row is disabled');
		config_set_path('unbound/forwarding', '');

		// When the Update runs
		$this->update();

		// Then the Upstream row is enabled and keeps its block counter
		$this->assertSame(0, $this->upstream('entries'), 'with forwarding on the Upstream row is enabled');
		$this->assertSame(4, $this->upstream('counter'), 'the Upstream block counter is kept');
	}

	#[DataProvider('pfbDnsModes')]
	public function testAnUpdateWithoutForwardingDisablesTheUpstreamRow(PfbToggle $pfbDns): void
	{
		// Given an enabled row, and the Resolver resolving itself (no upstream to detect blocks from)
		$GLOBALS['pfb']['pfb_dns'] = $pfbDns;
		$this->seed('0');
		$this->assertSame(0, $this->upstream('entries'), 'before: the Upstream row is enabled');

		// When the Update runs
		$this->update();

		// Then the Upstream row is disabled and keeps its block counter
		$this->assertSame('disabled', $this->upstream('entries'), 'with forwarding off the Upstream row is disabled');
		$this->assertSame(4, $this->upstream('counter'), 'the Upstream block counter is kept');
	}
}
