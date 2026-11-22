<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The continent-set corpus (#4038, sub-slice 9f) frozen through today's continent block: every case of
 * tests/geoip/fixtures/continents/continent_sets.json runs through the block of sync_package_pfblockerng() that builds the
 * GeoIP continent lists (pfblockerng_apply.inc, from `$maxmind_run_once = TRUE;` to the removal of the temporary file,
 * lines 3471-3661 when frozen). Go's stage 11 (go/pfb_core/update/geosets.go) runs the same cases.
 *
 * The block sits inside a function of several thousand lines, so it is cut out of the source by those two statements and
 * run alone, as GeoipContinentUndefinedBucketTest runs its statement. Only what the block cannot do off the appliance is
 * replaced in the cut source: pfctl's table count (a table that holds entries), the firewall rule writer and the logger
 * (whose lines are captured). Every other call is the package's own.
 *
 * Feature: today's continent block builds each continent's set from the country lists
 *   Scenario Outline: a case's files, rebuilt sets and log lines are what the corpus records as today's (old_expect when
 *     Core departs, else expect)
 */
final class GeoipContinentSetCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../geoip/fixtures/continents/continent_sets.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const CLASSES = ['original', 'deny', 'permit', 'match', 'native'];

	/** @var list<string> */
	public static array $log = [];
	private string $root;
	private array $savedPfb;
	private mixed $savedConfig;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_test_continent_block')) {
			return;
		}
		$source = (string) file_get_contents(self::APPLY);
		$start = strpos($source, "\t\$maxmind_run_once = TRUE;\n");
		$endMarker = "\tunlink_if_exists(\"{\$pfb['geoip_tmp']}\");\n";
		$end = strpos($source, $endMarker, (int) $start);
		self::assertNotFalse($start, 'the continent block start is not in pfblockerng_apply.inc');
		self::assertNotFalse($end, 'the continent block end is not in pfblockerng_apply.inc');
		$block = substr($source, $start, $end + strlen($endMarker) - $start);
		$replaced = 0;
		$block = str_replace(
			['pfb_pfctl_table_count(', 'pfb_firewall_rule(', 'pfb_logger('],
			['GeoipContinentSetCorpusTest::tableCount(', 'GeoipContinentSetCorpusTest::rule(', 'GeoipContinentSetCorpusTest::logger('],
			$block, $replaced);
		self::assertGreaterThanOrEqual(3, $replaced, 'the continent block no longer calls what this test replaces');
		eval('function pfb_test_continent_block(array $cont_types, string $elog): array {'
			. ' global $pfb, $pfbarr;'
			. ' $maxmind_verify = TRUE;'	// the credential notice is not the block's set building
			. ' $new_aliases = $new_aliases_list = $pfb_alias_lists = $pfb_alias_lists_all = [];'
			. $block
			. ' return $pfb_alias_lists; }');
	}

	public static function tableCount(string $table): int
	{
		return 1;
	}

	public static function rule(mixed ...$args): void
	{
	}

	public static function logger(mixed $log, mixed $type): void
	{
		foreach (explode("\n", (string) $log) as $line) {
			if (str_starts_with($line, 'Could not open ISO')) {
				self::$log[] = $line;
			}
		}
	}

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_continent_sets_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700, TRUE));
		$this->savedPfb = $GLOBALS['pfb'];
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		self::$log = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		$GLOBALS['config'] = $this->savedConfig;
		rmdir_recursive($this->root);
	}

	/** @return iterable<string, array{array}> */
	public static function cases(): iterable
	{
		$corpus = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
		foreach ($corpus['cases'] as $case) {
			yield $case['id'] => [$case];
		}
	}

	#[DataProvider('cases')]
	public function testTodaysContinentBlockBuildsTheRecordedSets(array $case): void
	{
		$db = "{$this->root}/db";
		$cc = "{$this->root}/cc";
		foreach (array_merge(array_map(static fn (string $class): string => "db/{$class}", self::CLASSES), ['cc', 'aliastables', 'snapshots']) as $dir) {
			$this->assertTrue(mkdir("{$this->root}/{$dir}", 0700, TRUE));
		}
		foreach ($case['cc'] as $name => $content) {
			file_put_contents("{$cc}/{$name}", $content);
		}
		foreach ($case['before'] ?? [] as $path => $content) {
			file_put_contents("{$db}/{$path}", $content);
		}
		if (!empty($case['geoipChanged'])) {
			touch("{$db}/geoip.update");
		}

		$sections = array_flip(array_map(
			static fn (string $continent): string => 'pfblockerng' . strtolower(str_replace(' ', '', $continent)),
			array_keys($GLOBALS['pfb']['continents'])));
		$aliases = array_combine(array_values($GLOBALS['pfb']['continents']), array_keys($sections));
		$installed = [];
		foreach ($case['groups'] as $group) {
			$installed[$aliases[$group['name']]] = ['config' => [[
				'action' => $group['action'],
				'countries4' => implode(',', $group['countriesV4']),
				'countries6' => implode(',', $group['countriesV6']),
				'aliaslog' => '',
			]]];
		}
		$GLOBALS['config'] = ['installedpackages' => $installed];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], [
			'enable' => ($case['enabled'] ?? TRUE) ? PfbToggle::On : PfbToggle::Off,
			'save' => FALSE,
			'reuse' => !empty($case['force']) ? 'on' : '',
			'agg' => PfbToggle::Off,
			'ip_ph' => '127.1.7.7',
			'dbdir' => $db,
			'ccdir' => $cc,
			'geoip_tmp' => "{$this->root}/pfb_continent",
			'origdir' => "{$db}/original",
			'denydir' => "{$db}/deny",
			'permitdir' => "{$db}/permit",
			'matchdir' => "{$db}/match",
			'nativedir' => "{$db}/native",
			'aliasdir' => "{$this->root}/aliastables",
			'snapdir' => "{$this->root}/snapshots",
			'grep' => '/usr/bin/grep',
			'weblocal' => '/pfblockerng/pfblockerng.php',
			'maxmind_key' => '',
			'maxmind_account' => '',
		]);

		$changed = pfb_test_continent_block(['countries4' => '_v4', 'countries6' => '_v6'], "{$this->root}/error.log");

		$want = $case['old_expect'] ?? $case['expect'];
		$files = $want['files'];
		ksort($files);
		$this->assertSame($files, $this->files($db), "{$case['id']}: the files of the list folders");
		$this->assertSame($want['changed'], $changed, "{$case['id']}: the sets rebuilt");
		$this->assertSame($want['log'], self::$log, "{$case['id']}: the lines logged");
		$this->assertFileDoesNotExist("{$this->root}/pfb_continent", "{$case['id']}: the temporary set outlives the block");
	}

	/**
	 * @return array<string, string> every set file under the list folders (a baseline .orig, a list .txt), by path relative
	 *   to $db, sorted by path. The Reputation snapshot and its aggcount are the cross-feed recompute's (#4038, 9h), and the
	 *   ADR-40 mirror in the alias folder is the Outpost apply's.
	 */
	private function files(string $db): array
	{
		$files = [];
		foreach (self::CLASSES as $class) {
			foreach (scandir("{$db}/{$class}") ?: [] as $name) {
				if (preg_match('/\.(?:orig|txt)\z/', $name) === 1) {
					$files["{$class}/{$name}"] = (string) file_get_contents("{$db}/{$class}/{$name}");
				}
			}
		}
		ksort($files);
		return $files;
	}
}
