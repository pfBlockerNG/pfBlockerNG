<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: Core reads the IP policy, the GeoIP continents, the Extras credentials, the SafeSearch settings and the hook rows
 * through its settings adapter, so every page save of them tells Core (SettingsChanged, forced: no GetSettings first, no
 * parameters) after a successful write_config() only, and Core's revision moves at once. A failed write tells Core nothing; a Core
 * that does not answer never undoes the save and leaves the failure for DNS General to show. The writers: the IP page, the
 * generated GeoIP continent pages and Reputation page (their templates in pfblockerng_geoip.inc), the SafeSearch page and the
 * Hooks page. Each case runs the page's own statements, from its last in-memory write through the notice, over the doubles, against
 * a Core stand-in (support/CoreSettingsStandIn.php) that records every request it gets.
 */
final class CoreSettingsPolicyPageSavesTest extends TestCase
{
	private const IP = 'src/usr/local/www/pfblockerng/pfblockerng_ip.php';
	private const GEOIP = 'src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc';
	private const SAFESEARCH = 'src/usr/local/www/pfblockerng/pfblockerng_safesearch.php';
	private const HOOKS = 'src/usr/local/www/pfblockerng/pfblockerng_hooks.php';
	private const ROW = ['script' => 'hook_pre_a.sh', 'when' => 'pre', 'enabled' => 'on', 'description' => '', 'timeout' => ''];

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} the running stand-in */
	private ?array $standIn = NULL;
	private array $priorConfig;
	private array $priorPfb;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_policy_pages_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/api.sock";
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->standIn !== NULL) {
			[$process, $pipes] = $this->standIn;
			proc_terminate($process);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_write_config_args'],
			$GLOBALS['pfb_test_write_config_hook']);
		rmdir_recursive($this->dir);
	}

	/** Start a Core stand-in that takes the notice, on the sandbox's socket; returns once it listens. */
	private function core(): void
	{
		$script = ['SettingsChanged' => [200, ['initialized' => TRUE, 'revision' => 4, 'projections' => []]]];
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', "{$this->dir}/api.sock", "{$this->dir}/requests", json_encode($script, JSON_THROW_ON_ERROR)]);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		for ($out = ''; !str_contains($out, 'ready'); usleep(1000)) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
		}
	}

	/** @return list<array{method: string, body: array}> every request the stand-in got, in order */
	private function requests(): array
	{
		$lines = @file("{$this->dir}/requests", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return array_map(static fn(string $line): array => json_decode($line, TRUE, 512, JSON_THROW_ON_ERROR), $lines);
	}

	/**
	 * Every page save of a setting the new projections read: the page, its statements from the last in-memory write to just before
	 * the redirect, the variables the page has set there (a `pfb.` key is a member of the page's $pfb), and the write_config()
	 * description.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: array<string, mixed>, 4: string}>
	 */
	public static function writers(): array
	{
		return [
			'the IP page saves' => [self::IP,
				"PfbConfig::writeSection('installedpackages/pfblockerngipsettings/config/0', \$pfb['iconfig']);", 'if (!empty($savemsg)) {',
				['pfb.iconfig' => ['enable_dup' => 'on', 'maxmind_locale' => 'de']], '[pfBlockerNG] save IP settings'],
			'a GeoIP continent page saves' => [self::GEOIP,
				'config_set_path("installedpackages/{$conf_type}/config/0", $pfb[\'geoipconfig\']);', 'header("Location: /pfblockerng/pfblockerng_{$continent_en}.php");',
				['conf_type' => 'pfblockerngafrica', 'continent_display' => 'Africa', 'pfb.geoipconfig' => ['action' => 'Deny_Both', 'countries4' => 'ZA']],
				'[pfBlockerNG] save GeoIP [ Africa ] settings'],
			'the Reputation page saves' => [self::GEOIP,
				"PfbConfig::writeSection('installedpackages/pfblockerngreputation/config/0', \$pfb['repconfig']);", "header('Location: /pfblockerng/pfblockerng_reputation.php');",
				['pfb.repconfig' => ['enable_rep' => 'on', 'p24_max_var' => '5']], '[pfBlockerNG] save Reputation settings'],
			'the SafeSearch page saves' => [self::SAFESEARCH,
				"PfbConfig::writeSection('installedpackages/pfblockerngsafesearch', \$pfb['bconfig']);", "\$savemsg = 'Changes saved.",
				['pfb.bconfig' => ['safesearch_enable' => 'Enable', 'safesearch_youtube' => 'Strict']], '[ pfBlockerNG ] Saved SafeSearch configuration'],
			'the Hooks page saves its rows' => [self::HOOKS,
				'if (empty($hooks)) {', "header('Location: /pfblockerng/pfblockerng_hooks.php');",
				['hooks' => [self::ROW]], '[pfBlockerNG] save Update Hooks settings'],
			'the Hooks page deletes its last row' => [self::HOOKS,
				'if (empty($hooks)) {', "header('Location: /pfblockerng/pfblockerng_hooks.php');",
				['hooks' => [], 'stored.hooks' => TRUE], '[pfBlockerNG] save Update Hooks settings'],
		];
	}

	/** Run the page's statements between $start and $end with $vars in scope (and the page's $pfb). */
	private function runPage(string $page, string $start, string $end, array $vars): void
	{
		$pfb = $GLOBALS['pfb'];
		foreach ($vars as $name => $value) {
			if (str_starts_with($name, 'pfb.')) {
				$pfb[substr($name, 4)] = $value;
				unset($vars[$name]);
			}
		}
		unset($vars['stored.hooks']);
		ob_start();
		try {
			pfb_test_page_eval(pfb_test_page_region($page, $start, $end), $vars + ['pfb' => $pfb, 'savemsg' => '']);
		} finally {
			ob_end_clean();
		}
	}

	/** What config.xml holds before the save: nothing, or the one hook row the "last row" case deletes. */
	private function arrange(array $vars): void
	{
		if (isset($vars['stored.hooks'])) {
			config_set_path('installedpackages/pfblockerng/config/0/hooks/row', [self::ROW]);
		}
	}

	/** @param array<string, mixed> $vars */
	#[DataProvider('writers')]
	public function testASuccessfulSaveTellsCoreOnceAfterTheWriteAndTheRevisionMoves(string $page, string $start, string $end, array $vars, string $message): void
	{
		$this->arrange($vars);
		$this->core();
		$before = pfb_core_settings_revision(pfb_core_settings(static fn(): array => []));
		$toldBeforeTheWrite = NULL;
		$GLOBALS['pfb_test_write_config_hook'] = function () use (&$toldBeforeTheWrite): void {
			$toldBeforeTheWrite = $this->requests();
		};

		$this->runPage($page, $start, $end, $vars);

		$this->assertSame([$message], $GLOBALS['pfb_test_write_config_calls'], 'the page wrote config.xml');
		$this->assertSame([], $toldBeforeTheWrite, 'Core hears nothing before config.xml is written');
		$this->assertSame([['method' => 'SettingsChanged', 'body' => []]], $this->requests(), 'forced: Core is told once, with nothing but the notice');
		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
		$this->assertNotSame($before, pfb_core_settings_revision(pfb_core_settings(static fn(): array => [])), 'the revision config.xml projects moved with the save');
	}

	/** @return array<string, array{0: string, 1: string, 2: string, 3: array<string, mixed>, 4: string, 5: bool|int}> */
	public static function failedWrites(): array
	{
		$cases = [];
		foreach (self::writers() as $name => $writer) {
			$cases["{$name}: write refused"] = [...$writer, FALSE];
			$cases["{$name}: file write failed"] = [...$writer, -1];
		}
		return $cases;
	}

	/** @param array<string, mixed> $vars */
	#[DataProvider('failedWrites')]
	public function testAFailedWriteTellsCoreNothing(string $page, string $start, string $end, array $vars, string $message, bool|int $result): void
	{
		$this->arrange($vars);
		$this->core();
		$GLOBALS['pfb_test_write_config_result'] = $result;

		$this->runPage($page, $start, $end, $vars);

		$this->assertSame([$message], $GLOBALS['pfb_test_write_config_calls'], 'the page tried to write config.xml');
		$this->assertSame([], $this->requests(), 'config.xml did not change: Core is not told');
	}

	/** @param array<string, mixed> $vars */
	#[DataProvider('writers')]
	public function testACoreThatDoesNotAnswerLeavesTheFailureAndTheSaveStands(string $page, string $start, string $end, array $vars, string $message): void
	{
		$this->arrange($vars);
		// Given no Core listening

		$this->runPage($page, $start, $end, $vars);

		$this->assertSame([$message], $GLOBALS['pfb_test_write_config_calls'], 'the save stands');
		$this->assertFileExists("{$this->dir}/pending", 'the save still marks its changes pending');
		$this->assertStringContainsString('did not answer', (string) @file_get_contents("{$this->dir}/core_settings_failed"), 'the reason is left for DNS General to show');
	}
}
