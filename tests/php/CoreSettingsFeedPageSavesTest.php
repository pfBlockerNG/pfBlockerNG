<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937: Core reads the IP and DNSBL groups through its settings adapter, so every page write of them tells Core
 * (SettingsChanged, forced: no GetSettings first, no parameters) after a successful write_config() only. A failed write tells Core
 * nothing; a Core that does not answer never undoes the save and leaves the failure for DNS General to show. The writers: the Groups
 * editor's save (pfblockerng_category_edit.php), the group list's removal of an empty entry, delete and reorder
 * (pfblockerng_category.php), and, issue #3968, the Blacklist page's save, whose fields Core's scheduler reads as `extra:bl`
 * (pfblockerng_blacklist.php). Each case runs the page's own statements, from before its write_config() through the notice, over the
 * doubles, against a Core stand-in (support/CoreSettingsStandIn.php) that records every request it gets.
 */
final class CoreSettingsFeedPageSavesTest extends TestCase
{
	private const EDIT = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
	private const LIST = 'src/usr/local/www/pfblockerng/pfblockerng_category.php';
	private const BLACKLIST = 'src/usr/local/www/pfblockerng/pfblockerng_blacklist.php';
	private const V4 = 'installedpackages/pfblockernglistsv4/config';

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} the running stand-in */
	private ?array $standIn = NULL;
	private array $priorConfig;
	private array $priorPfb;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_feed_pages_' . bin2hex(random_bytes(8));
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
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_write_config_args']);
		rmdir_recursive($this->dir);
	}

	/** Start a Core stand-in that takes the notice, on the sandbox's socket; returns once it listens. */
	private function core(): void
	{
		$script = ['GetSettings' => [200, ['initialized' => TRUE, 'revision' => 3, 'projections' => []]], 'SettingsChanged' => [200, ['initialized' => TRUE, 'revision' => 4, 'projections' => []]]];
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
	 * Every page write of the groups: the page, its statements from before the write_config() to after the notice, the variables
	 * the page has set there, and the write_config() description.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string, 3: array<string, mixed>, 4: string}>
	 */
	public static function writers(): array
	{
		$group = ['aliasname' => 'Spam', 'action' => 'Deny_Inbound', 'cron' => 'Never'];
		return [
			'the Groups editor saves a group' => [self::EDIT,
				'$savemsg = "Saved [ Type:{$type}, Name:{$name} ] configuration";', 'pfb_mark_pending_changes();',
				['type' => 'IPv4', 'name' => 'Spam'], 'pfBlockerNG: Saved [ Type:IPv4, Name:Spam ] configuration'],
			'the group list removes an empty entry' => [self::LIST,
				"// Remove any empty '<config></config>' XML tags", 'if (!empty($action) && isset($gtype) && isset($rowid)) {',
				['rowdata' => [[], $group], 'rowdata_path' => self::V4], 'pfBlockerNG: Removed empty rowdata'],
			'the group list deletes a group' => [self::LIST,
				"try {\n\t\t\t\t\$name = pfb_filter(\$rowdata[\$rowid]['aliasname'] ?? '', PFB_FILTER_WORD, 'Category');", 'header("Location: /pfblockerng/pfblockerng_category.php?type={$gtype}&savemsg={$savemsg}");',
				['rowdata' => [$group], 'rowid' => 0, 'rowdata_path' => self::V4, 'gtype' => 'ipv4', 'type' => 'IPv4'], 'pfBlockerNG: Removed [ IPv4 | Spam ]'],
			'the group list saves its order' => [self::LIST,
				'// Save postdata and Table re-ordering', "\n\t\t\t}\n\t}\n\texit;",
				['input_errors' => [], 'type' => 'IPv4'], 'pfBlockerNG: Saved page order format/settings for [ IPv4 ]'],
			'the Blacklist page saves' => [self::BLACKLIST,
				"\$pfb_written = write_config('[ pfBlockerNG ] save DNSBL Category settings');", 'if ($savemsg) {',
				['config_mod' => TRUE], '[ pfBlockerNG ] save DNSBL Category settings'],
		];
	}

	/** Run the page's statements between $start and $end with $vars in scope (and the page's $pfb). */
	private function runPage(string $page, string $start, string $end, array $vars): void
	{
		config_set_path(self::V4, [['aliasname' => 'Spam', 'action' => 'Deny_Inbound', 'cron' => 'Never']]);
		$code = pfb_test_page_region($page, $start, $end);
		// The editor and update snippets now cross try/finally boundaries: supply their surrounding openers/closers.
		if ($page === self::EDIT) {
			$code = 'try {' . $code . "\n}";
		} elseif (str_starts_with($start, '// Save postdata') || $page === self::BLACKLIST) {
			$code = 'try { if (TRUE) {' . $code . "\n}";
		}
		$lock = pfb_dns_config_lock();
		$post = $_POST;
		$_POST = ['aliasname' => 'Spam'];	// the group name the list page's delete posts with the row index
		ob_start();
		try {
			pfb_test_page_eval($code, $vars + [
				'pfb' => $GLOBALS['pfb'], 'pfb_config_lock' => $lock, 'pfb_groups_changed' => FALSE,
				'action' => '', 'input_errors' => [],
			]);
		} finally {
			ob_end_clean();
			$_POST = $post;
			unlock($lock);
		}
	}

	/** @param array<string, mixed> $vars */
	#[DataProvider('writers')]
	public function testASuccessfulWriteTellsCoreAtOnceWithoutAskingItsRevision(string $page, string $start, string $end, array $vars, string $message): void
	{
		$this->core();

		$this->runPage($page, $start, $end, $vars);

		$this->assertSame([$message], $GLOBALS['pfb_test_write_config_calls'], 'the page wrote config.xml');
		$this->assertSame([['method' => 'SettingsChanged', 'body' => []]], $this->requests(), 'forced: Core is told, with nothing but the notice');
		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
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
		// Given no Core listening

		// When the page writes
		$this->runPage($page, $start, $end, $vars);

		// Then the write stands, and the reason Core was not told is left for DNS General
		$this->assertSame([$message], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertStringContainsString('did not answer', (string) @file_get_contents("{$this->dir}/core_settings_failed"));
	}
}
