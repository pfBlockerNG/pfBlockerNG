<?php

declare(strict_types=1);

require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3996: Core runs every pfBlockerNG schedule, so the package installs no crontab entry and removes every one an earlier version
 * installed. The sync pass is covered by TickCronInstallTest; this class pins the function, the install/upgrade script, the removal
 * hook and the absence of any install call in the shipped sources.
 */
#[CoversFunction('pfblockerng_retire_cron_jobs')]
final class RetireCronJobsTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src';
	private const PHP = '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php ';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/** @return list<string> every command a pfBlockerNG version once installed, daily and weekly clear jobs side by side */
	private function legacyEntries(): array
	{
		$entries = [];
		foreach (['cron', 'tick', 'cron-tick', 'dcc', 'ss_refresh', 'bl'] as $verb) {
			$entries[] = self::PHP . $verb . ' >> /var/log/pfblockerng/pfblockerng.log 2>&1';
		}
		foreach (['clearip', 'cleardnsbl'] as $verb) {
			foreach (['', "'"] as $quote) {
				$entries[] = self::PHP . "{$quote}{$verb}{$quote} >/dev/null 2>&1";
				$entries[] = self::PHP . "{$quote}{$verb}{$quote} >/dev/null 2>&1 ";	// the weekly twin differs only in its wday field
			}
		}
		$entries[] = '/usr/bin/timeout -s TERM -k 5 50 ' . self::PHP . 'metrics >> /dev/null 2>&1';
		return $entries;
	}

	/** @param list<string> $commands */
	private function seed(array $commands): void
	{
		foreach ($commands as $idx => $command) {
			config_set_path("cron/item/{$idx}", [
				'minute' => '0', 'hour' => '0', 'mday' => '*', 'month' => '*',
				'wday' => $idx % 2 === 0 ? '*' : '7', 'who' => 'root', 'command' => $command,
			]);
		}
	}

	/** @return list<string> */
	private function commands(): array
	{
		return array_values(array_map(static fn (array $item): string => $item['command'], config_get_path('cron/item', [])));
	}

	/** @return list<array{string, bool}> every install_cron_job() call the callback makes */
	private function recordInstalls(callable $run): array
	{
		$calls = [];
		$GLOBALS['pfb_test_install_cron_hook'] = static function (string $command, bool $active) use (&$calls): void {
			$calls[] = [$command, $active];
		};
		try {
			$run();
		} finally {
			unset($GLOBALS['pfb_test_install_cron_hook']);
		}
		return $calls;
	}

	public function testItRemovesEveryLegacyEntryIncludingSeveralOfOneVerbAndKeepsOtherJobs(): void
	{
		$legacy = $this->legacyEntries();
	$others = [
			'/usr/sbin/newsyslog', '/usr/local/bin/php /usr/local/www/otherpackage.php clearip-cache',
			self::PHP . 'clearip_backup >/dev/null 2>&1', self::PHP . 'cleardnsbl2 >/dev/null 2>&1', self::PHP . 'metrics_x >> /dev/null 2>&1',
			self::PHP . "'clearip'x >/dev/null 2>&1", self::PHP . "'cleardnsbl'x >/dev/null 2>&1",
		];
		$this->seed(array_merge($legacy, $others));
		$this->assertSame(array_merge($legacy, $others), $this->commands(), 'before: daily and weekly entries of one verb, quoted and not');

		$calls = $this->recordInstalls(static fn () => pfblockerng_retire_cron_jobs());

		$this->assertSame($others, $this->commands());
		$this->assertSame([], array_filter($calls, static fn (array $call): bool => $call[1]), 'removal only: no install_cron_job(..., TRUE)');
	}

	public function testItIsANoOpOnACrontabWithoutPackageEntries(): void
	{
		$this->seed(['/usr/sbin/newsyslog']);

		$calls = $this->recordInstalls(static fn () => pfblockerng_retire_cron_jobs());

		$this->assertSame(['/usr/sbin/newsyslog'], $this->commands());
		$this->assertSame([], array_filter($calls, static fn (array $call): bool => $call[1]));
	}

	/** The upgrade of a box whose widget cadences and metrics export were on: its install script removes the entries and installs none. */
	public function testTheInstallScriptRemovesEveryLegacyEntryAndInstallsNone(): void
	{
		$legacy = $this->legacyEntries();
		$this->seed(array_merge($legacy, ['/usr/sbin/newsyslog']));
		config_set_path('installedpackages/pfblockerngglobal/widget-clearip', 'daily');
		config_set_path('installedpackages/pfblockerngglobal/widget-cleardnsbl', 'weekly');
		$code = pfb_test_page_region(
			'src/usr/local/pkg/pfblockerng/pfblockerng_install.inc',
			'// Core schedules every job',
			'// issue #1921: the ONE registry-driven pass'
		);
		$GLOBALS['pfb_test_update_status'] = [];

		$calls = $this->recordInstalls(static fn () => pfb_test_page_eval($code, []));

		$this->assertSame(['/usr/sbin/newsyslog'], $this->commands());
		$this->assertSame([], array_filter($calls, static fn (array $call): bool => $call[1]));
		$this->assertNotSame([], $GLOBALS['pfb_test_update_status'], 'the install log says what ran');
	}

	public function testTheRemovalRetiresTheEntriesAfterTheMetricsLockIsReleased(): void
	{
		$source = (string) file_get_contents(self::SRC . '/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start);
		$body = substr($source, $start, (int) strpos($source, "\n}\n", $start) - $start);
		$export = strpos($body, 'pfb_metrics_configure_export(FALSE);');
		$retire = strpos($body, 'pfblockerng_retire_cron_jobs();');
		$this->assertNotFalse($export, 'the removal turns the metrics export off');
		$this->assertNotFalse($retire, 'the removal retires every cron entry');
		$this->assertLessThan($retire, $export, 'install_cron_job() can start cron, which would inherit a held metrics lock');
	}

	public function testNoShippedSourceInstallsACronEntry(): void
	{
		$offenders = [];
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::SRC, FilesystemIterator::SKIP_DOTS));
		foreach ($iterator as $file) {
			if (!in_array($file->getExtension(), ['php', 'inc'], TRUE)) {
				continue;
			}
			$tokens = token_get_all((string) file_get_contents($file->getPathname()));
			foreach ($tokens as $i => $token) {
				if (!is_array($token) || $token[0] !== T_STRING || $token[1] !== 'install_cron_job') {
					continue;
				}
				// the call's second argument: everything up to the first top-level comma after the first argument
				$depth = 0;
				$arguments = [''];
				for ($j = $i + 1; $j < count($tokens); $j++) {
					$text = is_array($tokens[$j]) ? $tokens[$j][1] : $tokens[$j];
					if ($text === '(') {
						$depth++;
						if ($depth === 1) {
							continue;
						}
					} elseif ($text === ')' && --$depth === 0) {
						break;
					} elseif ($text === ',' && $depth === 1) {
						$arguments[] = '';
						continue;
					}
					$arguments[count($arguments) - 1] .= $text;
				}
				if (strtoupper(trim($arguments[1] ?? '')) !== 'FALSE') {
					$offenders[] = $file->getPathname() . ' line ' . ($token[2]) . ': install_cron_job(' . implode(',', $arguments) . ')';
				}
			}
		}
		$this->assertSame([], $offenders, 'a call that is not install_cron_job(<needle>, FALSE) installs an entry');
	}
}
