<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyTest extends TestCase
{
	/**
	 * How far ahead of the clock a "created in the future" fixture is written (#2029).
	 *
	 * pfb_settings_downgrade_context_target() reads its own time(), so such a fixture is
	 * only in the future while the wall clock stays behind its created_at. Every rejection
	 * row is therefore written against the clock read immediately before ITS OWN write --
	 * never one array-literal snapshot shared by all rows, which made each row's verdict
	 * depend on how long the preceding rows took to validate (a one-second margin lost that
	 * race on CI). The margin is a salvage bound, not an assertion: the guard beside it
	 * reports STUCK/ENVIRONMENT if the clock ever overtakes it. Its mirror-image sibling,
	 * the "older than the window" row, drifts the safe way -- it only gets older -- and so
	 * needs no such guard.
	 */
	private const FUTURE_MARGIN_S = 300;

	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_family_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['pfb']['downgrade_context_path'] = $this->root . '/context.json';
		$GLOBALS['config'] = [
			'system' => ['hostname' => 'unchanged'],
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => [
					'pfb_keep' => 'off',
					'credential' => 'secret-canary',
					'empty' => [],
				]]],
				'pfblockerngglobal' => ['unknown_future' => ['nested' => ['value' => 'keep-me']]],
				'otherpackage' => ['config' => ['untouched' => 'yes']],
			],
		];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb']['downgrade_context_path']);
		$this->removeTree($this->root);
	}

	public function testMissingMarkerDefaultsToThreeTwoAndRecordUsesGateway(): void
	{
		$this->assertSame('3.2', pfb_settings_family_current());
		$this->assertSame('3.2', PfbConfig::read('gen/settings_family'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$this->assertSame('4.0', pfb_settings_family_current());
		$this->assertSame('4.0', PfbConfig::read('gen/settings_family'));
	}

	public function testInvalidMarkerAndUnknownVersionFailClosed(): void
	{
		PfbConfig::write('gen/settings_family', '9.0');
		$this->assertNull(pfb_settings_family_current());
		$this->assertSame('3.2', pfb_settings_family_from_version('3.2.0'));
		$this->assertSame('3.3', pfb_settings_family_from_version('3.3.0'));
		$this->assertSame('4.0', pfb_settings_family_from_version('4.0.0'));
		$this->assertSame('4.1', pfb_settings_family_from_version('4.1.0'));
		$this->assertSame('4.1', pfb_settings_family_from_version('20260819010101.abcdef1'));
		// pfb_pkg_ver() prefixes 'v'; POST-INSTALL on nightly was failing closed as NULL (lab finding 16).
		$this->assertSame('4.1', pfb_settings_family_from_version('v20260819010101.abcdef1'));
		$this->assertSame('3.3', pfb_settings_family_from_version('v3.3.2'));
		$this->assertSame('4.0', pfb_settings_family_from_version('v4.0.0.a1'));
		$this->assertNull(pfb_settings_family_from_version('vv4.0.0'));
		$this->assertNull(pfb_settings_family_from_version('5.0.1'));
		$this->assertNull(pfb_settings_family_from_version('20260230010101.abcdef1'));
		$this->assertNull(pfb_settings_family_from_version('20260819010101.ABCDEF1'));
		$this->assertNull(pfb_settings_family_from_version('20260819010101.abcdef'));
	}

	public function testThreeThreeMarkerCanBeSnapshottedBeforeUpgrade(): void
	{
		$this->assertTrue(pfb_settings_family_record('3.3'));
		$this->assertSame('3.3', pfb_settings_family_current());
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-3.3.xml');
	}

	public function testSaveAndReplacePreserveOwnedSubtreeAndUnrelatedConfig(): void
	{
		$owned = [
			'pfblockerng' => $GLOBALS['config']['installedpackages']['pfblockerng'],
			'pfblockerngglobal' => $GLOBALS['config']['installedpackages']['pfblockerngglobal'],
		];
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'changed';
		$GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched'] = 'changed';
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		$this->assertSame($owned['pfblockerng'], $GLOBALS['config']['installedpackages']['pfblockerng']);
		$this->assertSame($owned['pfblockerngglobal'], $GLOBALS['config']['installedpackages']['pfblockerngglobal']);
		$this->assertSame('changed', $GLOBALS['config']['installedpackages']['otherpackage']['config']['untouched']);
		$this->assertSame('unchanged', $GLOBALS['config']['system']['hostname']);
	}

	public function testMissingSlotLeavesLiveConfigUntouched(): void
	{
		$before = $GLOBALS['config'];
		$this->assertTrue(pfb_settings_family_replace('4.0'));
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testRawDowngradeWithoutContextDoesNotReplaceV3(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testValidGuiContextRestoresExactLowerSlotAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		$this->assertSame('3.2', pfb_settings_downgrade_context_target('4.0'));
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());
		$this->assertSame('secret-canary', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testInvalidContextsRejectAndRegularFilesAreConsumed(): void
	{
		// 'created_at' is an OFFSET, resolved against the clock read immediately before
		// that row's OWN write (#2029) -- see FUTURE_MARGIN_S.
		$contexts = [
			'with an unsupported version'          => ['version' => 2, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => 0],
			'older than the 300-second window'     => ['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => -301],
			'created in the future'                => ['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => self::FUTURE_MARGIN_S],
			'whose source family is not the live family' => ['version' => 1, 'source_family' => '3.2', 'target_family' => '3.2', 'created_at' => 0],
			'whose target family does not rank below its source' => ['version' => 1, 'source_family' => '4.0', 'target_family' => '4.0', 'created_at' => 0],
			'whose version is a string, not an int' => ['version' => '1', 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => 0],
			'whose source family is an array, not a string' => ['version' => 1, 'source_family' => ['4.0'], 'target_family' => '3.2', 'created_at' => 0],
		];
		foreach ($contexts as $why => $context) {
			$offset                = (int) $context['created_at'];
			$context['created_at'] = time() + $offset;
			$this->writeContext($context);
			$target = pfb_settings_downgrade_context_target('4.0');
			if ($offset > 0) {
				// Salvage guard, never the verdict: re-read the clock AFTER the call, so a
				// pass proves the fixture was still in the future when the validator read
				// time(). Only its expiry is time-shaped, and it says so.
				$this->assertGreaterThan(time(), $context['created_at'],
					'STUCK/ENVIRONMENT: the wall clock consumed the whole ' . self::FUTURE_MARGIN_S
					. 's future margin during one validation call -- the run is stuck or the '
					. 'environment is broken, not a behavioural failure');
			}
			$this->assertNull($target, "a context {$why} must be rejected, got "
				. var_export($target, TRUE));
			pfb_settings_downgrade_context_consume();
			$this->assertFileDoesNotExist($this->contextPath());
		}

		file_put_contents($this->contextPath(), '{malformed');
		chmod($this->contextPath(), 0600);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time(), 'future' => TRUE]);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		file_put_contents($this->contextPath(), str_repeat('x', 513));
		chmod($this->contextPath(), 0600);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		chmod($this->contextPath(), 0644);
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileDoesNotExist($this->contextPath());

		$target = $this->root . '/context-target.json';
		file_put_contents($target, '{}');
		symlink($target, $this->contextPath());
		$this->assertNull(pfb_settings_downgrade_context_target('4.0'));
		pfb_settings_downgrade_context_consume();
		$this->assertFileExists($this->contextPath());
	}

	public function testValidContextWithMissingTargetIsConsumedWithoutMutation(): void
	{
		$before = $GLOBALS['config'];
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		$this->assertSame('3.2', pfb_settings_downgrade_context_target('4.0'));
		$this->assertTrue(pfb_settings_family_replace('3.2'));
		pfb_settings_downgrade_context_consume();
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testKeepOffIsPreservedAtLegacyBoundary(): void
	{
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_keep'));
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_keep'));
	}

	public function testSaveWithNoOwnedConfigIsNoOpWithoutCreatingSlot(): void
	{
		foreach (array_keys($GLOBALS['config']['installedpackages']) as $section) {
			if (str_starts_with((string) $section, 'pfblockerng')) {
				unset($GLOBALS['config']['installedpackages'][$section]);
			}
		}
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertFileDoesNotExist($this->root . '/settings-3.2.xml');
	}

	public function testSaveCreatesSecureSlotAndOverwritesExisting(): void
	{
		$rootMode = fileperms($this->root) & 0777;
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$slot = $this->root . '/settings-3.2.xml';
		$this->assertSame($rootMode, fileperms($this->root) & 0777);
		$this->assertSame(0600, fileperms($slot) & 0777);
		$first = file_get_contents($slot);
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'overwrite-proof';
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$second = file_get_contents($slot);
		$this->assertNotSame($first, $second);
	}

	public function testCorruptSlotFailsWithoutMutatingLiveConfig(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$slot = $this->root . '/settings-3.2.xml';
		file_put_contents($slot, 'corrupt');
		chmod($slot, 0600);
		$before = $GLOBALS['config'];
		$this->assertFalse(pfb_settings_family_replace('3.2'));
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testPreUninstallRawPathSavesCurrentFamilyWithoutRestoringLowerSlot(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
	}

	public function testPreUninstallValidContextSavesCurrentRestoresLowerAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 1, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('secret-canary', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testPreUninstallInvalidContextSavesOnlyAndConsumes(): void
	{
		$this->assertTrue(pfb_settings_family_save('3.2'));
		$this->assertTrue(pfb_settings_family_record('4.0'));
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential'] = 'current-v4';
		$this->writeContext(['version' => 2, 'source_family' => '4.0', 'target_family' => '3.2', 'created_at' => time()]);
		pfb_settings_family_pre_uninstall();
		$this->assertFileExists($this->root . '/settings-4.0.xml');
		$this->assertSame('current-v4', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['credential']);
		$this->assertFileDoesNotExist($this->contextPath());
	}

	public function testLifecycleOrdersReplaceAndContextConsumptionBeforeMigrations(): void
	{
		$order = [];
		$family = pfb_install_settings_family_capture_restore(
			static function () use (&$order): string { $order[] = 'current'; return '3.3'; },
			static function (string $value) use (&$order): bool { $order[] = 'save'; return TRUE; },
			static function () use (&$order): string { $order[] = 'version'; return '4.0.0'; },
			static function (string $value) use (&$order): string { $order[] = 'from-version'; return '4.0'; },
			static function (string $value) use (&$order): bool { $order[] = 'replace'; return TRUE; },
		);
		pfb_install_settings_family_finalize(
			$family,
			static function () use (&$order): void { $order[] = 'migrations'; },
			static function (string $value) use (&$order): bool { $order[] = 'record'; return TRUE; }
		);
		$this->assertSame('4.0', $family);
		$this->assertSame(['current', 'version', 'from-version', 'save', 'replace', 'migrations', 'record'], $order);
	}

	/**
	 * The pre-deinstall hook reads live process/config state and can tear down firewall, DNSBL,
	 * mounts, files, and services, so only its executable order is pinned off-appliance.
	 */
	public function testPreDeinstallSavesAndRestoresBeforePackageOperationAndHonorsKeepBoundary(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start, 'pre-deinstall controller must remain defined');
		$save = strpos($source, 'pfb_settings_family_pre_uninstall();', $start);
		$operation = strpos($source, 'pfb_pkg_operation();', $start);
		$this->assertNotFalse($save, 'pre-deinstall must enter settings-family save/restore boundary');
		$this->assertNotFalse($operation, 'pre-deinstall must inspect package operation after settings boundary');
		$this->assertLessThan($operation, $save);
		$this->assertSame(1, substr_count(substr($source, $start, $operation - $start), 'pfb_settings_family_pre_uninstall();'));

		$keep = strpos($source, "\$pfb['keep'] !== PfbToggle::On", $start);
		$remove = strpos($source, 'pfb_remove_config_settings();', $start);
		$this->assertNotFalse($keep, 'keep setting must guard config removal');
		$this->assertNotFalse($remove, 'keep-off branch must remove package config');
		$this->assertLessThan($remove, $keep);
	}

	private function contextPath(): string
	{
		return $GLOBALS['pfb']['downgrade_context_path'];
	}

	private function writeContext(array $context): void
	{
		file_put_contents($this->contextPath(), json_encode($context, JSON_THROW_ON_ERROR));
		chmod($this->contextPath(), 0600);
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path)) {
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$child = $path . '/' . $entry;
			is_dir($child) && !is_link($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
