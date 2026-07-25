<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionMigrateTest extends TestCase
{
	private string $root;
	private string $artifact;
	private string $artifactHash;

	protected function setUp(): void
	{
		$this->root = realpath(sys_get_temp_dir()) . '/pfb_migrate_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$this->artifact = $this->root . '/target.pkg';
		file_put_contents($this->artifact, 'target artifact bytes');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_persisted_config'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_persisted_config']);
		$this->removeTree($this->root);
	}

	public function testFirstThreeTwoToFourUsesMigrateAndRetainsOnlySourceHead(): void
	{
		$this->seedConfig([
			'pfblockerng' => ['config' => ['0' => ['value' => 'source', 'pfb_schema_family' => '3.2']]],
		]);

		$result = $this->prepare();

		$this->assertSame('migrate', $result['action']);
		$this->assertSame('', $result['target_snapshot_sha256']);
		$this->assertFileExists($this->root . '/3.2/head.json');
		$this->assertFileDoesNotExist($this->root . '/4.0/head.json');
	}

	public function testMigrateVerifiesProtectedSourceWithoutRestoringOwnedSettings(): void
	{
		$source = [
			'pfblockerng' => ['config' => ['0' => ['value' => 'source', 'pfb_schema_family' => '3.2']]],
		];
		$this->seedConfig($source);
		$this->prepare();

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '4.0.0', $this->root);

		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame($source, pfb_settings_capture_owned());
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testMigrateResetsTemporaryKeepForAbsentOnAndOffSources(): void
	{
		foreach ([NULL, 'on', 'off'] as $sourceKeep) {
			$this->resetRoot();
			$config = ['0' => ['value' => 'source', 'pfb_schema_family' => '3.2']];
			if ($sourceKeep !== NULL) {
				$config['0']['pfb_keep'] = $sourceKeep;
			}
			$source = ['pfblockerng' => ['config' => $config]];
			$this->seedConfig($source);
			$this->prepare();
			$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['pfb_keep'] = 'on';
			$GLOBALS['pfb_test_write_config_calls'] = [];

			$result = pfb_settings_transition_apply('4.0', 'target-pkg', '4.0.0', $this->root);

			$this->assertSame('settings-applied', $result['phase']);
			$this->assertSame('3.2', PfbConfig::read('pfb_schema_family'));
			if ($sourceKeep === NULL) {
				$this->assertArrayNotHasKey('pfb_keep', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']);
				$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
			} else {
				$this->assertSame($sourceKeep, PfbConfig::read('pfb_keep')->value);
				$this->assertCount($sourceKeep === 'on' ? 0 : 1, $GLOBALS['pfb_test_write_config_calls']);
			}
		}
	}

	public function testLegacyUnversionedSnapshotMigratesWithoutRestoringIt(): void
	{
		$source = [
			'pfblockerng' => ['config' => ['0' => ['value' => 'legacy', 'pfb_keep' => 'off']]],
		];
		$this->seedConfig($source);
		$snapshot = pfb_settings_snapshot_create('3.2', 'source-pkg', '3.2.15', $this->root);
		$protected = $source;
		$protected['pfblockerng']['config']['0']['pfb_schema_family'] = '3.2';
		$protected['pfblockerng']['config']['0']['pfb_keep'] = 'on';
		$this->seedConfig($protected);
		_pfb_settings_journal_publish([
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => 'migrate',
			'source_family' => '3.2',
			'source_package_name' => 'source-pkg',
			'source_package_version' => '3.2.15',
			'source_snapshot_sha256' => $snapshot['payload_sha256'],
			'source_live_sha256' => hash('sha256', serialize($protected)),
			'target_family' => '4.0',
			'target_package_name' => 'target-pkg',
			'target_package_version' => '4.0.0',
			'target_snapshot_sha256' => '',
			'target_artifact' => $this->artifact,
			'target_artifact_sha256' => $this->artifactHash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:migrate-test',
			'authorization_sha256' => '',
		], $this->root);

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '4.0.0', $this->root);

		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame('legacy', config_get_path('installedpackages/pfblockerng/config/0/value'));
		$this->assertSame('off', PfbConfig::read('pfb_keep')->value);
		$this->assertSame('3.2', PfbConfig::read('pfb_schema_family'));
	}

	public function testLegacyOwnedSectionsWithoutGeneralConfigStillMigrateInPlace(): void
	{
		$source = ['pfblockerngdnsblsettings' => ['config' => ['0' => ['value' => 'legacy']]]];
		$this->seedConfig($source);
		$snapshot = pfb_settings_snapshot_create('3.2', 'source-pkg', '3.2.15', $this->root);
		$protected = $source;
		$protected['pfblockerng']['config']['0'] = [
			'pfb_schema_family' => '3.2',
			'pfb_keep' => 'on',
		];
		$this->seedConfig($protected);
		_pfb_settings_journal_publish([
			'journal_version' => 1,
			'phase' => 'prepared',
			'action' => 'migrate',
			'source_family' => '3.2',
			'source_package_name' => 'source-pkg',
			'source_package_version' => '3.2.15',
			'source_snapshot_sha256' => $snapshot['payload_sha256'],
			'source_live_sha256' => hash('sha256', serialize($protected)),
			'target_family' => '4.0',
			'target_package_name' => 'target-pkg',
			'target_package_version' => '4.0.0',
			'target_snapshot_sha256' => '',
			'target_artifact' => $this->artifact,
			'target_artifact_sha256' => $this->artifactHash,
			'target_abi' => 'FreeBSD:14:amd64',
			'target_source_identity' => 'git:migrate-test',
			'authorization_sha256' => '',
		], $this->root);

		$result = pfb_settings_transition_apply('4.0', 'target-pkg', '4.0.0', $this->root);

		$this->assertSame('settings-applied', $result['phase']);
		$this->assertSame($source['pfblockerngdnsblsettings'], pfb_settings_capture_owned()['pfblockerngdnsblsettings']);
		$this->assertSame('3.2', PfbConfig::read('pfb_schema_family'));
		$this->assertArrayNotHasKey('pfb_keep', config_get_path('installedpackages/pfblockerng/config/0'));
	}

	public function testMigrateRejectsProtectedSourceChangesWithoutRestoringSnapshot(): void
	{
		$source = [
			'pfblockerng' => ['config' => ['0' => ['value' => 'source', 'pfb_schema_family' => '3.2']]],
		];
		$this->seedConfig($source);
		$this->prepare();
		$GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['value'] = 'changed';

		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_apply('4.0', 'target-pkg', '4.0.0', $this->root));
		$this->assertSame('changed', $GLOBALS['config']['installedpackages']['pfblockerng']['config']['0']['value']);
		$this->assertSame('settings-applying', pfb_settings_journal_read($this->root)['phase']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	private function prepare(): array
	{
		return pfb_settings_transition_prepare(
			'source-pkg',
			'3.2.15',
			'4.0',
			'target-pkg',
			'4.0.0',
			$this->artifact,
			$this->artifactHash,
			'FreeBSD:14:amd64',
			'git:migrate-test',
			'',
			$this->root
		);
	}

	private function seedConfig(array $owned): void
	{
		$GLOBALS['config'] = ['installedpackages' => $owned];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	private function resetRoot(): void
	{
		$this->removeTree($this->root);
		mkdir($this->root, 0700, TRUE);
		file_put_contents($this->artifact, 'target artifact bytes');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	private function assertThrows(string $class, Closure $call): void
	{
		try {
			$call();
		} catch (Throwable $error) {
			$this->assertInstanceOf($class, $error);
			return;
		}
		$this->fail('expected ' . $class);
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path) || is_link($path)) {
			@unlink($path);
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				$this->removeTree($path . '/' . $entry);
			}
		}
		@rmdir($path);
	}
}
