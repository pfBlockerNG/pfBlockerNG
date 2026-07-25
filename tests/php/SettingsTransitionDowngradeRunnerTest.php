<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionDowngradeRunnerTest extends TestCase
{
	private string $root;
	private string $artifact;
	private string $artifactHash;

	protected function setUp(): void
	{
		$this->root = realpath(sys_get_temp_dir()) . '/pfb_downgrade_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$this->artifact = $this->root . '/pfSense-pkg-pfBlockerNG-3.2.15.pkg';
		file_put_contents($this->artifact, 'frozen target package');
		chmod($this->artifact, 0600);
		$this->artifactHash = hash_file('sha256', $this->artifact);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => ['0' => ['value' => 'v4', 'pfb_schema_family' => '4.0']],
				],
			],
		];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
		unset($GLOBALS['pfb_test_persisted_config'], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testPreparesAppliesAndInstallsExactFrozenTargetBeforeCompleting(): void
	{
		$order = [];
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$authorization = $this->authorize($target);

		$result = pfb_settings_transition_downgrade($target, [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $authorization,
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => function (array $argv, array $stdio) use (&$order): int {
				$order[] = [
					'install',
					$argv,
					$stdio,
					pfb_settings_journal_read($this->root)['phase'],
					PfbConfig::read('pfb_schema_family'),
					$GLOBALS['pfb_test_persisted_config']['installedpackages']['pfblockerng']['config']['0']['pfb_schema_family'] ?? '',
				];
				return 0;
			},
		]);

		$this->assertSame(0, $result);
		$this->assertCount(1, $order);
		$this->assertSame([
			'install',
			['/usr/local/sbin/pkg', 'install', '-y', '-f', $this->artifact],
			['stdin' => '/dev/null', 'stdout' => 'inherit', 'stderr' => 'inherit'],
			'settings-applied',
			'3.2',
			'3.2',
		], $order[0]);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testAcceptsExactFrozenDevelTarget(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-devel-3.2.16';
		$descriptor = $this->descriptor($target);
		$status = pfb_settings_transition_downgrade($target, [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $this->authorize($target),
			'source_package_name' => 'pfSense-pkg-pfBlockerNG',
			'source_package_version' => '4.0.0',
			'install' => static function (): int {
				PfbConfig::write('pfb_schema_family', '3.2');
				return 0;
			},
		]);
		$this->assertSame(0, $status);
	}

	public function testRejectsNearTargetsAndWrongAuthorizationBeforeJournal(): void
	{
		foreach ([
			['pfSense-pkg-pfBlockerNG-3.2.14', 'target'],
			['pfSense-pkg-pfBlockerNG-3.2.15 --force', 'target'],
			['pfSense-pkg-pfBlockerNG-3.2.15', 'wrong-auth'],
		] as [$target, $kind]) {
			$this->resetFixture();
			$descriptor = $this->descriptor('pfSense-pkg-pfBlockerNG-3.2.15');
			$authorization = $kind === 'wrong-auth'
				? str_repeat('a', 64)
				: str_repeat('b', 64);
			if ($kind === 'wrong-auth') {
				$this->authorize('pfSense-pkg-pfBlockerNG-3.2.15');
			}
			$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade(
				$target,
				[
					'artifact_root' => $this->root,
					'artifact' => $descriptor,
					'installed' => $descriptor,
					'current_abi' => $descriptor['abi'],
					'authorization_sha256' => $authorization,
					'install' => static fn(): int => 0,
				]
			));
			$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
		}
	}

	public function testRejectsArtifactMetadataMismatchBeforePrepareOrInstall(): void
	{
		$descriptor = $this->descriptor('pfSense-pkg-pfBlockerNG-3.2.15');
		$descriptor['manifest']['name'] = 'pfSense-pkg-pfBlockerNG-devel';
		$before = $GLOBALS['config'];
		$authorization = $this->authorize('pfSense-pkg-pfBlockerNG-3.2.15');

		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade(
			'pfSense-pkg-pfBlockerNG-3.2.15',
			[
				'artifact_root' => $this->root,
				'artifact' => $descriptor,
				'current_abi' => $descriptor['abi'],
				'authorization_sha256' => $authorization,
				'install' => static fn(): int => 0,
			]
		));
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testRejectsFrozenSourceIdentityMismatchBeforePrepare(): void
	{
		$descriptor = $this->descriptor('pfSense-pkg-pfBlockerNG-3.2.15');
		$descriptor['source_identity'] = 'git:' . str_repeat('f', 40);
		$authorization = $this->authorize('pfSense-pkg-pfBlockerNG-3.2.15');
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade(
			'pfSense-pkg-pfBlockerNG-3.2.15',
			[
				'artifact_root' => $this->root,
				'artifact' => $descriptor,
				'current_abi' => $descriptor['abi'],
				'authorization_sha256' => $authorization,
				'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
				'source_package_version' => '4.0.0',
				'install' => static fn(): int => 0,
			]
		));
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testNonzeroInstallStatusRetainsJournalAndSkipsCompletion(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$authorization = $this->authorize($target);
		$install_status = 37;
		$installs = 0;
		$io = [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => 'FreeBSD:14:amd64',
			'authorization_sha256' => $authorization,
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => static function () use (&$install_status, &$installs): int {
				$installs++;
				return $install_status;
			},
		];

		$this->assertSame(37, pfb_settings_transition_downgrade($target, $io));
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
		$wrong = $io;
		$wrong['authorization_sha256'] = str_repeat('a', 64);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade($target, $wrong));
		$install_status = 0;
		$this->assertSame(0, pfb_settings_transition_downgrade($target, $io));
		$this->assertSame(2, $installs);
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
	}

	public function testInstallExceptionRetainsPreparedJournal(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_downgrade($target, [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => 'FreeBSD:14:amd64',
			'authorization_sha256' => $this->authorize($target),
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => static function (): int {
				throw new RuntimeException('package runner unavailable');
			},
		]));
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
	}

	public function testLiveRunnerUsesNativeBoundedCatalogQueriesAndInheritedInstallStreams(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertIsString($source);
		$this->assertStringContainsString("PFB_PKG_BIN, 'rquery', '-r', 'pfblockerng', '%n|%v|%q|%X'", $source);
		$this->assertStringContainsString("PFB_PKG_BIN, 'fetch', '-r', 'pfblockerng'", $source);
		$this->assertStringContainsString("\$fetch_dir . '/All/' . \$target . '.pkg'", $source);
		$this->assertStringContainsString("array(PFB_PKG_BIN, 'query', '-F', \$path, '%n|%v|%q')", $source);
		$this->assertStringContainsString("array(PFB_PKG_BIN, 'query', '-F', \$path, '%An=%Av')", $source);
		$this->assertStringContainsString('proc_open($argv, $descriptors, $pipes)', $source);
		$this->assertStringContainsString("1 => array('file', 'php://stdout', 'w')", $source);
		$this->assertStringContainsString("2 => array('file', 'php://stderr', 'w')", $source);
		$this->assertStringContainsString("0 => array('file', '/dev/null', 'r')", $source);
	}

	public function testNativeRunnerUsesTimeoutReaperAndRetainsJournalOnTimeout(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$process = new stdClass();
		$closed = 0;

		$result = pfb_settings_transition_downgrade($target, [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $this->authorize($target),
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'process_open' => function (array $argv, array $descriptors, &$pipes) use ($process): object {
				$this->assertSame([
					'/usr/bin/timeout', '-s', 'TERM', '-k', '5', '3600',
					'/usr/local/sbin/pkg', 'install', '-y', '-f', $this->artifact,
				], $argv);
				$this->assertSame('php://stdout', $descriptors[1][1]);
				$this->assertSame('php://stderr', $descriptors[2][1]);
				$pipes = [];
				return $process;
			},
			'process_close' => static function ($candidate) use ($process, &$closed): int {
				if ($candidate !== $process) {
					throw new RuntimeException('unexpected process handle');
				}
				$closed++;
				return 124;
			},
		]);

		$this->assertSame(124, $result);
		$this->assertSame(1, $closed);
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
	}

	public function testRejectsAuthorizationReplayAfterSuccessfulDowngrade(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$authorization = $this->authorize($target);
		$installs = 0;
		$io = [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $authorization,
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => static function () use (&$installs): int {
				$installs++;
				return 0;
			},
		];

		$this->assertSame(0, pfb_settings_transition_downgrade($target, $io));
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade($target, $io));
		$this->assertSame(1, $installs);
	}

	public function testRejectsInstalledPackageIdentityMismatchBeforeCompletion(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$installed = $descriptor;
		$installed['version'] = '3.2.14';

		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_downgrade($target, [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $installed,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $this->authorize($target),
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => static fn(): int => 0,
		]));
		$this->assertSame('settings-applied', pfb_settings_journal_read($this->root)['phase']);
	}

	public function testConsumedAuthorizationRequiresFreshOwnerActionWhenPrepareFails(): void
	{
		$target = 'pfSense-pkg-pfBlockerNG-3.2.15';
		$descriptor = $this->descriptor($target);
		$authorization = $this->authorize($target);
		$before = $GLOBALS['config'];
		mkdir($this->root . '/4.0', 0755);
		$io = [
			'artifact_root' => $this->root,
			'artifact' => $descriptor,
			'installed' => $descriptor,
			'current_abi' => $descriptor['abi'],
			'authorization_sha256' => $authorization,
			'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'source_package_version' => '4.0.0',
			'install' => static fn(): int => 0,
		];

		$this->assertThrows(RuntimeException::class, fn() => pfb_settings_transition_downgrade($target, $io));
		$this->assertFileDoesNotExist($this->root . '/downgrade-authorization.json');
		$this->assertFileDoesNotExist($this->root . '/transition-journal.json');
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade($target, $io));
	}

	public function testRejectsSymlinkArtifactRootBeforeAnyPackageAction(): void
	{
		$unsafe = $this->root . '/unsafe-root';
		$this->assertTrue(symlink(sys_get_temp_dir(), $unsafe));
		$descriptor = $this->descriptor('pfSense-pkg-pfBlockerNG-3.2.15');
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_downgrade(
			'pfSense-pkg-pfBlockerNG-3.2.15',
			[
				'artifact_root' => $unsafe,
				'artifact' => $descriptor,
				'current_abi' => $descriptor['abi'],
				'authorization_sha256' => str_repeat('a', 64),
				'source_package_name' => 'pfSense-pkg-pfBlockerNG-devel',
				'source_package_version' => '4.0.0',
				'install' => static fn(): int => 0,
			]
		));
	}

	private function descriptor(string $target): array
	{
		[$name, $version] = str_contains($target, '-devel-')
			? ['pfSense-pkg-pfBlockerNG-devel', '3.2.16']
			: ['pfSense-pkg-pfBlockerNG', '3.2.15'];
		return [
			'path' => $this->artifact,
			'name' => $name,
			'version' => $version,
			'abi' => 'FreeBSD:14:amd64',
			'source_identity' => $version === '3.2.15'
				? 'git:0846aa7c090f96e62b5322d7dea70e80b1f31b63'
				: 'git:0676cd1c7ed79d49a0644070151c4fffa39ea409',
			'catalog' => 'pfblockerng',
			'sha256' => $this->artifactHash,
			'manifest' => [
				'name' => $name,
				'version' => $version,
				'abi' => 'FreeBSD:14:amd64',
				'annotations' => ['commit' => $version === '3.2.15'
					? '0846aa7c090f96e62b5322d7dea70e80b1f31b63'
					: '0676cd1c7ed79d49a0644070151c4fffa39ea409'],
			],
		];
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
			if (is_dir($child) && !is_link($child)) {
				$this->removeTree($child);
			} else {
				@unlink($child);
			}
		}
		@rmdir($path);
	}

	private function authorize(string $target): string
	{
		return pfb_settings_transition_downgrade_authorize($target, $this->artifactHash, $this->root);
	}

	private function resetFixture(): void
	{
		$this->removeTree($this->root);
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => ['0' => ['value' => 'v4', 'pfb_schema_family' => '4.0']],
				],
			],
		];
		$GLOBALS['pfb_test_persisted_config'] = $GLOBALS['config'];
	}

	private function assertThrows(string $class, Closure $call): void
	{
		try {
			$call();
		} catch (Throwable $error) {
			$this->assertInstanceOf($class, $error);
			return;
		}
		$this->fail("expected {$class}");
	}
}
