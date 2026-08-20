<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyPostInstallCaptureTest extends TestCase
{
	private const INSTALL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';

	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_cap_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->root;
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => ['config' => ['0' => ['pfb_keep' => 'off']]],
			],
		];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb']['dbdir']);
		if (!is_dir($this->root)) {
			return;
		}
		foreach (scandir($this->root) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			@unlink($this->root . '/' . $entry);
		}
		@rmdir($this->root);
	}

	public function testPostInstallCapturesSourceBeforeTargetRestoreAndMigrations(): void
	{
		$order = [];
		$installed = pfb_install_settings_family_capture_restore(
			static function () use (&$order): string {
				$order[] = 'current';
				return '3.3';
			},
			static function (string $family) use (&$order): bool {
				$order[] = "save:{$family}";
				return TRUE;
			},
			static function () use (&$order): string {
				$order[] = 'version';
				return '4.0.0';
			},
			static function (string $version) use (&$order): string {
				$order[] = "from:{$version}";
				return '4.0';
			},
			static function (string $family) use (&$order): bool {
				$order[] = "replace:{$family}";
				return TRUE;
			}
		);
		pfb_install_settings_family_finalize(
			$installed,
			static function () use (&$order): void { $order[] = 'migrations'; },
			static function (string $family) use (&$order): bool {
				$order[] = "record:{$family}";
				return TRUE;
			}
		);

		$this->assertSame('4.0', $installed);
		$this->assertSame(
			['current', 'version', 'from:4.0.0', 'save:3.3', 'replace:4.0', 'migrations', 'record:4.0'],
			$order
		);
	}

	public function testThreeTwoCannotSkipThreeThreeBridgeToFourX(): void
	{
		$order = [];
		try {
			pfb_install_settings_family_capture_restore(
				static function () use (&$order): string { $order[] = 'current'; return '3.2'; },
				static function (string $family) use (&$order): bool { $order[] = "save:{$family}"; return TRUE; },
				static function () use (&$order): string { $order[] = 'version'; return 'v20260819010101.abcdef1'; },
				static function (string $version) use (&$order): string {
					$order[] = "from:{$version}";
					return '4.1';
				},
				static function (string $family) use (&$order): bool { $order[] = "replace:{$family}"; return TRUE; }
			);
			$this->fail('3.2 must not skip the 3.3 bridge onto a 4.x family');
		} catch (RuntimeException $error) {
			$this->assertSame(
				'pfBlockerNG: install the 3.3 bridge before a 4.x family',
				$error->getMessage()
			);
		}
		$this->assertSame(['current', 'version', 'from:v20260819010101.abcdef1'], $order);
	}

	public function testFirstInstallWithNoOwnedSectionsAllowsFourX(): void
	{
		$GLOBALS['config'] = ['installedpackages' => []];
		$this->assertSame('3.2', pfb_settings_family_current());
		$order = [];
		$installed = pfb_install_settings_family_capture_restore(
			NULL,
			static function (string $family) use (&$order): bool {
				$order[] = "save:{$family}";
				return TRUE;
			},
			static function () use (&$order): string {
				$order[] = 'version';
				return '4.0.0.a1';
			},
			static function (string $version) use (&$order): string {
				$order[] = "from:{$version}";
				return '4.0';
			},
			static function (string $family) use (&$order): bool {
				$order[] = "replace:{$family}";
				return TRUE;
			}
		);
		$this->assertSame('4.0', $installed);
		$this->assertSame(['version', 'from:4.0.0.a1', 'save:3.2', 'replace:4.0'], $order);
	}

	public function testProductionCurrentMissingMarkerWithOwnedConfigCannotSkipBridge(): void
	{
		$this->assertSame('3.2', pfb_settings_family_current());
		$order = [];
		try {
			pfb_install_settings_family_capture_restore(
				NULL,
				static function (string $family) use (&$order): bool {
					$order[] = "save:{$family}";
					return TRUE;
				},
				static function () use (&$order): string {
					$order[] = 'version';
					return '4.0.0.a1';
				},
				static function (string $version) use (&$order): string {
					$order[] = "from:{$version}";
					return '4.0';
				},
				static function (string $family) use (&$order): bool {
					$order[] = "replace:{$family}";
					return TRUE;
				}
			);
			$this->fail('owned 3.2-default config must not skip the 3.3 bridge onto 4.x');
		} catch (RuntimeException $error) {
			$this->assertSame(
				'pfBlockerNG: install the 3.3 bridge before a 4.x family',
				$error->getMessage()
			);
		}
		$this->assertSame(['version', 'from:4.0.0.a1'], $order);
	}

	public function testThreeTwoCanInstallThreeThreeBridge(): void
	{
		$order = [];
		$installed = pfb_install_settings_family_capture_restore(
			static function () use (&$order): string {
				$order[] = 'current';
				return '3.2';
			},
			static function (string $family) use (&$order): bool {
				$order[] = "save:{$family}";
				return TRUE;
			},
			static function () use (&$order): string {
				$order[] = 'version';
				return '3.3.2';
			},
			static function (string $version) use (&$order): string {
				$order[] = "from:{$version}";
				return '3.3';
			},
			static function (string $family) use (&$order): bool {
				$order[] = "replace:{$family}";
				return TRUE;
			}
		);
		$this->assertSame('3.3', $installed);
		$this->assertSame(['current', 'version', 'from:3.3.2', 'save:3.2', 'replace:3.3'], $order);
	}

	public function testCaptureAndRestoreFailuresStopBeforeLaterEffects(): void
	{
		$order = [];
		try {
			pfb_install_settings_family_capture_restore(
			static function () use (&$order): string { $order[] = 'current'; return '3.3'; },
			static function () use (&$order): bool { $order[] = 'save'; return FALSE; },
			static fn (): string => '4.0.0',
			static fn (string $version): string => '4.0',
			static function () use (&$order): bool { $order[] = 'replace'; return TRUE; }
			);
			$this->fail('capture/restore must fail closed when source snapshot save fails');
		} catch (RuntimeException $error) {
			$this->assertSame('pfBlockerNG: unable to save source settings family', $error->getMessage());
		}
		$this->assertSame(['current', 'save'], $order);
	}

	public function testTargetResolutionAndRestoreFailuresRollBackToSource(): void
	{
		foreach ([NULL, '4.1'] as $target) {
			$order = [];
			try {
				pfb_install_settings_family_capture_restore(
					static function () use (&$order): string { $order[] = 'current'; return '3.3'; },
					static function (string $family) use (&$order): bool { $order[] = "save:{$family}"; return TRUE; },
					static function () use (&$order): string { $order[] = 'version'; return 'nightly'; },
					static function () use (&$order, $target): ?string { $order[] = 'from-version'; return $target; },
					static function (string $family) use (&$order): bool {
						$order[] = "replace:{$family}";
						return $family === '3.3';
					}
				);
				$this->fail('target failure must restore the saved source and fail closed');
			} catch (RuntimeException $error) {
				$this->assertSame('pfBlockerNG: unable to restore settings family', $error->getMessage());
			}
			$targetRestore = $target === NULL ? [] : ['replace:4.1'];
			$this->assertSame(
				['current', 'version', 'from-version', 'save:3.3', ...$targetRestore, 'replace:3.3'],
				$order
			);
		}
	}

	/**
	 * The installer performs appliance-only migrations and service changes, so a direct include
	 * is destructive/off-appliance. php_strip_whitespace keeps this pin executable-code-only.
	 */
	public function testInstallerUsesCaptureRestoreThenFinalize(): void
	{
		$source = php_strip_whitespace(self::INSTALL);
		$this->assertNotSame('', $source, 'installer source must be readable');
		$capture = strpos($source, 'pfb_install_settings_family_capture_restore();');
		$modes = strpos($source, '$pfb_registry_modes = pfb_registry_section_modes($pfb_registry_sections);');
		$finalize = strpos($source, 'pfb_install_settings_family_finalize($pfb_installed_family);');
		$this->assertNotFalse($capture, 'installer must capture and restore settings before migrations');
		$this->assertNotFalse($modes, 'installer must capture registry modes from the restored settings family');
		$this->assertNotFalse($finalize, 'installer must finalize settings after legacy migration');
		$this->assertLessThan($modes, $capture, 'target settings must be restored before registry modes are captured');
		$this->assertLessThan($finalize, $modes, 'registry modes must be captured before migrations mutate sections');
	}
}
