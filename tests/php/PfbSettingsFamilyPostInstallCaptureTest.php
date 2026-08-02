<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbSettingsFamilyPostInstallCaptureTest extends TestCase
{
	private const INSTALL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';

	public function testPostInstallCapturesSourceBeforeTargetRestoreAndMigrations(): void
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
			['current', 'save:3.2', 'version', 'from:4.0.0', 'replace:4.0', 'migrations', 'record:4.0'],
			$order
		);
	}

	public function testCaptureAndRestoreFailuresStopBeforeLaterEffects(): void
	{
		$order = [];
		try {
			pfb_install_settings_family_capture_restore(
			static function () use (&$order): string { $order[] = 'current'; return '3.2'; },
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

	/**
	 * The installer performs appliance-only migrations and service changes, so a direct include
	 * is destructive/off-appliance. php_strip_whitespace keeps this pin executable-code-only.
	 */
	public function testInstallerUsesCaptureRestoreThenFinalize(): void
	{
		$source = php_strip_whitespace(self::INSTALL);
		$this->assertNotSame('', $source, 'installer source must be readable');
		$capture = strpos($source, 'pfb_install_settings_family_capture_restore();');
		$finalize = strpos($source, 'pfb_install_settings_family_finalize($pfb_installed_family);');
		$this->assertNotFalse($capture, 'installer must capture/restore settings before migrations');
		$this->assertNotFalse($finalize, 'installer must finalize settings after legacy migration');
		$this->assertLessThan($finalize, $capture);
	}
}
