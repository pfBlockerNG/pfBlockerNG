<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class InstallPrePassWriteOrderTest extends TestCase
{
	private const INSTALL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';

	/**
	 * install.inc performs appliance-only migrations and service changes, so it cannot be included
	 * safely in the off-appliance PHPUnit process. php_strip_whitespace gives an executable-code
	 * pin without allowing comments/docblocks to satisfy the ordering contract.
	 */
	public function testRegistryPassWritebackRunsBeforeFinalConfigFlush(): void
	{
		$source = php_strip_whitespace(self::INSTALL);
		$this->assertNotSame('', $source, 'installer source must be readable');
		$capture = strpos($source, '$pfb_registry_modes = pfb_registry_section_modes($pfb_registry_sections);');
		$this->assertNotFalse($capture, 'installer must capture registry modes before migrations');
		$restore = strpos($source, 'pfb_install_settings_family_capture_restore();');
		$this->assertNotFalse($restore, 'installer must restore the target settings family');
		$this->assertLessThan($capture, $restore, 'registry modes must describe the restored target settings family');
		$migrations = strpos($source, 'pfb_install_settings_family_finalize($pfb_installed_family);');
		$this->assertNotFalse($migrations, 'installer must run migrations through the settings-family seam');
		$this->assertLessThan($migrations, $capture, 'registry modes must be captured before migrations mutate sections');

		$call = strpos($source, 'pfb_install_registry_writeback($pfb_registry_sections, $pfb_registry_modes);');
		$this->assertNotFalse($call, 'installer must dispatch its registry pass through the writeback seam');
		$this->assertSame(1, substr_count($source,
			'pfb_install_registry_writeback($pfb_registry_sections, $pfb_registry_modes);'));
		$prepass = substr($source, 0, $call);
		$this->assertFalse(str_contains($prepass, 'PfbConfig::writeSectionSystem('), 'system writes must not precede registry pass');
		$this->assertLessThan(strrpos($source, 'return TRUE;'), $call, 'registry writeback must complete before installer return');
	}

	public function testRegistryWritebackSeamFlushesAfterReturnedSectionWrites(): void
	{
		$order = [];
		$modes = ['installedpackages/pfblockerng' => 'NEWCFG'];
		pfb_install_registry_writeback(
			['installedpackages/pfblockerng' => ['raw' => 'value']],
			$modes,
			static function (array $sections, ?array $registry, ?array $received_modes) use (&$order): array {
				$order[] = 'registry-pass:' . $received_modes['installedpackages/pfblockerng'];
				return $sections;
			},
			static function (string $path, array $blob) use (&$order): void {
				$order[] = "write-section:{$path}";
			},
			static function (string $message) use (&$order): void {
				$order[] = "write-config:{$message}";
			}
		);
		$this->assertSame(
			['registry-pass:NEWCFG', 'write-section:installedpackages/pfblockerng', 'write-config:[pfBlockerNG] Save installation settings'],
			$order
		);
	}
}
