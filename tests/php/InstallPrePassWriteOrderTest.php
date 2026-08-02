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
		$call = strpos($source, 'pfb_install_registry_writeback($pfb_registry_sections);');
		$this->assertNotFalse($call, 'installer must dispatch its registry pass through the writeback seam');
		$this->assertSame(1, substr_count($source, 'pfb_install_registry_writeback($pfb_registry_sections);'));
		$prepass = substr($source, 0, $call);
		$this->assertFalse(str_contains($prepass, 'PfbConfig::writeSectionSystem('), 'system writes must not precede registry pass');
		$this->assertLessThan(strrpos($source, 'return TRUE;'), $call, 'registry writeback must complete before installer return');
	}

	public function testRegistryWritebackSeamFlushesAfterReturnedSectionWrites(): void
	{
		$order = [];
		pfb_install_registry_writeback(
			['installedpackages/pfblockerng' => ['raw' => 'value']],
			static function (array $sections) use (&$order): array {
				$order[] = 'registry-pass';
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
			['registry-pass', 'write-section:installedpackages/pfblockerng', 'write-config:[pfBlockerNG] Save installation settings'],
			$order
		);
	}
}
