<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1772 companion — the migration body's per-key copy used
 * `$pfb['gconfig'][$setting] ?: ''`, which (a) emits an Undefined-array-key
 * warning for every key the legacy section does not hold and (b) migrates a
 * stored '0' as '' (the empty('0') falsiness class, issue #1787/#1792).
 * Same extraction oracle as InstallGeneralToIpMigrationTest.
 */
#[CoversNothing]
final class InstallGeneralToIpMigrationZeroTest extends TestCase
{
	private ?array $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/InstallGeneralToIpMigrationTest.php';
		InstallGeneralToIpMigrationTest::setUpBeforeClass();
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? null;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
	}

	public function testZeroValuedLegacySettingMigratesAsZeroWithoutWarnings(): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => [0 => [
						'settings_family' => 'v4',
						'killstates'      => '0',
					]],
				],
			],
		];

		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		});
		try {
			pfb_install_oracle_gen_to_ip_region();
		} finally {
			restore_error_handler();
		}

		$ip = $GLOBALS['config']['installedpackages']['pfblockerngipsettings']['config'][0] ?? [];
		$this->assertSame('0', $ip['killstates'] ?? null,
			"a stored '0' is the operator's value -- it must migrate as '0', never collapse to ''");
		$undefined = array_values(array_filter($warnings,
			static fn (string $w): bool => str_contains($w, 'Undefined array key')));
		$this->assertSame([], $undefined,
			"the per-key copy must not emit Undefined-array-key warnings for keys the legacy section lacks, got:\n"
			. implode("\n", $undefined));
	}
}
