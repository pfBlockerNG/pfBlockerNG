<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1772 — the installer's "General Tab -> IP Tab settings" migration
 * (pfblockerng_install.inc) evaled verbatim, InstallGrandfatherChokepointTest's
 * extraction idiom.
 *
 * On a genuinely fresh install the General section holds ONLY the installer's
 * own `settings_family` schema marker (seeded by pfb_settings_family_replace()
 * before this region runs). The `!empty($pfb_gen_section)` gate read that
 * marker as "pre-existing config", fired the migration, and wrote 14
 * blank-string keys into installedpackages/pfblockerngipsettings/config/0 —
 * phantom "migrated" keys a truly fresh install never has (the #1770
 * contamination class; gate must read the pfb_gconfig_operator_view()).
 */
#[CoversNothing]
final class InstallGeneralToIpMigrationTest extends TestCase
{
	private ?array $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_install_oracle_gen_to_ip_region')) {
			return;
		}
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_install.inc');
		}
		// The migration region: from the General-section read through the
		// closing brace of its else-arm.
		if (!preg_match(
			'/(\$pfb_gen_section  = PfbConfig::readSection\(\'installedpackages\/pfblockerng\/config\/0\'\);\n'
			. '.*?'
			. 'else \{\n\tupdate_status\(" no changes required \.\.\. done\.\\\\n"\);\n\}\n)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: General->IP migration region not found');
		}
		eval(
			'function pfb_install_oracle_gen_to_ip_region(): void {'
			. ' global $pfb;'
			. $m[1]
			. ' }'
		);
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? null;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
	}

	private function seedGeneralSection(array $section): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerng' => [
					'config' => [0 => $section],
				],
			],
		];
	}

	private function ipSection(): array
	{
		return $GLOBALS['config']['installedpackages']['pfblockerngipsettings']['config'][0] ?? [];
	}

	public function testMarkerOnlyGeneralSectionDoesNotSeedIpKeys(): void
	{
		// Genuine fresh install: General holds ONLY the installer's marker.
		$this->seedGeneralSection(['settings_family' => 'v4']);

		pfb_install_oracle_gen_to_ip_region();

		$this->assertSame([], $this->ipSection(),
			'a marker-only General section is a FRESH install -- the migration must not seed '
			. 'phantom blank keys into the IP section (issue #1772)');
		$this->assertSame('v4',
			$GLOBALS['config']['installedpackages']['pfblockerng']['config'][0]['settings_family'] ?? null,
			'the installer marker itself must survive untouched');
	}

	public function testRealLegacyGeneralSettingsStillMigrate(): void
	{
		// Genuine v2-era config: operator data present -> migration must still
		// fire, moving the value and leaving the marker in place.
		$this->seedGeneralSection([
			'settings_family' => 'v4',
			'pass_order'      => 'order_1',
			'enable_dup'      => 'on',
		]);

		pfb_install_oracle_gen_to_ip_region();

		$ip = $this->ipSection();
		$this->assertSame('order_1', $ip['pass_order'] ?? null,
			'a real legacy General->IP setting must still migrate');
		$this->assertSame('on', $ip['enable_dup'] ?? null);
		$gen = $GLOBALS['config']['installedpackages']['pfblockerng']['config'][0];
		$this->assertArrayNotHasKey('pass_order', $gen, 'migrated keys must leave the General section');
		$this->assertSame('v4', $gen['settings_family'] ?? null,
			'the installer marker must survive a real migration untouched');
	}

	public function testScheduleSeededGeneralDoesNotPlantBlankIpKeys(): void
	{
		// Current installer order: pfb_schedule_migrate() writes these
		// into General before this region. They are not IP-tab leftovers.
		$this->seedGeneralSection([
			'settings_family' => 'v4',
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '0',
			'pfb_schedule_minute' => '0',
			'skipfeed' => '',
		]);

		pfb_install_oracle_gen_to_ip_region();

		$this->assertSame([], $this->ipSection(),
			'schedule keys in General are not IP leftovers -- do not plant the 14 blank IP keys');
		$gen = $GLOBALS['config']['installedpackages']['pfblockerng']['config'][0];
		$this->assertSame('on', $gen['pfb_scheduled_feed_updates'] ?? null);
		$this->assertSame('v4', $gen['settings_family'] ?? null);
	}
}
