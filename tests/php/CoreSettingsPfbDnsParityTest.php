<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4038 (sub-slice 9g): freezes today's reader of the pfB-DNS switch `dns/pfb_dns` as the parity fixture
 * tests/core/fixtures/settings_pfb_dns_parity.json, for the read-only field `pfbDnsEnabled` of Core's `dns` projection.
 *   - A case is a stored value: `php` is today's reader as pfb_dnsbl_active() compares it, PfbConfig::read('dns/pfb_dns') ===
 *     PfbToggle::On; `pfbDnsEnabled` is what the settings adapter answers. go/pfb_core/settings reads it back.
 *   - The adapter's write refuses a changed switch: the DNS page owns it.
 */
#[CoversFunction('pfb_core_dns_settings')]
#[CoversFunction('pfb_dnsbl_active')]
#[CoversFunction('pfb_core_settings_backend')]
final class CoreSettingsPfbDnsParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_pfb_dns_parity.json';
	private const KEY = 'installedpackages/pfblockerngdns/config/0/pfb_dns';

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_pfb_dns_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir("{$this->dir}/db", 0700, TRUE));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
		$GLOBALS['pfb']['core_revision_key'] = "{$this->dir}/db/core_revision.key";
		@pfb_core_revision_key();	// made here: its first creation warns, which the no-warning read below must not see
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::fixture()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		return $reply;
	}

	public function testTheFixtureHoldsTheSwitchesTodaysPageWritesAndTheHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame([1, 'dns', 'pfbDnsEnabled'], [$doc['schema'], $doc['projection'], $doc['field']]);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['absent', 'empty', 'on', 'upper', 'yes', 'leading-space', 'array'] as $id) {
			$this->assertContains($id, $ids, "the coverage row {$id}");
		}
		$this->assertSame(['string', 'number'], array_column($doc['refused'], 'id'));
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysReaderGivesTheFixturesSwitchAndTheAdapterAnswersIt(array $case): void
	{
		if (array_key_exists('stored', $case)) {
			config_set_path(self::KEY, $case['stored']);
		}
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::On;
		$GLOBALS['pfb']['pfb_dns'] = PfbConfig::read('dns/pfb_dns');	// pfb_global()'s read
		$this->assertSame($case['php'], pfb_dnsbl_active(), "{$case['id']}: today's DNSBL-active test with pfBlockerNG and DNSBL on");
		$this->assertSame($case['php'], PfbConfig::read('dns/pfb_dns') === PfbToggle::On, "{$case['id']}: today's reader");

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame($case['pfbDnsEnabled'], $reply['settings']['dns']['pfbDnsEnabled'] ?? NULL, "{$case['id']}: {$case['description']}");
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testTheAdaptersWriteRefusesAChangedSwitchAndWritesNothing(): void
	{
		config_set_path(self::KEY, 'on');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertTrue($read['settings']['dns']['pfbDnsEnabled'] ?? NULL, 'before-state: pfB-DNS on');
		$settings = $read['settings'];
		$settings['dns']['pfbDnsEnabled'] = FALSE;

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([['field' => 'dns.pfbDnsEnabled', 'message' => 'read-only: the DNS page owns it']], $reply['error']['fieldErrors'] ?? NULL);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame($before, $GLOBALS['config'], 'config.xml is unchanged');
	}

	public function testTheAdaptersWriteRefusesAWriteWithoutTheSwitch(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['dns']['pfbDnsEnabled']);
		$refusal = pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings],
			static fn(): array => []);
		$this->assertContains(['field' => 'dns.pfbDnsEnabled', 'message' => 'required'], $refusal['error']['fieldErrors'] ?? [], json_encode($refusal));
	}

	public function testTheRevisionMovesWhenTheSwitchChanges(): void
	{
		$base = $this->read()['revision'];

		config_set_path(self::KEY, 'on');
		$on = $this->read()['revision'];
		$this->assertNotSame($base, $on, 'pfB-DNS turned on moves the revision, so Core reads it again');

		config_set_path(self::KEY, '');
		$this->assertSame($base, $this->read()['revision'], 'turned off moves it back');
	}
}
