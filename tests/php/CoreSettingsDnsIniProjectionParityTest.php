<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4036: freezes, for a matrix of stored configurations, what pfB-DNS gets from each of its two inputs for the noAAAA and
 * Group Policy settings: the [noAAAA] and [GP_Bypass_List] sections today's pfb_unbound_python_ini() writes, and the `settings/dns`
 * fields the settings adapter projects for Core (pfb_core_dns_settings()). The fixture tests/core/fixtures/dns_ini_projection_parity.json
 * holds both side by side, so a later slice can boot pfB-DNS from either and prove it builds the same noAAAA table and bypass lists.
 */
#[CoversFunction('pfb_unbound_python_ini')]
#[CoversFunction('pfb_core_dns_settings')]
final class CoreSettingsDnsIniProjectionParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/dns_ini_projection_parity.json';
	private const SECTIONS = ['noAAAA', 'GP_Bypass_List'];
	private const FIELDS = ['noAaaa', 'noAaaaList', 'groupPolicy', 'groupPolicyBypassList'];

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $root;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->root = sys_get_temp_dir() . '/pfb_core_ini_projection_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700));
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->root;
		$GLOBALS['pfb']['log'] = "{$this->root}/pfblockerng.log";
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->root);
	}

	/** @return array<string, mixed> */
	private static function doc(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::doc()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	public function testTheFixtureCoversBothSwitchesAndBothListsOnEveryCase(): void
	{
		$doc = self::doc();
		$this->assertSame(1, $doc['schema']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach ($doc['cases'] as $case) {
			$this->assertSame(self::SECTIONS, array_keys($case['ini']), "{$case['id']}: both sections, present or null");
			$this->assertSame(self::FIELDS, array_keys($case['projection']), "{$case['id']}: the four fields");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysIniWriterAndTheAdapterGiveTheFrozenSectionsAndFields(array $case): void
	{
		foreach ($case['values'] as $key => $value) {
			[$alias, $leaf] = explode('/', $key, 2);
			config_set_path(PFB_SECTIONS[$alias] . '/' . $leaf, $value);
		}

		pfb_global();
		pfb_dnsbl_ini_inputs();
		$ini = pfb_unbound_python_ini('enabled', '2026-01-01 00:00:00');
		$projection = pfb_core_dns_settings();

		$sections = [];
		foreach (self::SECTIONS as $section) {
			$sections[$section] = preg_match('/\n\[' . $section . '\]\n((?:[^\[\n][^\n]*\n|\n)*)/', $ini, $m) === 1 ? $m[1] : NULL;
		}
		$this->assertSame($case['ini'], $sections, "{$case['id']}: {$case['description']}\nthe ini sections, from\n{$ini}");
		$this->assertSame($case['projection'], array_intersect_key($projection, array_flip(self::FIELDS)), "{$case['id']}: {$case['description']}\nthe projection");
	}
}
