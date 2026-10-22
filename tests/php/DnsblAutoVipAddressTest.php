<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_auto_vip_address() (issue #3565): the address "Create VIPs automatically" uses for a family.
 * A VIP the package already created (descr starting pfB_AUTO_VIP_v4/_v6, pfb_find_marked_vip) keeps its
 * own address, exactly as pfb_manage_dnsbl_vip reuses it; a family without one gets the picker's first free
 * candidate. VIP rows are listed as pfSense lists them: config virtualip/vip plus get_configured_vip_list().
 */
#[CoversFunction('pfb_dnsbl_auto_vip_address')]
final class DnsblAutoVipAddressTest extends TestCase
{
	private const V4_FIRST = '172.16.53.53';
	private const V4_SECOND = '192.168.53.53';
	private const V6 = 'fd00:53:53:53:53:53:53:53';

	private mixed $savedConfig;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_vip_list'], $GLOBALS['pfb_test_configured_subnets']);
	}

	protected function tearDown(): void
	{
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		unset($GLOBALS['pfb_test_vip_list'], $GLOBALS['pfb_test_configured_subnets']);
	}

	/** @param list<array<string,string>> $rows virtualip/vip rows; every row with a subnet is also listed. */
	private static function seedVips(array $rows): void
	{
		config_set_path('virtualip/vip', $rows);
		$GLOBALS['pfb_test_vip_list'] = [];
		foreach ($rows as $row) {
			if (isset($row['subnet'])) {
				$GLOBALS['pfb_test_vip_list']["_vip{$row['uniqid']}"] = $row['subnet'];
			}
		}
	}

	/** @return array<string,string> */
	private static function row(string $uniqid, string $subnet, string $descr): array
	{
		return ['mode' => 'ipalias', 'interface' => 'lo0', 'subnet' => $subnet, 'descr' => $descr, 'uniqid' => $uniqid];
	}

	public function testMarkedV4VipAtALaterCandidateKeepsItsOwnAddress(): void
	{
		// Given: without a VIP the address is the first candidate.
		$this->assertSame(self::V4_FIRST, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'), 'Pre-condition: first candidate');

		// When: the package's own v4 VIP sits at the second candidate.
		self::seedVips([self::row('own4', self::V4_SECOND, PFB_AUTO_VIP_DESCR_V4)]);

		// Then: its own address, not the picker's first free candidate.
		$this->assertSame(self::V4_SECOND, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'));
	}

	public function testMarkedV6VipAtTheOnlyCandidateKeepsItsOwnAddress(): void
	{
		// Given: the package's own v6 VIP holds the single ULA candidate, so the picker has nothing free.
		self::seedVips([self::row('own6', self::V6, PFB_AUTO_VIP_DESCR_V6)]);
		$this->assertNull(pfb_pick_free_dnsbl_vip(AF_INET6, 'lo0'), 'Pre-condition: the picker counts the VIP as taken');

		// Then: the family is provisioned at that VIP's address.
		$this->assertSame(self::V6, pfb_dnsbl_auto_vip_address(AF_INET6, 'lo0'));
	}

	public function testWithoutAMarkedVipTheAddressIsThePickersChoice(): void
	{
		// Given: a user's VIP holds the first candidate.
		self::seedVips([self::row('user1', self::V4_FIRST, 'web server')]);

		// Then: the picker's next free candidate.
		$this->assertSame(self::V4_SECOND, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'));
	}

	public function testAMarkedVipOfTheOtherFamilyDoesNotCount(): void
	{
		// Given: only the v6 marked VIP exists, at an address that is no v4 candidate.
		self::seedVips([self::row('own6', self::V6, PFB_AUTO_VIP_DESCR_V6)]);
		$this->assertSame(self::V4_FIRST, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'), 'v4 ignores the v6 marked VIP');

		// Given: only the v4 marked VIP exists.
		self::seedVips([self::row('own4', self::V4_SECOND, PFB_AUTO_VIP_DESCR_V4)]);
		$this->assertSame(self::V6, pfb_dnsbl_auto_vip_address(AF_INET6, 'lo0'), 'v6 ignores the v4 marked VIP');
	}

	public function testBothMarkedVipsEachKeepTheirOwnFamilysAddress(): void
	{
		self::seedVips([
			self::row('own6', self::V6, PFB_AUTO_VIP_DESCR_V6),
			self::row('own4', self::V4_SECOND, PFB_AUTO_VIP_DESCR_V4),
		]);

		$this->assertSame(self::V4_SECOND, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'));
		$this->assertSame(self::V6, pfb_dnsbl_auto_vip_address(AF_INET6, 'lo0'));
	}

	public function testMarkedVipWithoutASubnetGivesAnEmptyAddressNotNull(): void
	{
		// A marked row without 'subnet' still provisions the family (pfb_manage_dnsbl_vip reuses it), so
		// the result is '' and the page does not treat the family as exhausted.
		self::seedVips([['mode' => 'ipalias', 'interface' => 'lo0', 'descr' => PFB_AUTO_VIP_DESCR_V4, 'uniqid' => 'own4']]);

		$this->assertSame('', pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'));
	}

	/** @return array<string, array{string, string}> descr => the address it gives with the VIP at the second candidate */
	public static function markerPlacements(): array
	{
		return [
			'the marker starts the descr: marked, as for the manager' => [PFB_AUTO_VIP_DESCR_V4 . ' old', self::V4_SECOND],
			'the marker inside the descr: a user VIP, so the picker' => ['old ' . PFB_AUTO_VIP_DESCR_V4, self::V4_FIRST],
		];
	}

	#[DataProvider('markerPlacements')]
	public function testOnlyADescrStartingWithTheMarkerIsTheFamilysOwnVip(string $descr, string $expected): void
	{
		self::seedVips([self::row('vip1', self::V4_SECOND, $descr)]);

		$this->assertSame($expected, pfb_dnsbl_auto_vip_address(AF_INET, 'lo0'), 'descr ' . var_export($descr, TRUE));
	}
}
