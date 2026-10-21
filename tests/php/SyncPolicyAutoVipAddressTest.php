<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * issue #3540 — the address of a node's auto-created DNSBL VIP syncs as policy (pfb_dnsvip_auto4/6),
 * so a policy receiver provisions its own VIP at it. The VIP ids (pfb_dnsvip4/6) and the auto-create
 * toggle name this node's own objects and never leave it.
 */
#[CoversFunction('pfb_cfg_registry')]
#[CoversFunction('pfb_sync_policy_projection')]
#[CoversFunction('pfb_sync_policy_merge')]
final class SyncPolicyAutoVipAddressTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const SECTION = 'pfblockerngdnsblsettings';

	/**
	 * @param array<string,string> $keys the settings leaves of config/0
	 * @return array<string,mixed>
	 */
	private static function settings(array $keys): array
	{
		return [self::SECTION => ['config' => [0 => $keys]]];
	}

	/** @return array<string,array{0:string,1:string}> */
	public static function registryClasses(): array
	{
		return [
			'v4 address is policy'     => ['dnsbl/pfb_dnsvip_auto4', 'policy'],
			'v6 address is policy'     => ['dnsbl/pfb_dnsvip_auto6', 'policy'],
			'v4 VIP id stays local'    => ['dnsbl/pfb_dnsvip4', 'local'],
			'v6 VIP id stays local'    => ['dnsbl/pfb_dnsvip6', 'local'],
			'auto-create stays local'  => ['dnsbl/pfb_dnsvip_auto', 'local'],
		];
	}

	#[DataProvider('registryClasses')]
	public function testRegistryClassifiesTheAddressAsPolicyAndTheVipIdsAsLocal(string $key, string $expected): void
	{
		$registry = pfb_cfg_registry();

		$this->assertArrayHasKey($key, $registry, "{$key} must be registered");
		$this->assertSame($expected, $registry[$key]['sync'] ?? NULL, "{$key} must sync as {$expected}");
	}

	public function testProjectionListsTheSyncedAddressesAndNeverTheVipIds(): void
	{
		$sections = self::settings([
			'pfb_dnsvip4' => '_vipLOCAL4', 'pfb_dnsvip_auto4' => '192.168.53.53',
			'pfb_dnsvip6' => '_vipLOCAL6', 'pfb_dnsvip_auto6' => 'fd00:53:53:53:53:53:53:53',
		]);

		$projection = $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_projection($sections));

		$this->assertSame([
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto4' => '192.168.53.53',
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto6' => 'fd00:53:53:53:53:53:53:53',
		], $projection);
	}

	public function testMergeStoresTheIncomingAddressAndKeepsTheReceiversOwnVipId(): void
	{
		// GIVEN a receiver with its own VIP id and no synced address, and a sender that also names its own VIP id
		$current  = self::settings(['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vipRECEIVER']);
		$incoming = self::settings(['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vipSENDER', 'pfb_dnsvip_auto4' => '192.168.53.53']);

		// WHEN the receiver merges the sender's policy
		$out = $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_merge($incoming, $current));

		// THEN the address is stored and the receiver's VIP id is untouched
		$map = $out[self::SECTION]['config'][0];
		$this->assertSame('192.168.53.53', $map['pfb_dnsvip_auto4'] ?? NULL, 'the sender\'s address must be stored');
		$this->assertSame('_vipRECEIVER', $map['pfb_dnsvip4'] ?? NULL, 'the receiver\'s own VIP id must be kept');
		$this->assertEqualsCanonicalizing(['pfb_dnsbl', 'pfb_dnsvip4', 'pfb_dnsvip_auto4'], array_keys($map));
	}

	public function testMergeFromAnOlderSenderThatLacksTheAddressDeletesTheStoredAddress(): void
	{
		// GIVEN a receiver holding a synced address, and a sender without the key (a release before #3540)
		$current  = self::settings(['pfb_dnsbl' => 'on', 'pfb_dnsvip4' => '_vipRECEIVER', 'pfb_dnsvip_auto4' => '192.168.53.53']);
		$incoming = self::settings(['pfb_dnsbl' => 'on']);

		// WHEN the receiver merges the sender's policy
		$out = $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_merge($incoming, $current));

		// THEN the stale address is gone, so the receiver picks its own as a standalone node does; its VIP id stays
		$map = $out[self::SECTION]['config'][0];
		$this->assertArrayNotHasKey('pfb_dnsvip_auto4', $map, 'a policy key the sender no longer has must be deleted');
		$this->assertSame('_vipRECEIVER', $map['pfb_dnsvip4'] ?? NULL, 'the receiver\'s own VIP id must be kept');
		$this->assertEqualsCanonicalizing(['pfb_dnsbl', 'pfb_dnsvip4'], array_keys($map));
	}
}
