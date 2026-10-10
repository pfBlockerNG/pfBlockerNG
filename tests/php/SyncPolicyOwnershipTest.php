<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3450 — ownership classification of every registry entry
 * (docs/specs/xmlrpc-per-field-sync.md, "Ownership classification").
 *
 * Every pfb_cfg_registry() entry declares exactly one 'sync' => 'policy'|'local' with no
 * default, so a new field cannot inherit a scope silently. The gate logic is a pure helper
 * over a registry-shaped array, so a synthetic registry proves the gate can fail, the same
 * arrangement as CfgRegistryGrandfatherGateTest.
 *
 * The expected local set is the spec table, held in SyncPolicyFixtureTrait. A key that
 * moves between classes changes what leaves the node, so it fails here by name instead of
 * drifting through a registry edit.
 */
#[CoversFunction('pfb_cfg_registry')]
#[CoversFunction('pfb_sync_local_paths')]
final class SyncPolicyOwnershipTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	/**
	 * One message per entry whose 'sync' is not exactly 'policy' or 'local'.
	 *
	 * @param  array<string,array<string,mixed>> $registry
	 * @return list<string>
	 */
	private static function unclassifiedSyncEntries(array $registry): array
	{
		$violations = [];
		foreach ($registry as $key => $entry) {
			$sync = $entry['sync'] ?? NULL;
			if ($sync !== 'policy' && $sync !== 'local') {
				$violations[] = "{$key}: 'sync' is " . (array_key_exists('sync', $entry) ? var_export($sync, TRUE) : 'missing');
			}
		}
		return $violations;
	}

	/** @return list<string> sorted registry keys whose 'sync' equals $class */
	private static function keysClassified(string $class): array
	{
		$keys = [];
		foreach (pfb_cfg_registry() as $key => $entry) {
			if (($entry['sync'] ?? NULL) === $class) {
				$keys[] = $key;
			}
		}
		sort($keys, SORT_STRING);
		return $keys;
	}

	// A1 -- totality over the real registry.
	public function testEveryRegistryEntryDeclaresPolicyOrLocal(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertCount(152, $registry, 'vacuity guard: 132 existing + 20 newly registered entries');

		$this->assertSame([], self::unclassifiedSyncEntries($registry),
			"every pfb_cfg_registry() entry must declare 'sync' => 'policy'|'local'");
	}

	// A2 -- the gate can fail.
	public function testGateFlagsMissingEmptyAndUnknownSyncValues(): void
	{
		$fixture = [
			'gen/policy_ok'  => ['default' => '', 'sync' => 'policy'],
			'gen/local_ok'   => ['default' => '', 'sync' => 'local'],
			'gen/missing'    => ['default' => ''],
			'gen/empty'      => ['default' => '', 'sync' => ''],
			'gen/shared'     => ['default' => '', 'sync' => 'shared'],
			'gen/null'       => ['default' => '', 'sync' => NULL],
			'gen/wrong_case' => ['default' => '', 'sync' => 'Policy'],
		];

		$this->assertSame([
			"gen/missing: 'sync' is missing",
			"gen/empty: 'sync' is ''",
			"gen/shared: 'sync' is 'shared'",
			"gen/null: 'sync' is NULL",
			"gen/wrong_case: 'sync' is 'Policy'",
		], self::unclassifiedSyncEntries($fixture));
	}

	// A3 -- the local set is exactly the spec table.
	public function testLocalKeySetIsExactlyTheSpecifiedSixty(): void
	{
		$expected = self::localRegistryKeys();
		$this->assertCount(60, $expected, 'vacuity guard: the spec local set has 60 keys');
		sort($expected, SORT_STRING);

		$this->assertSame($expected, self::keysClassified('local'),
			'the registry must classify exactly the spec local keys as local');
	}

	// A4 -- policy is everything else, with pinned per-section counts.
	public function testPolicySetIsRegistryMinusLocalWithPinnedCounts(): void
	{
		$registry = array_keys(pfb_cfg_registry());
		$expected = array_values(array_diff($registry, self::localRegistryKeys()));
		sort($expected, SORT_STRING);

		$policy = self::keysClassified('policy');
		$this->assertSame($expected, $policy, 'policy must be exactly the registry minus the local set');
		$this->assertCount(92, $policy);

		$byAlias = [];
		foreach ($policy as $key) {
			$alias = explode('/', $key, 2)[0];
			$byAlias[$alias] = ($byAlias[$alias] ?? 0) + 1;
		}
		ksort($byAlias);
		$this->assertSame(['dnsbl' => 58, 'gen' => 12, 'ip' => 15, 'rep' => 3, 'ss' => 4], $byAlias);
	}

	// A5 -- every credential leaf is local.
	public function testCredentialLeavesAreLocal(): void
	{
		$registry = pfb_cfg_registry();
		foreach (['ip/maxmind_account', 'ip/maxmind_key', 'ip/asn_token', 'dnsbl/top1m_token'] as $key) {
			$this->assertArrayHasKey($key, $registry, "{$key} must be registered");
			$this->assertSame('local', $registry[$key]['sync'] ?? NULL, "{$key} is a credential and must stay on its node");
		}

		$paths = pfb_sync_local_paths();
		$this->assertContains('item/*/username', $paths['section']['pfblockerngblacklist'] ?? []);
		$this->assertContains('item/*/password', $paths['section']['pfblockerngblacklist'] ?? []);
	}

	// A6 -- the deny-list schema for the non-settings sections, exactly.
	public function testLocalPathsSchemaIsExact(): void
	{
		$this->assertSame([
			'row'         => ['srcint', 'script_pre', 'script_post', 'agateway_in', 'agateway_out'],
			'section'     => ['pfblockerngblacklist' => ['item/*/username', 'item/*/password']],
			'policy_only' => ['pfblockerngglobal' => ['feed_']],
		], pfb_sync_local_paths());
	}
}
