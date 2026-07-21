<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Public-seam contract for the structural PfbConfig registry.
 *
 * These tests deliberately use only PfbConfig's named structural methods. A
 * structural root is never reached through a raw config path by a caller.
 */
final class StructuralRegistryTest extends TestCase
{
	private const FEED_PATH = 'installedpackages/pfblockerngfeedmodel/config/0';
	private const POLICY_PATH = 'installedpackages/pfblockernggrouppolicy/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	/**
	 * Absent writable roots materialize the complete v1 defaults; the legacy
	 * names are read-only snapshots and are empty when their source is absent.
	 */
	public function testAbsentRootsReturnV1DefaultsAndEmptySnapshots(): void
	{
		$feed_model = PfbConfig::readStructure('feed_model');
		$group_policy = PfbConfig::readStructure('group_policy');

		$this->assertSame(
			['schema_version', 'catalog_revision_seen', 'feeds', 'groups', 'notices', 'provenance'],
			array_keys($feed_model)
		);
		$this->assertSame(1, $feed_model['schema_version']);
		$this->assertIsString($feed_model['catalog_revision_seen']);
		$this->assertNotSame('', $feed_model['catalog_revision_seen']);
		$this->assertSame([], $feed_model['feeds']);
		$this->assertCount(2, $feed_model['groups']);
		$this->assertSame(
			['Default IP', 'Default DNSBL'],
			array_column($feed_model['groups'], 'name')
		);
		$this->assertSame(['ip', 'dnsbl'], array_column($feed_model['groups'], 'type'));
		$this->assertSame(['false', 'false'], array_column($feed_model['groups'], 'enabled'));

		$this->assertSame(
			['schema_version', 'baseline', 'user_groups', 'policies', 'notices', 'provenance'],
			array_keys($group_policy)
		);
		$this->assertSame(1, $group_policy['schema_version']);
		$this->assertSame('group-policy.dnsbl.baseline', $group_policy['baseline']['id']);
		$this->assertSame('Baseline', $group_policy['baseline']['name']);
		$this->assertSame('true', $group_policy['baseline']['enabled']);
		$this->assertSame([], $group_policy['user_groups']);
		$this->assertSame([], $group_policy['policies']);

		$this->assertSame([], PfbConfig::readStructure('legacy_ipv4_groups'));
		$this->assertSame([], PfbConfig::readStructure('legacy_ipv6_groups'));
		$this->assertSame([], PfbConfig::readStructure('legacy_dnsbl_groups'));
		$this->assertSame([], PfbConfig::readStructure('legacy_feed_patches'));
	}

	/**
	 * Valid v1 data round-trips byte-for-byte through the named seam and never
	 * flushes config.xml; delete removes only the selected writable root.
	 */
	public function testWritableRootReadWriteDeleteIsInMemoryOnly(): void
	{
		$stored = PfbConfig::readStructure('feed_model');
		$stored['groups'][0]['name'] = 'Renamed Default IP';
		config_set_path(self::FEED_PATH, $stored);

		$this->assertSame($stored, PfbConfig::readStructure('feed_model'));
		$candidate = $stored;
		$candidate['groups'][0]['description'] = 'Changed description';
		$this->assertSame([], PfbConfig::writeStructure('feed_model', $candidate));
		$this->assertSame($candidate, config_get_path(self::FEED_PATH));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);

		$this->assertSame([], PfbConfig::deleteStructure('feed_model'));
		$this->assertNull(config_get_path(self::FEED_PATH, null));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	/**
	 * Legacy rows are snapshots, not a second mutable registry. Dynamic feed
	 * patch keys are filtered by their two approved prefixes and retain order.
	 */
	public function testLegacySnapshotsAreFilteredAndReadOnly(): void
	{
		config_set_path('installedpackages/pfblockerngglobal', [
			'feed_alpha' => 'Target',
			'ignore' => 'foreign',
			'feed_alt_HEADER' => 'alt_X',
			'feed' => 'near miss',
			'feed_../bad' => 'path hostile',
			"feed_\0bad" => 'control hostile',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', [
			['aliasname' => 'legacy-ip', 'row' => 'kept'],
		]);

		$this->assertSame(
			[
				'feed_alpha' => 'Target',
				'feed_alt_HEADER' => 'alt_X',
			],
			PfbConfig::readStructure('legacy_feed_patches')
		);
		$this->assertSame(
			[['aliasname' => 'legacy-ip', 'row' => 'kept']],
			PfbConfig::readStructure('legacy_ipv4_groups')
		);

		$this->expectException(InvalidArgumentException::class);
		PfbConfig::writeStructure('legacy_feed_patches', []);
	}

	public function testNestedInvalidPersistedRootFailsClosed(): void
	{
		$stored = PfbConfig::readStructure('feed_model');
		$stored['groups'][0]['enabled'] = ['invalid'];
		config_set_path(self::FEED_PATH, $stored);
		$serialized_before = serialize(config_get_path(self::FEED_PATH));

		$this->expectException(PfbRegistryException::class);
		try {
			PfbConfig::readStructure('feed_model');
		} finally {
			$this->assertSame($serialized_before, serialize(config_get_path(self::FEED_PATH)));
		}
	}

	public function testMalformedSiblingBlocksCandidateWriteWithoutMutation(): void
	{
		$feed = PfbConfig::readStructure('feed_model');
		config_set_path(self::FEED_PATH, $feed);
		config_set_path(self::POLICY_PATH, 'malformed sibling');
		$candidate = $feed;
		$candidate['groups'][0]['description'] = 'candidate';

		$diagnostics = PfbConfig::writeStructure('feed_model', $candidate);

		$this->assertNotEmpty($diagnostics);
		$this->assertSame($feed, config_get_path(self::FEED_PATH));
		$this->assertSame('malformed sibling', config_get_path(self::POLICY_PATH));
	}

	/**
	 * Every malformed/newer root fails closed with typed, ordered diagnostics;
	 * rejected values and secrets are not copied into the exception text.
	 */
	#[DataProvider('malformedRootProvider')]
	public function testMalformedOrNewerRootFailsClosed(string $name, mixed $candidate, string $code): void
	{
		$path = $name === 'feed_model' ? self::FEED_PATH : self::POLICY_PATH;
		$sentinel = ['schema_version' => 1, 'sentinel' => 'unchanged'];
		config_set_path($path, $sentinel);
		config_set_path($path, $candidate);
		$serialized_before = serialize(config_get_path($path));

		try {
			PfbConfig::readStructure($name);
			$this->fail('invalid structural root unexpectedly read successfully');
		} catch (PfbRegistryException $exception) {
			$diagnostics = $exception->getDiagnostics();
			$this->assertNotEmpty($diagnostics);
			$this->assertSame($code, $diagnostics[0]['code']);
			$this->assertSame(['code', 'path', 'severity', 'message'], array_keys($diagnostics[0]));
			$this->assertStringNotContainsString('STRUCTURAL_SECRET_CANARY', $exception->getMessage());
			$this->assertStringNotContainsString(
				'STRUCTURAL_SECRET_CANARY',
				json_encode($diagnostics, JSON_THROW_ON_ERROR)
			);
		}

		$this->assertSame($candidate, config_get_path($path));
		$this->assertSame($serialized_before, serialize(config_get_path($path)));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	/**
	 * @return array<string,array{string,mixed,string}>
	 */
	public static function malformedRootProvider(): array
	{
		return [
			'newer feed schema' => ['feed_model', ['schema_version' => 2], 'schema.version'],
			'wrong feed container' => ['feed_model', 'STRUCTURAL_SECRET_CANARY', 'schema.type'],
			'wrong policy version' => ['group_policy', ['schema_version' => '1'], 'schema.type'],
			'newer policy schema' => ['group_policy', ['schema_version' => 99], 'schema.version'],
		];
	}

	/**
	 * Candidate validation is atomic: a bad write returns diagnostics and leaves
	 * the original serialized root untouched.
	 */
	public function testInvalidCandidateWriteDoesNotMutateOrFlush(): void
	{
		$before = PfbConfig::readStructure('feed_model');
		config_set_path(self::FEED_PATH, $before);
		$candidate = $before;
		$candidate['schema_version'] = 2;

		$diagnostics = PfbConfig::writeStructure('feed_model', $candidate);

		$this->assertNotEmpty($diagnostics);
		$this->assertSame('schema.version', $diagnostics[0]['code']);
		$this->assertSame($before, config_get_path(self::FEED_PATH));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testPolicyWriteRunsCompleteBaselineAndCrossRootValidation(): void
	{
		$feed = PfbConfig::readStructure('feed_model');
		$policy = PfbConfig::readStructure('group_policy');
		$before = $policy;
		config_set_path(self::FEED_PATH, $feed);
		config_set_path(self::POLICY_PATH, $policy);
		$policy['baseline']['name'] = 'Not Baseline';
		$diagnostics = PfbConfig::writeStructure('group_policy', $policy);
		$this->assertContains('baseline.invariant', array_column($diagnostics, 'code'));
		$this->assertSame($feed, config_get_path(self::FEED_PATH));
		$this->assertSame($before, config_get_path(self::POLICY_PATH));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testProvenanceRowsAreImmutableAndAppendOnlyAcrossWrites(): void
	{
		$feed = PfbConfig::readStructure('feed_model');
		$feed['provenance'][] = [
			'id' => 'provenance.append_0123456789ab4def8123456789abcdef', 'subject_type' => 'group', 'subject_id' => 'group.ip.default',
			'origin' => 'test', 'event' => 'created', 'catalog_revision' => $feed['catalog_revision_seen'], 'config_revision' => '1',
			'trigger' => 'test', 'source_locator' => 'fixture', 'immutable' => 'true', 'before' => [], 'after' => [],
		];
		$this->assertSame([], PfbConfig::writeStructure('feed_model', $feed));
		$stored = config_get_path(self::FEED_PATH);

		$mutated = $stored;
		$mutated['provenance'][0]['event'] = 'updated';
		$diagnostics = PfbConfig::writeStructure('feed_model', $mutated);
		$this->assertContains('provenance.append', array_column($diagnostics, 'code'));
		$this->assertSame($stored, config_get_path(self::FEED_PATH));

		$deleted = $stored;
		$deleted['provenance'] = [];
		$diagnostics = PfbConfig::writeStructure('feed_model', $deleted);
		$this->assertContains('provenance.append', array_column($diagnostics, 'code'));
		$this->assertSame($stored, config_get_path(self::FEED_PATH));

		$appended = $stored;
		$appended['provenance'][] = [
			'id' => 'provenance.append-two_0123456789ab4def8123456789abcdef', 'subject_type' => 'group', 'subject_id' => 'group.ip.default',
			'origin' => 'test', 'event' => 'updated', 'catalog_revision' => $feed['catalog_revision_seen'], 'config_revision' => '2',
			'trigger' => 'test', 'source_locator' => 'fixture', 'immutable' => 'true', 'before' => [], 'after' => [],
		];
		$this->assertSame([], PfbConfig::writeStructure('feed_model', $appended));
		$this->assertSame($appended, config_get_path(self::FEED_PATH));
	}

	public function testScheduleReferenceAndResolvedNoticeAreValidatedAtGateway(): void
	{
		$feed = PfbConfig::readStructure('feed_model');
		$policy = PfbConfig::readStructure('group_policy');
		$policy['notices'][] = [
			'id' => 'notice.catalog.drift_0123456789ab4def8123456789abcdef', 'code' => 'catalog.drift', 'severity' => 'info',
			'subject_type' => 'catalog', 'subject_id' => 'catalog', 'status' => 'resolved', 'details' => 'redacted', 'resolution' => 'acknowledged',
		];
		$policy['policies'][] = [
			'id' => 'group-policy.dnsbl.invalid_0123456789ab4def8123456789abcdef', 'name' => 'Invalid', 'description' => '', 'enabled' => 'false',
			'audience' => [], 'schedule' => [], 'dnsbl_group_ids' => [], 'bypass_all' => 'false',
			'deny_domains' => [], 'permit_domains' => [], 'deny_regex' => [], 'permit_regex' => [], 'tld_allow' => [], 'wildcard' => ['enabled' => 'false', 'exclusions' => []],
			'tld_blacklist' => [], 'top1m' => ['enabled' => 'false', 'provider' => '', 'count' => 0, 'tld_filters' => []], 'idn' => ['mode' => 'off', 'confusable' => 'off'],
			'cname_validation' => 'false', 'no_aaaa' => [], 'safe_search' => [], 'doh_hostnames' => [], 'default_response' => 'vip', 'default_logging' => 'true',
		];
		config_set_path(self::FEED_PATH, $feed);
		config_set_path(self::POLICY_PATH, $policy);
		try {
			PfbConfig::readStructure('group_policy');
			$this->fail('invalid schedule should have prevented gateway read');
		} catch (PfbRegistryException $exception) {
			$codes = array_column($exception->getDiagnostics(), 'code');
			$this->assertContains('policy.audience', $codes);
			$this->assertContains('field.value', $codes);
			$this->assertSame($policy, config_get_path(self::POLICY_PATH));
		}
	}

	public function testUnknownAndReadOnlyNamesFailClosed(): void
	{
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::readStructure('not_a_registered_structure');
	}

	public function testWritableDeleteRejectsReadOnlySnapshot(): void
	{
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::deleteStructure('legacy_ipv4_groups');
	}
}
