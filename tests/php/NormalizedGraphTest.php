<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Whole-candidate graph contract. The fixture enters through the public
 * PfbRegistry seam; storage paths and validator helpers stay private.
 */
final class NormalizedGraphTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	public function testFreshDefaultRootsFormAValidGraph(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();

		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
	}

	public function testEffectiveUrlUsesOverrideOnlyWhenPresent(): void
	{
		$this->assertSame(
			'https://managed.example.test/feed',
			PfbRegistry::effectiveUrl([
				'url' => 'https://managed.example.test/feed',
			])
		);
		$this->assertSame(
			'https://user.example.test/feed',
			PfbRegistry::effectiveUrl([
				'url' => 'https://managed.example.test/feed',
				'custom_url' => 'https://user.example.test/feed',
			])
		);
		$this->assertSame(
			'https://managed.example.test/feed',
			PfbRegistry::effectiveUrl([
				'url' => 'https://managed.example.test/feed',
				'custom_url' => null,
			])
		);
	}

	public function testDiagnosticsAreTypedDeterministicAndSecretSafe(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$secret = 'STRUCTURAL_SECRET_CANARY';
		$feed_model['schema_version'] = 2;
		$group_policy['baseline']['id'] = 'not-a-baseline-id';
		$feed_model['feeds'][] = [
			'id' => 'not a valid feed id',
			'type' => 'ip',
			'name' => 'Hostile feed',
			'alias' => 'hostile',
			'url' => "https://user:{$secret}@feeds.example.test/list",
			'family' => 'ipv4',
			'parser' => 'auto',
			'update_policy' => 'normal',
			'schedule' => ['cadence' => 'never', 'time' => '00:00', 'weekdays' => []],
			'provenance' => [
				'kind' => 'catalog',
				'catalog_feed_id' => 'feed.ip.example',
				'origin_category_id' => 'cat.ip.example',
				'legacy_rows' => [],
			],
		];

		$first = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$second = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);

		$this->assertNotEmpty($first);
		$this->assertSame($first, $second, 'diagnostics must be stable across identical candidates');
		$this->assertContains('schema.version', array_column($first, 'code'));
		$this->assertContains('baseline.invariant', array_column($first, 'code'));
		foreach ($first as $diagnostic) {
			$this->assertSame(
				['code', 'path', 'severity', 'message'],
				array_keys($diagnostic),
				'diagnostics expose only the typed secret-safe public shape'
			);
			$this->assertNotContains($secret, $diagnostic);
			$this->assertStringNotContainsString($secret, json_encode($diagnostic, JSON_THROW_ON_ERROR));
		}
	}

	public function testTopologyRejectsDuplicateEdgesAndEmptyFamilyIntersection(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed_id = 'feed-instance.ip.example_0123456789ab4def8123456789abcdef';
		$feed_model['feeds'][] = $this->runtimeFeed($feed_id);
		$feed_model['groups'][0]['memberships'] = [
			['feed_id' => $feed_id, 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
			['feed_id' => $feed_id, 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
		];

		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertContains('membership.duplicate', array_column($diagnostics, 'code'));

		$feed_model['groups'][0]['memberships'] = [
			['feed_id' => $feed_id, 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
		];
		$feed_model['groups'][0]['family_override'] = 'ipv6';
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertContains('family.intersection', array_column($diagnostics, 'code'));
	}

	public function testCatalogBackedAndCustomFeedOwnershipAreValidated(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed_model['feeds'][] = $this->runtimeFeed(
			'feed-instance.ip.custom_0123456789ab4def8123456789abcdef',
			[
				'url' => '',
				'custom_url' => 'https://custom.example.test/list',
				'provenance' => [
					'kind' => 'catalog',
					'catalog_feed_id' => '',
					'origin_category_id' => '',
					'legacy_rows' => [],
				],
			]
		);

		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$codes = array_column($diagnostics, 'code');
		$this->assertTrue(
			(bool) array_intersect(['feed.url.ownership', 'field.required', 'provenance.reference'], $codes),
			'custom feeds must not acquire a managed URL or catalog provenance implicitly'
		);
	}

	public function testPolicySelectorNoticeAndProvenanceFailuresAreTyped(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'][] = [
			'id' => 'user-group.clients_0123456789ab4def8123456789abcdef',
			'name' => 'Clients',
			'description' => '',
			'selectors' => [
				['type' => 'address', 'value' => '999.0.0.1'],
				['type' => 'address', 'value' => '999.0.0.1'],
			],
		];
		$group_policy['notices'][] = [
			'id' => 'notice.policy.missing_0123456789ab4def8123456789abcdef',
			'code' => 'reference.dangling',
			'severity' => 'error',
			'subject_type' => 'policy',
			'subject_id' => 'missing-policy',
			'status' => 'resolved',
			'details' => 'redacted',
			'resolution' => '',
		];
		$feed_model['provenance'][] = [
			'id' => 'provenance.missing_0123456789ab4def8123456789abcdef',
			'subject_type' => 'feed',
			'subject_id' => 'missing-feed',
			'origin' => 'migration',
			'event' => 'created',
			'catalog_revision' => $catalog['revision'],
			'config_revision' => '1',
			'trigger' => 'test',
			'source_locator' => 'fixture',
			'before' => [],
			'after' => [],
		];

		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$codes = array_column($diagnostics, 'code');
		$this->assertContains('selector.invalid', $codes);
		$this->assertContains('selector.duplicate', $codes);
		$this->assertContains('provenance.reference', $codes);
		$this->assertContains('notice.resolution', $codes);
	}

	public function testHostileTypesAndUnknownReferencesFailWithoutLeakingInput(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$secret = 'STRUCTURAL_SECRET_CANARY';
		$feed_model['feeds'] = [
			[
				'id' => 'feed-instance.ip.hostile_0123456789ab4def8123456789abcdef',
				'type' => ['ip', $secret],
				'name' => ['not', 'scalar'],
				'alias' => 'hostile',
				'url' => "https://{$secret}@feeds.example.test/list",
				'family' => 'ipv4',
				'parser' => 'auto',
				'update_policy' => 'normal',
				'schedule' => ['cadence' => 'never', 'time' => '00:00', 'weekdays' => []],
				'provenance' => [
					'kind' => 'catalog',
					'catalog_feed_id' => 'feed.ip.missing',
					'origin_category_id' => 'cat.ip.missing',
					'legacy_rows' => [],
				],
			],
		];

		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertNotEmpty($diagnostics);
		foreach ($diagnostics as $diagnostic) {
			$this->assertStringNotContainsString($secret, json_encode($diagnostic, JSON_THROW_ON_ERROR));
		}
		$this->assertContains('field.type', array_column($diagnostics, 'code'));
		$this->assertContains('reference.dangling', array_column($diagnostics, 'code'));
	}

	public function testOwnershipMatrixAllowsManagedCustomAndUnattachedFeeds(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$managed = $this->runtimeFeed('feed-instance.ip.managed_0123456789ab4def8123456789abcdef');
		$custom = $this->runtimeFeed('feed-instance.ip.custom_0123456789ab4def8123456789abcdef', [
			'url' => '',
			'custom_url' => 'https://custom.example.test/list',
			'provenance' => ['kind' => 'custom', 'catalog_feed_id' => '', 'origin_category_id' => '', 'legacy_rows' => []],
		]);
		$unattached = $this->runtimeFeed('feed-instance.ip.unattached_0123456789ab4def8123456789abcdef');
		$feed_model['feeds'] = [$managed, $custom, $unattached];
		$feed_model['groups'][0]['memberships'] = [
			['feed_id' => $managed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
			['feed_id' => $custom['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
		];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
		$this->assertSame('https://custom.example.test/list', PfbRegistry::effectiveUrl($custom));
	}

	public function testBlankOverrideAndOwnershipViolationsHaveSpecificDiagnostics(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.badownership_0123456789ab4def8123456789abcdef', [
			'custom_url' => '',
			'provenance' => ['kind' => 'custom', 'catalog_feed_id' => 'feed.ip.example', 'origin_category_id' => 'cat.ip.example', 'legacy_rows' => []],
		]);
		$feed_model['feeds'] = [$feed];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('feed.custom_url.blank', $codes);
		$this->assertContains('feed.provenance.ownership', $codes);
		$this->assertContains('feed.url.ownership', $codes);
	}

	public function testSelectorsNormalizeAddressesNetworksAndAliasesAndRejectHostBits(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'][] = [
			'id' => 'user-group.clients_0123456789ab4def8123456789abcdef',
			'name' => 'Clients',
			'description' => '',
			'selectors' => [
				['type' => 'address', 'value' => '2001:0DB8::1'],
				['type' => 'network', 'value' => '2001:db8::/64'],
				['type' => 'alias', 'value' => 'trusted_clients'],
			],
		];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => ['trusted_clients' => 'network'], 'schedules' => []]));
		$group_policy['user_groups'][0]['selectors'][1]['value'] = '2001:db8::1/64';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => ['trusted_clients' => 'network'], 'schedules' => []]), 'code');
		$this->assertContains('selector.host_bits', $codes);
	}

	public function testNativeAliasContextIsEphemeralAndTypeChecked(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'][] = [
			'id' => 'user-group.aliases_0123456789ab4def8123456789abcdef',
			'name' => 'Alias selectors', 'description' => '',
			'selectors' => [['type' => 'alias', 'value' => 'trusted_clients']],
		];

		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('reference.context', $codes);
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => [], 'schedules' => []]), 'code');
		$this->assertContains('reference.dangling', $codes);
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => ['trusted_clients' => 'port'], 'schedules' => []]), 'code');
		$this->assertContains('reference.wrong_type', $codes);
		$group_policy['user_groups'][0]['selectors'][0]['value'] = 'pfB_Managed';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => ['pfB_Managed' => 'network'], 'schedules' => []]), 'code');
		$this->assertContains('selector.invalid', $codes);
	}

	public function testNativeScheduleContextIsEphemeralAndReferenceChecked(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'][] = [
			'id' => 'user-group.schedule_0123456789ab4def8123456789abcdef',
			'name' => 'Scheduled clients', 'description' => '',
			'selectors' => [['type' => 'address', 'value' => '192.0.2.10']],
		];
		$group_policy['policies'][] = [
			'id' => 'group-policy.dnsbl.schedule_0123456789ab4def8123456789abcdef',
			'name' => 'Scheduled', 'description' => '', 'enabled' => 'false',
			'audience' => ['user-group.schedule_0123456789ab4def8123456789abcdef'],
			'schedule' => 'office-hours', 'dnsbl_group_ids' => [], 'bypass_all' => 'false',
			'deny_domains' => ['example.test'], 'permit_domains' => [], 'deny_regex' => [], 'permit_regex' => [],
			'tld_allow' => [], 'wildcard' => ['enabled' => 'false', 'exclusions' => []], 'tld_blacklist' => [],
			'top1m' => ['enabled' => 'false', 'provider' => '', 'count' => 0, 'tld_filters' => []],
			'idn' => ['mode' => 'off', 'confusable' => 'off'], 'cname_validation' => 'false', 'no_aaaa' => [],
			'safe_search' => [], 'doh_hostnames' => [], 'default_response' => 'vip', 'default_logging' => 'true',
		];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('reference.context', $codes);
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => [], 'schedules' => []]), 'code');
		$this->assertContains('reference.dangling', $codes);
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog, ['aliases' => [], 'schedules' => ['office-hours' => TRUE]]), 'code');
		$this->assertNotContains('reference.context', $codes);
		$this->assertNotContains('reference.dangling', $codes);
	}

	public function testPolicyBypassAndDecisionLanesAreMutuallyExclusiveAndTyped(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'][] = [
			'id' => 'user-group.clients_0123456789ab4def8123456789abcdef',
			'name' => 'Clients', 'description' => '',
			'selectors' => [['type' => 'address', 'value' => '192.0.2.4']],
		];
		$group_policy['policies'][] = [
			'id' => 'group-policy.dnsbl.clients_0123456789ab4def8123456789abcdef',
			'name' => 'Clients', 'description' => '', 'enabled' => 'false',
			'audience' => ['user-group.clients_0123456789ab4def8123456789abcdef'],
			'schedule' => '', 'dnsbl_group_ids' => [], 'bypass_all' => 'false',
			'deny_domains' => ['example.test'], 'permit_domains' => [], 'deny_regex' => [], 'permit_regex' => [],
			'tld_allow' => [], 'wildcard' => ['enabled' => 'false', 'exclusions' => []], 'tld_blacklist' => [],
			'top1m' => ['enabled' => 'false', 'provider' => '', 'count' => 0, 'tld_filters' => []],
			'idn' => ['mode' => 'off', 'confusable' => 'off'], 'cname_validation' => 'false', 'no_aaaa' => [],
			'safe_search' => [], 'doh_hostnames' => [], 'default_response' => 'vip', 'default_logging' => 'true',
		];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
		$group_policy['policies'][0]['bypass_all'] = 'true';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('policy.bypass.exclusive', $codes);
	}

	public function testDiagnosticsStayBoundedForDeepWideAndControlInput(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'] = array_fill(0, 6000, ['id' => [], 'name' => ['SECRET'], 'selectors' => 'bad']);
		$group_policy['policies'] = [['id' => "bad\0SECRET", 'name' => ['SECRET'], 'enabled' => [], 'audience' => [], 'dnsbl_group_ids' => [], 'bypass_all' => [], 'deny_domains' => [], 'permit_domains' => [], 'deny_regex' => [], 'permit_regex' => [], 'tld_allow' => [], 'wildcard' => [], 'tld_blacklist' => [], 'top1m' => [], 'idn' => [], 'cname_validation' => [], 'no_aaaa' => [], 'safe_search' => [], 'doh_hostnames' => [], 'default_response' => [], 'default_logging' => []]];
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertLessThanOrEqual(1024, count($diagnostics));
		$this->assertStringNotContainsString('SECRET', json_encode($diagnostics, JSON_THROW_ON_ERROR));
	}

	public function testFeedOwnsAcquisitionFieldsAndGroupRejectsThem(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.transport_0123456789ab4def8123456789abcdef', [
			'download_interface' => 'wan', 'request_method' => 'GET', 'request_params' => ['a' => 'b'],
			'headers' => ['Accept: text/plain'], 'credential_ref' => 'cred-feed', 'pre_transform' => 'trim', 'post_transform' => 'none',
		]);
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][0]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'false', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
		$this->assertContains('field.unknown', array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code'));
		$feed_model['groups'][0]['source_interface'] = 'wan';
		$feed_model['groups'][0]['pre_script'] = 'bad';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
	}

	public function testAcquisitionFieldsHaveFeedOwnership(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.owned_0123456789ab4def8123456789abcdef', [
			'source_interface' => 'wan', 'pre_script' => 'pre', 'post_script' => 'post',
		]);
		$feed_model['feeds'] = [$feed];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertNotContains('field.unknown', $codes);

		$feed_model['groups'][0]['source_interface'] = 'wan';
		$feed_model['groups'][0]['pre_script'] = 'pre';
		$feed_model['groups'][0]['post_script'] = 'post';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
	}

	public function testStrictRuntimeIdentityAndDnsblMembershipMode(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed_model['feeds'][] = $this->runtimeFeed('feed.ip.not-runtime');
		$feed_model['feeds'][] = $this->runtimeFeed('feed-instance.ip.badversion_0123456789ab0def7123456789abcdef');
		$dnsbl = $this->runtimeFeed('feed-instance.dnsbl.easylist_0123456789ab4def8123456789abcdef', [
			'type' => 'dnsbl', 'name' => 'EasyList', 'url' => 'https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt',
			'provenance' => ['kind' => 'catalog', 'catalog_feed_id' => 'feed.dnsbl.easylist', 'origin_category_id' => 'cat.dnsbl.easylist', 'legacy_rows' => []],
		]);
		unset($dnsbl['family']);
		$feed_model['feeds'][] = $dnsbl;
		$feed_model['groups'][1]['enabled'] = 'true';
		$feed_model['groups'][1]['memberships'][] = ['feed_id' => $dnsbl['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.value', $codes);
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertContains('feed_model/feeds/1/id', array_column($diagnostics, 'path'));
		$this->assertContains('membership.dnsbl_mode', $codes);
		$feed_model['groups'][0]['memberships'][] = ['feed_id' => 'feed-instance.ip.example_0123456789ab4def8123456789abcdef', 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [], 'dnsbl_mode' => 'deny'];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
	}

	public function testOneFeedMayBeSharedByTwoGroupsWithOrderedDisabledMembership(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.shared_0123456789ab4def8123456789abcdef');
		$feed_model['feeds'] = [$feed];
		$second_group = $feed_model['groups'][0];
		$second_group['id'] = 'group.ip.second_0123456789ab4def8123456789abcdef';
		$second_group['name'] = 'Second IP';
		$second_group['alias'] = 'second_ip';
		$second_group['memberships'] = [];
		$feed_model['groups'][] = $second_group;
		$feed_model['groups'][0]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
		$feed_model['groups'][2]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'false', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
		$feed_model['groups'][2]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [], 'order' => 0];
		$this->assertContains('membership.duplicate', array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code'));
	}

	public function testNewCrossGroupFamilyOverlapNeedsGrandfatheredEvidence(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.cross-group_0123456789ab4def8123456789abcdef', ['family' => 'both']);
		$feed_model['feeds'] = [$feed];
		$second = $feed_model['groups'][0];
		$second['id'] = 'group.ip.cross-group_0123456789ab4def8123456789abcdef';
		$second['name'] = 'Cross Group';
		$second['alias'] = 'cross_group';
		$second['family_override'] = 'ipv6';
		$feed_model['groups'][0]['family_override'] = 'ipv4';
		$feed_model['groups'][0]['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
		]];
		$second['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
		]];
		$feed_model['groups'][] = $second;
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
		$feed_model['groups'][2]['family_override'] = 'ipv4';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('membership.overlap', $codes);

		$feed_model['groups'][2]['memberships'][0]['grandfathered_overlap'] = 'true';
		$feed_model['groups'][2]['memberships'][0]['legacy_rows'] = [['section' => 'legacy', 'group_index' => 0, 'row_index' => 0, 'header' => 'CrossGroup']];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('membership.overlap', $codes);
		$feed_model['groups'][0]['memberships'][0]['grandfathered_overlap'] = 'true';
		$feed_model['groups'][0]['memberships'][0]['legacy_rows'] = [['section' => 'legacy', 'group_index' => 1, 'row_index' => 0, 'header' => 'DefaultGroup']];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
	}

	public function testNewDuplicateAndGrandfatheredIpOverlapAreDistinct(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.overlap_0123456789ab4def8123456789abcdef');
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][0]['memberships'] = [
			['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
			['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []],
		];
		$this->assertContains('membership.duplicate', array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code'));
		$feed_model['groups'][0]['memberships'][1]['grandfathered_overlap'] = 'true';
		$this->assertContains('membership.duplicate', array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code'));
	}

	public function testUserGroupAndPolicyNamesAreCaseInsensitiveUnique(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'] = [
			['id' => 'user-group.one_0123456789ab4def8123456789abcdef', 'name' => 'Clients', 'description' => '', 'selectors' => [['type' => 'address', 'value' => '192.0.2.1']]],
			['id' => 'user-group.two_0123456789ab4def8123456789abcdef', 'name' => 'clients', 'description' => '', 'selectors' => [['type' => 'address', 'value' => '192.0.2.2']]],
		];
		$group_policy['policies'] = [];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('name.duplicate', $codes);
	}

	public function testNoticeAndProvenanceSecretCanariesRemainRedacted(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$secret = 'GRAPH_SECRET_CANARY';
		$group_policy['notices'][] = ['id' => 'notice.feed.secret_0123456789ab4def8123456789abcdef', 'code' => 'feed.error', 'severity' => 'error', 'subject_type' => 'feed', 'subject_id' => 'missing', 'status' => 'resolved', 'details' => "token={$secret}", 'resolution' => ''];
		$feed_model['provenance'][] = ['id' => 'provenance.secret_0123456789ab4def8123456789abcdef', 'subject_type' => 'feed', 'subject_id' => 'missing', 'origin' => 'migration', 'event' => 'created', 'catalog_revision' => $catalog['revision'], 'config_revision' => '1', 'trigger' => 'raw_request', 'source_locator' => 'headers', 'before' => ['authorization' => $secret], 'after' => ['token' => $secret]];
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertNotEmpty($diagnostics);
		$this->assertStringNotContainsString($secret, json_encode($diagnostics, JSON_THROW_ON_ERROR));
		$this->assertContains('notice.resolution', array_column($diagnostics, 'code'));
		$this->assertContains('provenance.secret', array_column($diagnostics, 'code'));
	}

	public function testMembershipAndPolicyTopologyUseOnlyApprovedKeys(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.contract_0123456789ab4def8123456789abcdef');
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][0]['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'true',
			'legacy_rows' => [], 'order' => 0,
		]];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
		$this->assertContains('membership.grandfathered.evidence', $codes);

		$group_policy['user_groups'][] = [
			'id' => 'user-group.contract_0123456789ab4def8123456789abcdef', 'name' => 'Contract', 'description' => '',
			'selectors' => [],
		];
		$group_policy['policies'][] = [
			'id' => 'group-policy.dnsbl.contract_0123456789ab4def8123456789abcdef', 'name' => 'Contract',
			'description' => '', 'enabled' => 'false', 'audience' => [], 'user_group_ids' => [], 'order' => 0,
		];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
		$this->assertContains('policy.audience', $codes);
	}

	public function testMembershipNoticeSubjectUsesGroupAndFeedComposite(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.subject_0123456789ab4def8123456789abcdef');
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][0]['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
		]];
		$group_policy['notices'][] = [
			'id' => 'notice.membership_0123456789ab4def8123456789abcdef', 'code' => 'membership.notice', 'severity' => 'info',
			'subject_type' => 'membership', 'subject_id' => 'group.ip.default|' . $feed['id'], 'status' => 'open', 'details' => 'redacted', 'resolution' => '',
		];
		$this->assertSame([], PfbRegistry::validateGraph($feed_model, $group_policy, $catalog));
	}

	public function testFeedAcquisitionAndPreparedCredentialsAreRejected(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.ip.transport_contract_0123456789ab4def8123456789abcdef', [
			'url' => 'https://user:secret@example.test/list',
			'headers' => ['Authorization: Bearer secret'],
			'credentials' => ['token' => 'secret'],
			'request_params' => ['q' => 'x'],
		]);
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][0]['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
		]];
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertContains('field.unknown', array_column($diagnostics, 'code'));
		$this->assertContains('url.credentials', array_column($diagnostics, 'code'));
		$this->assertStringNotContainsString('secret', json_encode($diagnostics, JSON_THROW_ON_ERROR));
	}

	public function testDnsblMembershipOwnsModeAndGroupShapesAreStrict(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$feed = $this->runtimeFeed('feed-instance.dnsbl.mode_contract_0123456789ab4def8123456789abcdef', [
			'type' => 'dnsbl', 'name' => 'EasyList', 'url' => 'https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt',
			'provenance' => ['kind' => 'catalog', 'catalog_feed_id' => 'feed.dnsbl.easylist', 'origin_category_id' => 'cat.dnsbl.easylist', 'legacy_rows' => []],
		]);
		unset($feed['family']);
		$feed_model['feeds'] = [$feed];
		$feed_model['groups'][1]['memberships'] = [[
			'feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
		]];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('membership.dnsbl_mode', $codes);
		$feed_model['groups'][1]['memberships'][0]['dnsbl_mode'] = 'deny';
		$feed['dnsbl_mode'] = 'deny';
		$feed_model['feeds'][0] = $feed;
		$feed_model['groups'][1]['order'] = 'strict';
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('feed.dnsbl_mode', $codes);
		$this->assertContains('group.order', $codes);
	}

	public function testOversizedGraphContainersAreRejectedWithoutTruncatingAcceptance(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$group_policy['user_groups'] = array_fill(0, 4097, [
			'id' => 'user-group.oversized_0123456789ab4def8123456789abcdef', 'name' => 'Oversized',
			'description' => '', 'selectors' => [],
		]);
		$diagnostics = PfbRegistry::validateGraph($feed_model, $group_policy, $catalog);
		$this->assertContains('graph.list.limit', array_column($diagnostics, 'code'));
	}

	public function testPolicyAudienceRejectsEmptyDraftUserGroup(): void
	{
		[$feed_model, $group_policy, $catalog] = $this->defaultGraph();
		$draftId = 'user-group.draft_0123456789ab4def8123456789abcdef';
		$group_policy['user_groups'][] = ['id' => $draftId, 'name' => 'Draft', 'description' => '', 'selectors' => []];
		$policy = $group_policy['baseline'];
		$policy['id'] = 'group-policy.dnsbl.draft_0123456789ab4def8123456789abcdef';
		$policy['name'] = 'Draft policy';
		$policy['audience'] = [$draftId];
		$group_policy['policies'] = [$policy];
		$codes = array_column(PfbRegistry::validateGraph($feed_model, $group_policy, $catalog), 'code');
		$this->assertContains('policy.audience', $codes);
	}

	/** @return array{array<string,mixed>,array<string,mixed>,array<string,mixed>} */
	private function defaultGraph(): array
	{
		$feed_model = PfbConfig::readStructure('feed_model');
		$group_policy = PfbConfig::readStructure('group_policy');
		$catalog = PfbRegistry::catalog();

		return [$feed_model, $group_policy, $catalog];
	}

	/** @return array<string,mixed> */
	private function catalog(string $revision): array
	{
		return [
			'schema_version' => 1,
			'revision' => $revision,
			'categories' => [[
				'id' => 'cat.ip.example',
				'type' => 'ip',
				'name' => 'Example',
				'description' => '',
				'info' => '',
				'status' => 'active',
				'legacy_keys' => [],
				'feed_ids' => ['feed.ip.example'],
			]],
			'feeds' => [[
				'id' => 'feed.ip.example',
				'type' => 'ip',
				'name' => 'Example',
				'status' => 'active',
				'family' => 'ipv4',
				'category_ids' => ['cat.ip.example'],
				'latest_url' => 'https://feeds.example.test/list',
				'past_urls' => [],
				'legacy_locators' => [],
				'metadata' => [],
			]],
			'tombstones' => [],
		];
	}

	/** @return array<string,mixed> */
	private function runtimeFeed(string $id, array $override = []): array
	{
		return array_replace_recursive([
			'id' => $id,
			'type' => 'ip',
			'name' => 'Example runtime feed',
			'alias' => 'example_runtime',
			'url' => 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
			'family' => 'ipv4',
			'parser' => 'auto',
			'update_policy' => 'normal',
			'schedule' => ['cadence' => 'never', 'time' => '00:00', 'weekdays' => []],
			'provenance' => [
				'kind' => 'catalog',
					'catalog_feed_id' => 'feed.ip.abuse-feodo-c2',
					'origin_category_id' => 'cat.ip.primary-1',
				'legacy_rows' => [],
			],
		], $override);
	}
}
