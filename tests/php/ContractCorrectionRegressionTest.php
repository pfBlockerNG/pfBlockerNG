<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ContractCorrectionRegressionTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	public function testDnsblModeBelongsToDnsblMembershipOnly(): void
	{
		[$feedModel, $policy, $catalog] = $this->graph();
		$dnsbl = $this->runtimeFeed($catalog, 'dnsbl', 'feed-instance.dnsbl.mode_0123456789ab4def8123456789abcdef');
		$feedModel['feeds'][] = $dnsbl;
		$feedModel['groups'][1]['memberships'][] = [
			'feed_id' => $dnsbl['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [],
			'dnsbl_mode' => 'deny',
		];
		$this->assertSame([], PfbRegistry::validateGraph($feedModel, $policy, $catalog));

		foreach (['deny', 'permit'] as $mode) {
			$feedModel['groups'][1]['memberships'][0]['dnsbl_mode'] = $mode;
			$this->assertSame([], PfbRegistry::validateGraph($feedModel, $policy, $catalog));
		}
		foreach ([NULL, 'invalid'] as $mode) {
			$membership = $feedModel['groups'][1]['memberships'][0];
			if ($mode === NULL) unset($membership['dnsbl_mode']); else $membership['dnsbl_mode'] = $mode;
			$feedModel['groups'][1]['memberships'][0] = $membership;
			$codes = array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code');
			$this->assertContains('membership.dnsbl_mode', $codes);
		}

		$feedModel['groups'][1]['memberships'][0]['dnsbl_mode'] = 'deny';
		$feedModel['feeds'][0]['dnsbl_mode'] = 'deny';
		$codes = array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
		$this->assertContains('feed.dnsbl_mode', $codes);

		$ip = $this->runtimeFeed($catalog, 'ip', 'feed-instance.ip.mode_0123456789ab4def8123456789abcdef', ['family' => 'ipv4']);
		$feedModel['feeds'] = [$ip];
		$feedModel['groups'][0]['memberships'][] = [
			'feed_id' => $ip['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => [], 'dnsbl_mode' => 'deny',
		];
		$codes = array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code');
		$this->assertContains('field.unknown', $codes);
		$this->assertNotContains('membership.dnsbl_mode', $codes);
	}

	public function testLegacyProjectionRetainsAlternateWhenCatalogOrderIsReversed(): void
	{
		$catalog = $this->catalog();
		$alternate = array_splice($catalog['feeds'], 1, 1)[0];
		array_unshift($catalog['feeds'], $alternate);
		$legacy = PfbRegistry::legacyCatalog($catalog);
		$primary = $legacy['ipv4']['PRI1']['feeds'][0];
		$this->assertSame('Abuse_Feodo_C2', $primary['header']);
		$this->assertContains('Abuse_Feodo_C2_med', array_column($primary['alternate'], 'header'));
	}

	public function testMalformedBracketUrlsFailClosedWithoutWarningsOrSecrets(): void
	{
		$catalog = $this->catalog();
		$catalog['feeds'][0]['latest_url'] = 'http://[bad';
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			$catalogDiagnostics = PfbRegistry::validateCatalog($catalog);
			[$feedModel, $policy, $validCatalog] = $this->graph();
			$feed = $this->runtimeFeed($validCatalog, 'ip', 'feed-instance.ip.bad-url_0123456789ab4def8123456789abcdef', [
				'family' => 'ipv4', 'custom_url' => 'http://[bad', 'provenance' => [
					'kind' => 'custom', 'catalog_feed_id' => '', 'origin_category_id' => '', 'legacy_rows' => [],
				], 'url' => '',
			]);
			$feedModel['feeds'][] = $feed;
			$runtimeDiagnostics = PfbRegistry::validateGraph($feedModel, $policy, $validCatalog);
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings);
		$this->assertContains('url.invalid', array_column($catalogDiagnostics, 'code'));
		$this->assertContains('url.invalid', array_column($runtimeDiagnostics, 'code'));
		$this->assertStringNotContainsString('URL_SECRET', json_encode($catalogDiagnostics, JSON_THROW_ON_ERROR));
		$this->assertStringNotContainsString('URL_SECRET', json_encode($runtimeDiagnostics, JSON_THROW_ON_ERROR));
	}

	public function testMalformedNativeInventoryIsTypedAndAtomic(): void
	{
		$GLOBALS['config'] = [
			'aliases' => ['alias' => 'NATIVE_SECRET'],
			'schedules' => ['schedule' => 'NATIVE_SECRET'],
		];
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			[$feedModel, $policy, $catalog] = $this->graph();
			$policy['user_groups'][] = [
				'id' => 'user-group.native_0123456789ab4def8123456789abcdef', 'name' => 'Native refs', 'description' => '',
				'selectors' => [['type' => 'alias', 'value' => 'native-alias']],
			];
			$policy['policies'][] = $this->policy('native-schedule', 'user-group.native_0123456789ab4def8123456789abcdef');
			$before = serialize($policy);
			$diagnostics = PfbConfig::writeStructure('group_policy', $policy);
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings);
		$this->assertNotEmpty($diagnostics);
		foreach ($diagnostics as $diagnostic) {
			$this->assertSame(['code', 'path', 'severity', 'message'], array_keys($diagnostic));
			$this->assertStringNotContainsString('NATIVE_SECRET', json_encode($diagnostic, JSON_THROW_ON_ERROR));
		}
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertNull(config_get_path('installedpackages/pfblockernggrouppolicy/config/0', NULL));
		$this->assertSame($before, serialize($policy));

		config_set_path('installedpackages/pfblockernggrouppolicy/config/0', $policy);
		$configBefore = serialize(config_get_path('installedpackages/pfblockernggrouppolicy/config/0'));
		try {
			PfbConfig::readStructure('group_policy');
			$this->fail('malformed native references unexpectedly read successfully');
		} catch (PfbRegistryException $exception) {
			$this->assertNotEmpty($exception->getDiagnostics());
		} finally {
			$this->assertSame($configBefore, serialize(config_get_path('installedpackages/pfblockernggrouppolicy/config/0')));
		}
	}

	public function testSuppressionPrefixUsesEffectiveIpFamily(): void
	{
		foreach ([
			'ipv4' => [8, 32, 7, 33],
			'ipv6' => [32, 128, 31, 129],
		] as $family => [$low, $high, $below, $above]) {
			[$feedModel, $policy, $catalog] = $this->graph();
			$feed = $this->runtimeFeed($catalog, 'ip', "feed-instance.ip.{$family}_0123456789ab4def8123456789abcdef", ['family' => $family]);
			$feedModel['feeds'][] = $feed;
			$feedModel['groups'][0]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
			foreach ([$low, $high] as $prefix) {
				$feedModel['groups'][0]['suppression_prefix'] = $prefix;
				$this->assertSame([], PfbRegistry::validateGraph($feedModel, $policy, $catalog));
			}
			foreach ([$below, $above] as $prefix) {
				$feedModel['groups'][0]['suppression_prefix'] = $prefix;
				$this->assertContains('group.suppression', array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code'));
			}
		}

		[$feedModel, $policy, $catalog] = $this->graph();
		$feed = $this->runtimeFeed($catalog, 'ip', 'feed-instance.ip.override_0123456789ab4def8123456789abcdef', ['family' => 'ipv4']);
		$feedModel['feeds'][] = $feed;
		$feedModel['groups'][0]['memberships'][] = ['feed_id' => $feed['id'], 'enabled' => 'true', 'grandfathered_overlap' => 'false', 'legacy_rows' => []];
		$feedModel['groups'][0]['family_override'] = 'ipv6';
		$feedModel['groups'][0]['suppression_prefix'] = 31;
		$this->assertContains('group.suppression', array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code'));
		$feedModel['groups'][0]['suppression_prefix'] = 32;
		$this->assertContains('family.intersection', array_column(PfbRegistry::validateGraph($feedModel, $policy, $catalog), 'code'));
	}

	public function testCatalogFeedCustomUrlOverrideIsValidatedAndEffective(): void
	{
		[$feedModel, $policy, $catalog] = $this->graph();
		$feed = $this->runtimeFeed($catalog, 'ip', 'feed-instance.ip.catalog-override_0123456789ab4def8123456789abcdef', [
			'custom_url' => 'https://override.example.test/list',
		]);
		$feedModel['feeds'] = [$feed];
		$this->assertSame([], PfbRegistry::validateGraph($feedModel, $policy, $catalog));
		$this->assertSame('https://override.example.test/list', PfbRegistry::effectiveUrl($feed));

		$feed['custom_url'] = '';
		$codes = array_column(PfbRegistry::validateGraph(['feeds' => [$feed]] + array_diff_key($feedModel, ['feeds' => TRUE]), $policy, $catalog), 'code');
		$this->assertContains('feed.custom_url.blank', $codes);
		$feed['custom_url'] = 'not-a-url';
		$codes = array_column(PfbRegistry::validateGraph(['feeds' => [$feed]] + array_diff_key($feedModel, ['feeds' => TRUE]), $policy, $catalog), 'code');
		$this->assertContains('url.invalid', $codes);
	}

	public function testWriteBoundaryRejectsCredentialQueryUrlsWithoutPersistence(): void
	{
		foreach (['api_key', 'api-key', 'API_KEY'] as $key) {
			[$feedModel, $policy, $catalog] = $this->graph();
			$GLOBALS['config'] = [];
			$GLOBALS['pfb_test_write_config_calls'] = [];
			$canary = 'LEAK_CANARY';
			$policy['notices'][] = [
				'id' => "notice.secret-{$key}_0123456789ab4def8123456789abcdef", 'code' => 'test.secret', 'severity' => 'error',
				'subject_type' => 'policy', 'subject_id' => $policy['baseline']['id'], 'status' => 'open',
				'details' => "https://example.test/request?{$key}={$canary}", 'resolution' => '',
			];
			$before = serialize($policy);
			$diagnostics = PfbConfig::writeStructure('group_policy', $policy);
			$this->assertContains('notice.secret', array_column($diagnostics, 'code'));
			$this->assertStringNotContainsString($canary, json_encode($diagnostics, JSON_THROW_ON_ERROR));
			$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
			$this->assertNull(config_get_path('installedpackages/pfblockernggrouppolicy/config/0', NULL));
			$this->assertSame($before, serialize($policy));
		}

		[$feedModel, $policy, $catalog] = $this->graph();
		$policy['notices'][] = [
			'id' => 'notice.query-ordinary_0123456789ab4def8123456789abcdef', 'code' => 'test.query', 'severity' => 'info',
			'subject_type' => 'policy', 'subject_id' => $policy['baseline']['id'], 'status' => 'open',
			'details' => 'https://example.test/request?monkey=value', 'resolution' => '',
		];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->assertSame([], PfbConfig::writeStructure('group_policy', $policy));
		$this->assertSame($policy, config_get_path('installedpackages/pfblockernggrouppolicy/config/0'));

		[$feedModel, $policy, $catalog] = $this->graph();
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$canary = 'LEAK_CANARY';
		$query = "https://example.test/request?api_key={$canary}";
		$feedModel['provenance'][] = [
			'id' => 'provenance.secret_0123456789ab4def8123456789abcdef', 'subject_type' => 'group', 'subject_id' => 'group.ip.default',
			'origin' => 'test', 'event' => 'updated', 'catalog_revision' => $catalog['revision'], 'config_revision' => '1',
			'trigger' => 'test', 'source_locator' => $query, 'immutable' => 'true', 'before' => ['url' => $query], 'after' => [],
		];
		$before = serialize($feedModel);
		$diagnostics = PfbConfig::writeStructure('feed_model', $feedModel);
		$this->assertContains('provenance.secret', array_column($diagnostics, 'code'));
		$this->assertStringNotContainsString($canary, json_encode($diagnostics, JSON_THROW_ON_ERROR));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertNull(config_get_path('installedpackages/pfblockerng/config/0', NULL));
		$this->assertSame($before, serialize($feedModel));
	}

	public function testCatalogTransitionRejectsFeedIdentityChurnButAllowsDistinctFeed(): void
	{
		$prior = $this->transitionCatalog();
		$oldFeed = $prior['feeds'][0];
		$candidate = $prior;
		$candidate['categories'][0]['feed_ids'] = ['feed.ip.replacement'];
		$candidate['feeds'][0]['id'] = 'feed.ip.replacement';
		$candidate['tombstones'][] = [
			'id' => $oldFeed['id'], 'kind' => 'feed', 'type' => $oldFeed['type'], 'name' => $oldFeed['name'], 'status' => 'tombstoned',
			'family' => $oldFeed['family'], 'latest_url' => $oldFeed['latest_url'], 'past_urls' => $oldFeed['past_urls'],
			'category_ids' => $oldFeed['category_ids'], 'legacy_locators' => $oldFeed['legacy_locators'],
		];
		$codes = array_column(PfbRegistry::validateCatalog($candidate, $prior), 'code');
		$this->assertContains('transition.identity', $codes);

		$distinct = $candidate;
		$distinct['feeds'][0]['id'] = 'feed.ip.distinct';
		$distinct['feeds'][0]['latest_url'] = 'https://example.test/distinct';
		$distinct['feeds'][0]['legacy_locators'][0]['legacy_category'] = 'DISTINCT';
		$distinct['feeds'][0]['legacy_locators'][0]['legacy_header'] = 'DISTINCT';
		$distinct['categories'][0]['legacy_keys'][0]['key'] = 'DISTINCT';
		$distinct['categories'][0]['feed_ids'] = ['feed.ip.distinct'];
		$this->assertSame([], PfbRegistry::validateCatalog($distinct, $prior));
	}

	public function testCatalogTransitionRejectsIdentityChurnWhenMutableEvidenceChanges(): void
	{
		$prior = $this->transitionCatalog();
		$oldFeed = $prior['feeds'][0];
		$candidate = $prior;
		$candidate['categories'][0]['feed_ids'] = ['feed.ip.replacement'];
		$candidate['feeds'][0]['id'] = 'feed.ip.replacement';
		$candidate['feeds'][0]['name'] = 'Renamed replacement';
		$candidate['feeds'][0]['family'] = 'both';
		$candidate['feeds'][0]['latest_url'] = 'https://example.test/replacement';
		$candidate['feeds'][0]['past_urls'] = ['https://example.test/one'];
		$candidate['tombstones'][] = [
			'id' => $oldFeed['id'], 'kind' => 'feed', 'type' => $oldFeed['type'], 'name' => $oldFeed['name'], 'status' => 'tombstoned',
			'family' => $oldFeed['family'], 'latest_url' => $oldFeed['latest_url'], 'past_urls' => $oldFeed['past_urls'],
			'category_ids' => $oldFeed['category_ids'], 'legacy_locators' => $oldFeed['legacy_locators'],
		];
		$codes = array_column(PfbRegistry::validateCatalog($candidate, $prior), 'code');
		$this->assertContains('transition.identity', $codes);
	}

	public function testPercentDecodedCredentialQueryKeysAreRejectedButMonkeyIsAccepted(): void
	{
		foreach ([
			'https://example.test/request?apikey=LEAK_CANARY',
			'https://example.test/request?apiKey=LEAK_CANARY',
			'https://example.test/request?API.KEY=LEAK_CANARY',
			'https://example.test/request?api+key=LEAK_CANARY',
			'https://example.test/request%3Fapi_key%3DLEAK_CANARY',
			'https://example.test/request%26API%2DKEY%3DLEAK_CANARY',
			'https://example.test/request?API%5FKEY=LEAK_CANARY',
		] as $details) {
			[, $policy, $catalog] = $this->graph();
			$GLOBALS['config'] = [];
			$GLOBALS['pfb_test_write_config_calls'] = [];
			$policy['notices'][] = [
				'id' => 'notice.encoded-secret_0123456789ab4def8123456789abcdef', 'code' => 'test.secret', 'severity' => 'error',
				'subject_type' => 'policy', 'subject_id' => $policy['baseline']['id'], 'status' => 'open', 'details' => $details, 'resolution' => '',
			];
			$diagnostics = PfbConfig::writeStructure('group_policy', $policy);
			$this->assertContains('notice.secret', array_column($diagnostics, 'code'));
			$this->assertStringNotContainsString('LEAK_CANARY', json_encode($diagnostics, JSON_THROW_ON_ERROR));
			$this->assertNull(config_get_path('installedpackages/pfblockernggrouppolicy/config/0', NULL));
		}

		[, $policy] = $this->graph();
		$policy['notices'][] = [
			'id' => 'notice.encoded-monkey_0123456789ab4def8123456789abcdef', 'code' => 'test.query', 'severity' => 'info',
			'subject_type' => 'policy', 'subject_id' => $policy['baseline']['id'], 'status' => 'open',
			'details' => 'https://example.test/request%3Fmonkey=value', 'resolution' => '',
		];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->assertSame([], PfbConfig::writeStructure('group_policy', $policy));
	}

	/** @return array{array<string,mixed>,array<string,mixed>,array<string,mixed>} */
	private function graph(): array
	{
		return [PfbConfig::readStructure('feed_model'), PfbConfig::readStructure('group_policy'), $this->catalog()];
	}

	/** @return array<string,mixed> */
	private function catalog(): array
	{
		return json_decode((string)file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json'), TRUE, 64, JSON_THROW_ON_ERROR);
	}

	/** @return array<string,mixed> */
	private function transitionCatalog(): array
	{
		$catalog = $this->catalog();
		foreach ($catalog['categories'] as $category) {
			if (count($category['feed_ids'] ?? []) !== 1) continue;
			foreach ($catalog['feeds'] as $feed) {
				if (($feed['id'] ?? NULL) !== $category['feed_ids'][0]) continue;
				$catalog['categories'] = [$category];
				$catalog['feeds'] = [$feed];
				$catalog['tombstones'] = [];
				return $catalog;
			}
		}
		$this->fail('catalog fixture has no single-feed category');
	}

	/** @param array<string,mixed> $catalog @param array<string,mixed> $overrides @return array<string,mixed> */
	private function runtimeFeed(array $catalog, string $type, string $id, array $overrides = []): array
	{
		foreach ($catalog['feeds'] as $catalogFeed) {
			if (($catalogFeed['type'] ?? NULL) !== $type) continue;
			$category = $catalogFeed['category_ids'][0] ?? '';
			$feed = [
				'id' => $id, 'type' => $type, 'name' => $catalogFeed['name'], 'alias' => str_replace('.', '_', $id),
				'url' => $catalogFeed['latest_url'], 'parser' => 'auto', 'update_policy' => 'normal',
				'schedule' => ['cadence' => 'never', 'time' => '00:00', 'weekdays' => []],
				'provenance' => ['kind' => 'catalog', 'catalog_feed_id' => $catalogFeed['id'], 'origin_category_id' => $category, 'legacy_rows' => []],
			];
			if (array_key_exists('family', $catalogFeed)) $feed['family'] = $catalogFeed['family'];
			return array_replace($feed, $overrides);
		}
		$this->fail("missing {$type} catalog feed");
	}

	/** @return array<string,mixed> */
	private function policy(string $schedule, string $audience): array
	{
		return [
			'id' => 'group-policy.native_0123456789ab4def8123456789abcdef', 'name' => 'Native refs', 'description' => '', 'enabled' => 'true',
			'audience' => [$audience], 'schedule' => $schedule, 'dnsbl_group_ids' => [], 'bypass_all' => 'true',
			'deny_domains' => [], 'permit_domains' => [], 'deny_regex' => [], 'permit_regex' => [], 'tld_allow' => [],
			'wildcard' => ['enabled' => 'false', 'exclusions' => []], 'tld_blacklist' => [],
			'top1m' => ['enabled' => 'false', 'provider' => '', 'count' => 0, 'tld_filters' => []], 'idn' => ['mode' => 'off', 'confusable' => 'off'],
			'cname_validation' => 'false', 'no_aaaa' => [], 'safe_search' => [], 'doh_hostnames' => [], 'default_response' => 'vip', 'default_logging' => 'true',
		];
	}
}
