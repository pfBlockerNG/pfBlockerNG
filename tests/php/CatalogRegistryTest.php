<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_registry.inc';

final class CatalogRegistryTest extends TestCase
{
	private function catalog(): array
	{
		$catalog = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json'), TRUE, 64, JSON_THROW_ON_ERROR);
		$this->assertIsArray($catalog);
		return $catalog;
	}

	public function testShippedCatalogHasNormalizedConservationAndNoLegacyOptionKeys(): void
	{
		$catalog = $this->catalog();
		$this->assertSame([], PfbRegistry::validateCatalog($catalog));
		$this->assertCount(41, $catalog['categories']);
		$this->assertCount(274, $catalog['feeds']);
		$this->assertSame(127, count(array_filter($catalog['feeds'], static fn(array $feed): bool => $feed['type'] === 'ip')));
		$this->assertSame(147, count(array_filter($catalog['feeds'], static fn(array $feed): bool => $feed['type'] === 'dnsbl')));
		$this->assertSame(19, count(array_filter($catalog['feeds'], static fn(array $feed): bool => ($feed['family'] ?? NULL) === 'both')));
		foreach ($catalog['feeds'] as $feed) {
			$this->assertArrayNotHasKey('family', $feed['type'] === 'dnsbl' ? $feed : []);
			foreach ($feed['legacy_locators'] as $locator) {
				foreach (['alternate', 'source_options', 'default_source_option_id', 'preference'] as $forbidden) {
					$this->assertArrayNotHasKey($forbidden, $feed);
					$this->assertArrayNotHasKey($forbidden, $locator);
				}
			}
		}
	}

	public function testLegacyProjectionPreservesLegacyShape(): void
	{
		$legacy = PfbRegistry::legacyCatalog($this->catalog());
		$this->assertSame(['description', 'copyright', 'ipv4', 'ipv6', 'dnsbl'], array_keys($legacy));
		$this->assertSame(['ipv4' => 88, 'ipv6' => 25, 'dnsbl' => 134], [
			'ipv4' => array_sum(array_map(static fn(array $group): int => count($group['feeds']), $legacy['ipv4'])),
			'ipv6' => array_sum(array_map(static fn(array $group): int => count($group['feeds']), $legacy['ipv6'])),
			'dnsbl' => array_sum(array_map(static fn(array $group): int => count($group['feeds']), $legacy['dnsbl'])),
		]);
		$this->assertSame('Abuse_Feodo_C2', $legacy['ipv4']['PRI1']['feeds'][0]['header']);
		$this->assertSame('EasyList', $legacy['dnsbl']['EasyList']['feeds'][0]['header']);
	}

	public function testLegacyProjectionHasOnlyRawCatalogArgument(): void
	{
		$method = new ReflectionMethod(PfbRegistry::class, 'legacyCatalog');
		$this->assertSame(1, $method->getNumberOfParameters());
	}

	/** @param mixed $value */
	#[PHPUnit\Framework\Attributes\DataProvider('legacyLocatorScalarProvider')]
	public function testLegacyProjectionRejectsScalarLocatorCollectionsWithoutWarnings(mixed $value): void
	{
		$catalog = $this->catalog();
		$catalog['feeds'][0]['legacy_locators'] = $value;
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			try {
				PfbRegistry::legacyCatalog($catalog);
				$this->fail('scalar legacy locator collection must be rejected');
			} catch (PfbRegistryException $exception) {
				$this->assertSame('pfBlockerNG catalog validation failed', $exception->getMessage());
				$diagnostics = $exception->getDiagnostics();
			}
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings);
		$this->assertContains([
			'code' => 'feed.locators',
			'path' => 'feeds/0/legacy_locators',
			'severity' => 'error',
			'message' => 'feed must have a non-empty locator list',
		], $diagnostics);
		$this->assertStringNotContainsString('CATALOG_SECRET_CANARY', json_encode($diagnostics, JSON_THROW_ON_ERROR));
	}

	/** @return array<string,array{mixed}> */
	public static function legacyLocatorScalarProvider(): array
	{
		return ['integer' => [42], 'boolean' => [TRUE], 'string' => ['CATALOG_SECRET_CANARY']];
	}

	public function testValidationIsPureTypedOrderedAndSecretSafe(): void
	{
		$candidate = $this->catalog();
		$secret = 'CATALOG_SECRET_CANARY';
		$candidate['feeds'][0]['alternate'] = $secret;
		$candidate['feeds'][0]['category_ids'][] = $candidate['feeds'][0]['category_ids'][0];
		$before = serialize($candidate);
		$diagnostics = PfbRegistry::validateCatalog($candidate);
		$this->assertSame($before, serialize($candidate));
		$this->assertNotEmpty($diagnostics);
		$this->assertSame($diagnostics, PfbRegistry::validateCatalog($candidate));
		foreach ($diagnostics as $diagnostic) {
			$this->assertSame(['code', 'path', 'severity', 'message'], array_keys($diagnostic));
			$this->assertSame('error', $diagnostic['severity']);
			$this->assertStringNotContainsString($secret, json_encode($diagnostic, JSON_THROW_ON_ERROR));
		}
	}

	public function testLoaderRejectsDuplicateJsonObjectKeysWithoutEchoingContents(): void
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb-catalog-');
		$this->assertNotFalse($path);
		file_put_contents($path, '{"schema_version":1,"schema_version":1}');
		try {
			$this->expectException(PfbRegistryException::class);
			PfbRegistry::catalog($path);
		} finally {
			unlink($path);
		}
	}

	public function testTransitionRequiresTombstoneAndRejectsRevival(): void
	{
		$prior = $this->minimalCatalog();
		$removed = $prior;
		$removed['categories'][0]['feed_ids'] = [];
		$removed['feeds'] = [];
		$this->assertContains('transition.tombstone', array_column(PfbRegistry::validateCatalog($removed, $prior), 'code'));
		$removed['tombstones'][] = ['id' => 'feed.ip.one', 'kind' => 'feed', 'type' => 'ip', 'name' => 'One', 'status' => 'tombstoned', 'family' => 'ipv4', 'latest_url' => 'https://example.test/one', 'past_urls' => [], 'category_ids' => ['cat.ip.one'], 'legacy_locators' => $prior['feeds'][0]['legacy_locators'], 'revision' => 'r2', 'reason' => 'retired'];
		$this->assertSame([], PfbRegistry::validateCatalog($removed, $prior));
		$revived = $prior;
		$revived['tombstones'] = $removed['tombstones'];
		$this->assertContains('transition.revive', array_column(PfbRegistry::validateCatalog($revived, $removed), 'code'));
	}

	public function testSkeletalTombstoneIsRejectedAndCompleteCategoryTombstoneIsAccepted(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['tombstones'][] = ['id' => 'cat.ip.one'];
		$codes = array_column(PfbRegistry::validateCatalog($catalog), 'code');
		$this->assertContains('tombstone.status', $codes);
		$this->assertContains('tombstone.domain_type', $codes);

		$complete = $this->minimalCatalog();
		$complete['categories'] = [];
		$complete['feeds'] = [];
		$complete['tombstones'] = [[
			'id' => 'cat.ip.one', 'kind' => 'category', 'type' => 'ip', 'name' => 'One', 'status' => 'tombstoned',
			'legacy_keys' => $catalog['categories'][0]['legacy_keys'], 'feed_ids' => ['feed.ip.one'],
		], [
			'id' => 'feed.ip.one', 'kind' => 'feed', 'type' => 'ip', 'name' => 'One', 'status' => 'tombstoned', 'family' => 'ipv4',
			'latest_url' => 'https://example.test/one', 'past_urls' => [], 'category_ids' => ['cat.ip.one'], 'legacy_locators' => $catalog['feeds'][0]['legacy_locators'],
		]];
		$this->assertSame([], PfbRegistry::validateCatalog($complete));
	}

	public function testCompleteDnsblFeedTombstoneAndAllowedMutableFields(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['categories'][0]['name'] = 'Renamed';
		$catalog['feeds'][0]['name'] = 'Renamed feed';
		$catalog['feeds'][0]['family'] = 'ipv6';
		$catalog['feeds'][0]['status'] = 'suspended';
		$this->assertSame([], PfbRegistry::validateCatalog($catalog, $this->minimalCatalog()));

		$catalog['categories'] = [];
		$catalog['feeds'] = [];
		$catalog['tombstones'] = [[
			'id' => 'feed.dnsbl.one', 'kind' => 'feed', 'type' => 'dnsbl', 'name' => 'DNSBL One', 'status' => 'tombstoned',
			'latest_url' => 'https://example.test/dnsbl', 'past_urls' => [], 'category_ids' => [], 'legacy_locators' => [[
				'role' => 'primary', 'legacy_type' => 'dnsbl', 'legacy_category' => 'ONE', 'legacy_header' => 'ONE', 'legacy_order' => 0,
				'legacy_fields' => ['feed', 'url', 'header'], 'metadata' => [],
			]],
		]];
		$this->assertSame([], PfbRegistry::validateCatalog($catalog));
	}

	/** @param callable(array<string,mixed>):void $mutator */
	#[PHPUnit\Framework\Attributes\DataProvider('tombstoneHostileProvider')]
	public function testTombstoneRetainedCollectionsRequireActiveShapes(callable $mutator): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['categories'] = [];
		$catalog['feeds'] = [];
		$catalog['tombstones'] = [$this->completeFeedTombstone()];
		$mutator($catalog['tombstones'][0]);
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertNotEmpty($diagnostics);
	}

	/** @return array<string,array{callable(array<string,mixed>):void}> */
	public static function tombstoneHostileProvider(): array
	{
		return [
			'locator role' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['role'] = []; }],
			'locator legacy type' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['legacy_type'] = []; }],
			'locator category' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['legacy_category'] = []; }],
			'locator header' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['legacy_header'] = []; }],
			'locator order' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['legacy_order'] = []; }],
			'locator field scalar' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['legacy_fields'][0] = []; }],
			'locator metadata scalar' => [static function (array &$tombstone): void { $tombstone['legacy_locators'][0]['metadata'] = 'hostile'; }],
			'past URL scalar' => [static function (array &$tombstone): void { $tombstone['past_urls'] = [[]]; }],
			'category ref scalar' => [static function (array &$tombstone): void { $tombstone['category_ids'] = [[]]; }],
		];
	}

	public function testCategoryTombstoneRetainedKeysAndRefsRequireFullShapes(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['categories'] = [];
		$catalog['feeds'] = [];
		$catalog['tombstones'] = [[
			'id' => 'cat.ip.one', 'kind' => 'category', 'type' => 'ip', 'name' => 'One', 'status' => 'tombstoned',
			'legacy_keys' => [['type' => [], 'key' => 'ONE']], 'feed_ids' => [[]],
		]];
		$codes = array_column(PfbRegistry::validateCatalog($catalog), 'code');
		$this->assertContains('tombstone.legacy_key', $codes);
		$this->assertContains('tombstone.feed_ref', $codes);
	}

	public function testFormerAlternateMustResolvePrimaryAndFollowLegacyOrder(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['feeds'][0]['legacy_locators'][] = [
			'role' => 'former_alternate', 'legacy_type' => 'ipv4', 'legacy_category' => 'ONE', 'legacy_header' => 'ALT',
			'former_parent_header' => 'MISSING', 'legacy_order' => 1, 'legacy_fields' => ['url', 'header'], 'metadata' => [],
		];
		$this->assertContains('feed.locator.parent', array_column(PfbRegistry::validateCatalog($catalog), 'code'));

		$catalog['feeds'][0]['legacy_locators'][1]['former_parent_header'] = 'ONE';
		$catalog['feeds'][0]['legacy_locators'][1]['legacy_order'] = 0;
		$this->assertContains('feed.locator.order', array_column(PfbRegistry::validateCatalog($catalog), 'code'));
	}

	/** @param callable(array<string,mixed>):void $mutator */
	#[PHPUnit\Framework\Attributes\DataProvider('hostileIdProvider')]
	public function testHostileSemanticIdsAreRejected(callable $mutator, string $code): void
	{
		$catalog = $this->minimalCatalog();
		$mutator($catalog);
		$this->assertContains($code, array_column(PfbRegistry::validateCatalog($catalog), 'code'));
	}

	/** @param callable(array<string,mixed>):void $mutator */
	#[PHPUnit\Framework\Attributes\DataProvider('unknownFieldProvider')]
	public function testUnknownStructuralFieldsAreRejected(callable $mutator, string $expectedPath): void
	{
		$catalog = $this->minimalCatalog();
		$mutator($catalog);
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertNotEmpty(array_filter($diagnostics, static fn(array $diagnostic): bool => $diagnostic['code'] === 'catalog.field.unknown' && $diagnostic['path'] === $expectedPath));
	}

	/** @return array<string,array{callable(array<string,mixed>):void,string}> */
	public static function unknownFieldProvider(): array
	{
		return [
			'root' => [static function (array &$catalog): void { $catalog['hostile'] = TRUE; }, 'catalog/hostile'],
			'category' => [static function (array &$catalog): void { $catalog['categories'][0]['hostile'] = TRUE; }, 'categories/0/hostile'],
			'legacy key' => [static function (array &$catalog): void { $catalog['categories'][0]['legacy_keys'][0]['hostile'] = TRUE; }, 'categories/0/legacy_keys/0/hostile'],
			'feed' => [static function (array &$catalog): void { $catalog['feeds'][0]['hostile'] = TRUE; }, 'feeds/0/hostile'],
			'locator' => [static function (array &$catalog): void { $catalog['feeds'][0]['legacy_locators'][0]['hostile'] = TRUE; }, 'feeds/0/legacy_locators/0/hostile'],
			'metadata' => [static function (array &$catalog): void { $catalog['feeds'][0]['metadata']['hostile'] = TRUE; }, 'feeds/0/metadata/hostile'],
			'legacy root' => [static function (array &$catalog): void { $catalog['legacy_root'] = ['hostile' => TRUE]; }, 'legacy_root/hostile'],
			'tombstone' => [static function (array &$catalog): void { $catalog['tombstones'][] = ['hostile' => TRUE]; }, 'tombstones/0/hostile'],
		];
	}

	#[PHPUnit\Framework\Attributes\DataProvider('textLimitProvider')]
	public function testTextBoundsRejectOnlyLimitPlusOne(int $length, bool $rejects): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['revision'] = str_repeat('r', $length);
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$hasLengthError = (bool) array_filter($diagnostics, static fn(array $diagnostic): bool => $diagnostic['code'] === 'catalog.revision.length');
		$this->assertSame($rejects, $hasLengthError);
	}

	/** @return array<string,array{int,bool}> */
	public static function textLimitProvider(): array
	{
		return ['limit' => [4096, FALSE], 'limit plus one' => [4097, TRUE]];
	}

	public function testCollectionBoundsRejectOverwideRecordsWithoutEchoingValues(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['tombstones'] = array_fill(0, 1025, $this->completeFeedTombstone());
		$catalog['feeds'][0]['past_urls'] = array_fill(0, 257, 'https://example.test/past');
		$catalog['feeds'][0]['metadata'] = array_fill_keys(array_map(static fn(int $index): string => 'k' . $index, range(0, 64)), 'v');
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$codes = array_column($diagnostics, 'code');
		$this->assertContains('catalog.tombstones.limit', $codes);
		$this->assertContains('feed.past_urls.limit', $codes);
		$this->assertContains('feed.metadata.limit', $codes);
		$this->assertStringNotContainsString('example.test', json_encode($diagnostics, JSON_THROW_ON_ERROR));
	}

	public function testTombstoneReferencesAndHistoryRemainTypedAndReciprocal(): void
	{
		$catalog = $this->minimalCatalog();
		$catalog['categories'][0]['feed_ids'] = [];
		$catalog['feeds'] = [];
		$feedTombstone = $this->completeFeedTombstone();
		$catalog['tombstones'] = [$feedTombstone];
		$this->assertSame([], PfbRegistry::validateCatalog($catalog));

		$catalog['tombstones'][0]['category_ids'] = ['cat.dnsbl.wrong'];
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertContains(['code' => 'tombstone.category_ref.type', 'path' => 'tombstones/0/category_ids/0', 'severity' => 'error', 'message' => 'feed tombstone category type conflicts with feed type'], $diagnostics);

		$catalog['tombstones'][0]['category_ids'] = ['cat.ip.missing'];
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertContains(['code' => 'tombstone.category_ref', 'path' => 'tombstones/0/category_ids/0', 'severity' => 'error', 'message' => 'feed tombstone category reference is dangling'], $diagnostics);

		$catalog['tombstones'][0]['category_ids'] = ['cat.ip.one'];
		$catalog['tombstones'][0]['past_urls'] = ['https://example.test/one'];
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertContains(['code' => 'tombstone.latest_history', 'path' => 'tombstones/0/latest_url', 'severity' => 'error', 'message' => 'latest URL must not be in tombstone history'], $diagnostics);
		$catalog['tombstones'][0]['past_urls'][] = 'https://example.test/one';
		$diagnostics = PfbRegistry::validateCatalog($catalog);
		$this->assertContains(['code' => 'tombstone.past_url.duplicate', 'path' => 'tombstones/0/past_urls/1', 'severity' => 'error', 'message' => 'tombstone past URL is duplicated'], $diagnostics);

		$categoryCatalog = $this->minimalCatalog();
		$categoryCatalog['categories'] = [];
		$categoryCatalog['feeds'] = [];
		$categoryCatalog['tombstones'] = [[
			'id' => 'cat.ip.one', 'kind' => 'category', 'type' => 'ip', 'name' => 'One', 'status' => 'tombstoned',
			'legacy_keys' => $this->minimalCatalog()['categories'][0]['legacy_keys'], 'feed_ids' => ['feed.ip.missing'],
		]];
		$diagnostics = PfbRegistry::validateCatalog($categoryCatalog);
		$this->assertContains(['code' => 'tombstone.feed_ref', 'path' => 'tombstones/0/feed_ids/0', 'severity' => 'error', 'message' => 'category tombstone feed reference is dangling'], $diagnostics);
	}

	/** @return array<string,array{callable(array<string,mixed>):void,string}> */
	public static function hostileIdProvider(): array
	{
		$set = static function (string $path, string $value): callable {
			return static function (array &$catalog) use ($path, $value): void {
				$cursor =& $catalog;
				$parts = explode('.', $path);
				$last = array_pop($parts);
				foreach ($parts as $part) $cursor =& $cursor[$part];
				$cursor[$last] = $value;
			};
		};
		$values = ["feed.ip.a\n", 'feed.ip.a..b', 'feed.ip.a-', 'feed.ip.a ', 'feed.ip.a/b', 'feed.ip.A', 'feed.ip.aé', 'feed.ip.' . str_repeat('a', 300)];
		$out = [];
		foreach ($values as $index => $value) $out['feed-' . $index] = [$set('feeds.0.id', $value), 'feed.id'];
		foreach ($values as $index => $value) $out['category-' . $index] = [$set('categories.0.id', str_replace('feed.', 'cat.', $value)), 'category.id'];
		return $out;
	}

	private function completeFeedTombstone(): array
	{
		$feed = $this->minimalCatalog()['feeds'][0];
		return [
			'id' => $feed['id'], 'kind' => 'feed', 'type' => 'ip', 'name' => $feed['name'], 'status' => 'tombstoned', 'family' => $feed['family'],
			'latest_url' => $feed['latest_url'], 'past_urls' => [], 'category_ids' => ['cat.ip.one'], 'legacy_locators' => $feed['legacy_locators'],
		];
	}

	/** @param callable(array<string,mixed>):void $mutator */
	#[PHPUnit\Framework\Attributes\DataProvider('hostileScalarProvider')]
	public function testNonScalarCollectionSlotsAccumulateDiagnosticsWithoutThrowing(callable $mutator, string $expectedCode, string $expectedPath): void
	{
		$catalog = $this->catalog();
		$mutator($catalog);
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool { $warnings[] = $message; return TRUE; });
		try {
			$diagnostics = PfbRegistry::validateCatalog($catalog);
		} finally {
			restore_error_handler();
		}
		$this->assertNotEmpty(array_filter($diagnostics, static fn(array $diagnostic): bool => $diagnostic['code'] === $expectedCode && $diagnostic['path'] === $expectedPath));
		$this->assertSame([], $warnings);
	}

	/** @return array<string,array{callable(array<string,mixed>):void,string,string}> */
	public static function hostileScalarProvider(): array
	{
		$set = static function (string $path, mixed $value): callable {
			return static function (array &$catalog) use ($path, $value): void {
				$cursor =& $catalog;
				$parts = explode('.', $path);
				$last = array_pop($parts);
				foreach ($parts as $part) $cursor =& $cursor[$part];
				$cursor[$last] = $value;
			};
		};
		$entry = static fn(callable $mutator, string $code, string $path): array => [$mutator, $code, $path];
		return [
			'schema array' => $entry($set('schema_version', []), 'catalog.schema', 'schema_version'),
			'schema object' => $entry($set('schema_version', ['x' => 1]), 'catalog.schema', 'schema_version'),
			'revision array' => $entry($set('revision', []), 'catalog.revision', 'revision'),
			'category id array' => $entry($set('categories.0.id', []), 'category.id', 'categories/0/id'),
			'category type array' => $entry($set('categories.0.type', []), 'category.type', 'categories/0/type'),
			'category name array' => $entry($set('categories.0.name', []), 'category.name', 'categories/0/name'),
			'category status array' => $entry($set('categories.0.status', []), 'category.status', 'categories/0/status'),
			'category description array' => $entry($set('categories.0.description', []), 'category.description', 'categories/0/description'),
			'category info array' => $entry($set('categories.0.info', []), 'category.info', 'categories/0/info'),
			'category default action array' => $entry($set('categories.0.legacy_defaults.action', []), 'category.defaults.shape', 'categories/0/legacy_defaults'),
			'category default cron array' => $entry($set('categories.0.legacy_defaults.cron', []), 'category.defaults.shape', 'categories/0/legacy_defaults'),
			'category feed ref array' => $entry($set('categories.0.feed_ids.0', []), 'category.feed_ref', 'categories/0/feed_ids/0'),
			'legacy key type array' => $entry($set('categories.0.legacy_keys.0.type', []), 'category.legacy_key', 'categories/0/legacy_keys/0'),
			'legacy key name array' => $entry($set('categories.0.legacy_keys.0.key', []), 'category.legacy_key', 'categories/0/legacy_keys/0'),
			'legacy index array' => $entry($set('categories.0.legacy_keys.0.legacy_index', []), 'category.legacy_key.index', 'categories/0/legacy_keys/0/legacy_index'),
			'legacy key status array' => $entry($set('categories.0.legacy_keys.0.status', []), 'category.legacy_key.status', 'categories/0/legacy_keys/0/status'),
			'legacy key description array' => $entry($set('categories.0.legacy_keys.0.description', []), 'category.legacy_key.description', 'categories/0/legacy_keys/0/description'),
			'legacy key info array' => $entry($set('categories.0.legacy_keys.0.info', []), 'category.legacy_key.info', 'categories/0/legacy_keys/0/info'),
			'feed id array' => $entry($set('feeds.0.id', []), 'feed.id', 'feeds/0/id'),
			'feed type array' => $entry($set('feeds.0.type', []), 'feed.type', 'feeds/0/type'),
			'feed name array' => $entry($set('feeds.0.name', []), 'feed.name', 'feeds/0/name'),
			'feed status array' => $entry($set('feeds.0.status', []), 'feed.status', 'feeds/0/status'),
			'feed family array' => $entry($set('feeds.0.family', []), 'feed.family', 'feeds/0/family'),
			'feed category ref array' => $entry($set('feeds.0.category_ids.0', []), 'feed.category_ref', 'feeds/0/category_ids/0'),
			'latest URL array' => $entry($set('feeds.0.latest_url', []), 'url.invalid', 'feeds/0/latest_url'),
			'past URL array' => $entry($set('feeds.0.past_urls', [[]]), 'url.invalid', 'feeds/0/past_urls/0'),
			'locator role array' => $entry($set('feeds.0.legacy_locators.0.role', []), 'feed.locator.role', 'feeds/0/legacy_locators/0/role'),
			'locator type array' => $entry($set('feeds.0.legacy_locators.0.legacy_type', []), 'feed.locator.type', 'feeds/0/legacy_locators/0/legacy_type'),
			'locator category array' => $entry($set('feeds.0.legacy_locators.0.legacy_category', []), 'feed.locator.legacy_category', 'feeds/0/legacy_locators/0/legacy_category'),
			'locator header array' => $entry($set('feeds.0.legacy_locators.0.legacy_header', []), 'feed.locator.legacy_header', 'feeds/0/legacy_locators/0/legacy_header'),
			'locator order array' => $entry($set('feeds.0.legacy_locators.0.legacy_order', []), 'feed.locator.order', 'feeds/0/legacy_locators/0/legacy_order'),
			'locator parent array' => $entry($set('feeds.0.legacy_locators.0.former_parent_header', []), 'feed.locator.parent.unexpected', 'feeds/0/legacy_locators/0/former_parent_header'),
			'locator field scalar' => $entry($set('feeds.0.legacy_locators.0.legacy_fields.0', []), 'feed.locator.fields.scalar', 'feeds/0/legacy_locators/0/legacy_fields/0'),
		];
	}

	private function minimalCatalog(): array
	{
		return [
			'schema_version' => 1,
			'revision' => 'r1',
			'categories' => [[
				'id' => 'cat.ip.one', 'type' => 'ip', 'name' => 'One', 'description' => '', 'info' => '', 'status' => 'active',
				'legacy_defaults' => ['action' => 'block', 'cron' => 'Daily'],
				'legacy_keys' => [['type' => 'ipv4', 'key' => 'ONE', 'legacy_index' => 0, 'status' => 'active', 'description' => '', 'info' => '', 'legacy_defaults' => ['action' => 'block', 'cron' => 'Daily']]],
				'feed_ids' => ['feed.ip.one'],
			]],
			'feeds' => [[
				'id' => 'feed.ip.one', 'type' => 'ip', 'name' => 'One', 'status' => 'active', 'family' => 'ipv4', 'category_ids' => ['cat.ip.one'],
				'latest_url' => 'https://example.test/one', 'past_urls' => [], 'metadata' => [],
				'legacy_locators' => [['role' => 'primary', 'legacy_type' => 'ipv4', 'legacy_category' => 'ONE', 'legacy_header' => 'ONE', 'legacy_order' => 0, 'legacy_fields' => ['feed', 'url', 'header'], 'metadata' => ['feed' => 'One']]],
			]],
			'tombstones' => [],
		];
	}
}
