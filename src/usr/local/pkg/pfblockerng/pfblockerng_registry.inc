<?php

declare(strict_types=1);

/** @internal Normalized immutable catalog and legacy read projection. */
final class PfbRegistryException extends RuntimeException
{
	/** @var list<array{code:string,path:string,severity:string,message:string}> */
	private array $diagnostics;

	/** @param list<array{code:string,path:string,severity:string,message:string}> $diagnostics */
	public function __construct(array $diagnostics)
	{
		$this->diagnostics = $diagnostics;
		parent::__construct('pfBlockerNG catalog validation failed');
	}

	/** @return list<array{code:string,path:string,severity:string,message:string}> */
	public function getDiagnostics(): array
	{
		return $this->diagnostics;
	}
}

final class PfbRegistry
{
	private const MAX_BYTES = 4_000_000;
	private const MAX_CATEGORIES = 128;
	private const MAX_FEEDS = 4096;
	private const MAX_TOMBSTONES = 1024;
	private const MAX_TEXT = 4096;
	private const MAX_CATEGORY_KEYS = 256;
	private const MAX_CATEGORY_FEEDS = 4096;
	private const MAX_FEED_CATEGORIES = 128;
	private const MAX_FEED_LOCATORS = 256;
	private const MAX_FEED_PAST_URLS = 256;
	private const MAX_METADATA_KEYS = 64;
	private const MAX_METADATA_DEPTH = 8;
	private const MAX_GRAPH_ITEMS = 4096;
	private const MAX_GRAPH_MAP_KEYS = 64;
	private const MAX_GRAPH_DEPTH = 8;
	private const MAX_GRAPH_DIAGNOSTICS = 1024;

	/** @return array<string,mixed> */
	public static function catalog(?string $path = NULL): array
	{
		if ($path === NULL) {
			$path = __DIR__ . '/../../www/pfblockerng/pfblockerng_feeds.json';
		}
		if (!is_file($path)) {
			throw new PfbRegistryException([self::diagnostic('catalog.missing', 'catalog', 'catalog file is unavailable')]);
		}
		$size = filesize($path);
		if ($size === FALSE || $size > self::MAX_BYTES) {
			throw new PfbRegistryException([self::diagnostic('catalog.size', 'catalog', 'catalog exceeds parser limit')]);
		}
		$raw = file_get_contents($path);
		if ($raw === FALSE || $raw === '') {
			throw new PfbRegistryException([self::diagnostic('catalog.empty', 'catalog', 'catalog is empty')]);
		}
		if (self::duplicateJsonKey($raw) !== NULL) {
			throw new PfbRegistryException([self::diagnostic('catalog.json.duplicate_key', 'catalog', 'catalog contains duplicate object keys')]);
		}
		try {
			$decoded = json_decode($raw, TRUE, 64, JSON_THROW_ON_ERROR);
		} catch (JsonException $exception) {
			$code = match ($exception->getCode()) {
				JSON_ERROR_UTF8 => 'catalog.json.utf8',
				JSON_ERROR_DEPTH => 'catalog.json.depth',
				default => 'catalog.json',
			};
			throw new PfbRegistryException([self::diagnostic($code, 'catalog', 'catalog JSON is malformed')]);
		}
		if (!is_array($decoded)) {
			throw new PfbRegistryException([self::diagnostic('catalog.type', 'catalog', 'catalog root must be an object')]);
		}
		$diagnostics = self::validateCatalog($decoded);
		if ($diagnostics !== []) throw new PfbRegistryException($diagnostics);
		return $decoded;
	}

	/**
	 * Validate the complete normalized storage graph without changing either
	 * candidate. Diagnostics intentionally contain no input values.
	 *
	 * @return list<array{code:string,path:string,severity:string,message:string}>
	 */
	public static function validateGraph(mixed $feedModel, mixed $groupPolicy, mixed $catalog, ?array $nativeRefs = NULL): array
	{
		$diagnostics = [];
		if (!self::isMap($feedModel)) {
			$diagnostics[] = self::diagnostic('schema.type', 'feed_model', 'feed model must be an object');
			$feedModel = [];
		}
		if (!self::isMap($groupPolicy)) {
			$diagnostics[] = self::diagnostic('schema.type', 'group_policy', 'group policy must be an object');
			$groupPolicy = [];
		}
		if (!self::isMap($catalog)) {
			$diagnostics[] = self::diagnostic('schema.type', 'catalog', 'catalog must be an object');
			$catalog = [];
		}
		self::validateGraphCaps($feedModel, 'feed_model', $diagnostics);
		self::validateGraphCaps($groupPolicy, 'group_policy', $diagnostics);
		self::validateGraphCaps($catalog, 'catalog', $diagnostics);
		self::validateGraphRoot($feedModel, 'feed_model', ['schema_version', 'catalog_revision_seen', 'feeds', 'groups', 'notices', 'provenance'], $diagnostics);
		self::validateGraphRoot($groupPolicy, 'group_policy', ['schema_version', 'baseline', 'user_groups', 'policies', 'notices', 'provenance'], $diagnostics);
		$feedVersion = $feedModel['schema_version'] ?? NULL;
		if (!is_int($feedVersion)) $diagnostics[] = self::diagnostic('schema.type', 'feed_model/schema_version', 'schema version must be an integer');
		elseif ($feedVersion !== 1) $diagnostics[] = self::diagnostic('schema.version', 'feed_model/schema_version', 'schema version must be exactly 1');
		$policyVersion = $groupPolicy['schema_version'] ?? NULL;
		if (!is_int($policyVersion)) $diagnostics[] = self::diagnostic('schema.type', 'group_policy/schema_version', 'schema version must be an integer');
		elseif ($policyVersion !== 1) $diagnostics[] = self::diagnostic('schema.version', 'group_policy/schema_version', 'schema version must be exactly 1');
		if (!is_string($feedModel['catalog_revision_seen'] ?? NULL) || trim((string)$feedModel['catalog_revision_seen']) === '') {
			$diagnostics[] = self::diagnostic('field.required', 'feed_model/catalog_revision_seen', 'catalog revision is required');
		}
		$diagnostics = array_merge($diagnostics, self::validateCatalog($catalog));
		$catalogFeeds = [];
		$catalogCategories = [];
		foreach (self::boundedList($catalog['feeds'] ?? NULL) as $feed) if (self::isMap($feed) && is_string($feed['id'] ?? NULL)) $catalogFeeds[$feed['id']] = $feed;
		foreach (self::boundedList($catalog['categories'] ?? NULL) as $category) if (self::isMap($category) && is_string($category['id'] ?? NULL)) $catalogCategories[$category['id']] = $category;
		$feedIndex = self::validateRuntimeFeeds($feedModel, $catalogFeeds, $catalogCategories, $diagnostics);
		$groupIndex = self::validateRuntimeGroups($feedModel, $feedIndex, $diagnostics);
		self::validateGraphPolicies($groupPolicy, $feedIndex, $groupIndex, $catalogCategories, $catalog, $diagnostics, $nativeRefs);
		self::validateGraphNotices($feedModel['notices'] ?? NULL, 'feed_model/notices', $feedIndex, $groupIndex, $groupPolicy, $diagnostics);
		self::validateGraphNotices($groupPolicy['notices'] ?? NULL, 'group_policy/notices', $feedIndex, $groupIndex, $groupPolicy, $diagnostics);
		self::validateGraphProvenance($feedModel['provenance'] ?? NULL, 'feed_model/provenance', $feedIndex, $groupIndex, $groupPolicy, $catalog, $diagnostics);
		self::validateGraphProvenance($groupPolicy['provenance'] ?? NULL, 'group_policy/provenance', $feedIndex, $groupIndex, $groupPolicy, $catalog, $diagnostics);
		if (count($diagnostics) > self::MAX_GRAPH_DIAGNOSTICS) {
			$diagnostics = array_slice($diagnostics, 0, self::MAX_GRAPH_DIAGNOSTICS - 1);
			$diagnostics[] = self::diagnostic('graph.diagnostics.limit', 'graph', 'diagnostics were bounded');
		}
		return self::sortDiagnostics($diagnostics);
	}

	/** Return custom_url exactly when present, otherwise managed url. */
	public static function effectiveUrl(mixed $feed): string
	{
		if (!is_array($feed)) return '';
		$value = $feed['custom_url'] ?? ($feed['url'] ?? '');
		return is_string($value) ? $value : '';
	}

	/** @param array<string,mixed> $candidate @param array<string,mixed>|null $prior @return list<array{code:string,path:string,severity:string,message:string}> */
	public static function validateCatalog(array $candidate, ?array $prior = NULL): array
	{
		$errors = [];
		self::forbiddenKeys($candidate, 'catalog', $errors);
		self::unknownKeys($candidate, ['schema_version', 'revision', 'legacy_root', 'categories', 'feeds', 'tombstones'], 'catalog', $errors);
		if (array_is_list($candidate)) $errors[] = self::diagnostic('catalog.root', 'catalog', 'catalog root must be an object');
		$schema = $candidate['schema_version'] ?? NULL;
		if (!is_int($schema) || $schema !== 1) $errors[] = self::diagnostic(is_int($schema) && $schema > 1 ? 'catalog.schema.newer' : 'catalog.schema', 'schema_version', 'schema version must be exactly 1');
		if (!is_string($candidate['revision'] ?? NULL) || trim((string)$candidate['revision']) === '') $errors[] = self::diagnostic('catalog.revision', 'revision', 'revision must be non-empty');
		elseif (strlen($candidate['revision']) > self::MAX_TEXT) $errors[] = self::diagnostic('catalog.revision.length', 'revision', 'revision exceeds the maximum length');
		if (array_key_exists('legacy_root', $candidate) && !self::isMap($candidate['legacy_root'])) $errors[] = self::diagnostic('catalog.legacy_root', 'legacy_root', 'legacy_root must be an object');
		if (self::isMap($candidate['legacy_root'] ?? NULL)) {
			self::unknownKeys($candidate['legacy_root'], ['description', 'copyright'], 'legacy_root', $errors);
			if (array_key_exists('description', $candidate['legacy_root'])) self::validateText($candidate['legacy_root']['description'], 'legacy_root/description', 'legacy_root.description', $errors, FALSE);
			if (array_key_exists('copyright', $candidate['legacy_root']) && !self::isList($candidate['legacy_root']['copyright'])) $errors[] = self::diagnostic('legacy_root.copyright', 'legacy_root/copyright', 'copyright must be a list');
			foreach (self::isList($candidate['legacy_root']['copyright'] ?? NULL) ? $candidate['legacy_root']['copyright'] : [] as $lineIndex => $line) self::validateText($line, "legacy_root/copyright/{$lineIndex}", 'legacy_root.copyright', $errors, FALSE);
		}
		$categories = $candidate['categories'] ?? NULL;
		$feeds = $candidate['feeds'] ?? NULL;
		$tombstones = $candidate['tombstones'] ?? NULL;
		if (!self::isList($categories) || count($categories) > self::MAX_CATEGORIES) $errors[] = self::diagnostic('catalog.categories', 'categories', 'categories must be a bounded list');
		if (!self::isList($feeds) || count($feeds) > self::MAX_FEEDS) $errors[] = self::diagnostic('catalog.feeds', 'feeds', 'feeds must be a bounded list');
		if (!self::isList($tombstones)) $errors[] = self::diagnostic('catalog.tombstones', 'tombstones', 'tombstones must be a list');
		elseif (count($tombstones) > self::MAX_TOMBSTONES) $errors[] = self::diagnostic('catalog.tombstones.limit', 'tombstones', 'tombstones exceed the maximum count');
		if (!self::isList($categories)) $categories = [];
		if (!self::isList($feeds)) $feeds = [];
		if (!self::isList($tombstones)) $tombstones = [];

		$categoryIds = []; $categoryById = []; $categoryKeys = [];
		foreach ($categories as $index => $category) {
			$path = "categories/{$index}";
			if (!self::isMap($category)) { $errors[] = self::diagnostic('category.type', $path, 'category must be an object'); continue; }
			self::unknownKeys($category, ['id', 'type', 'name', 'description', 'info', 'status', 'legacy_defaults', 'legacy_keys', 'feed_ids'], $path, $errors);
			$id = $category['id'] ?? NULL; $type = $category['type'] ?? NULL;
			if (!self::validId($id, 'cat')) $errors[] = self::diagnostic('category.id', "{$path}/id", 'category id is invalid');
			if (is_string($id) && isset($categoryIds[$id])) $errors[] = self::diagnostic('category.duplicate_id', "{$path}/id", 'category id is duplicated');
			if (is_string($id)) { $categoryIds[$id] = TRUE; $categoryById[$id] = $category; }
			if (!in_array($type, ['ip', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('category.type', "{$path}/type", 'category type is invalid');
			if (!is_string($category['name'] ?? NULL) || trim((string)$category['name']) === '') $errors[] = self::diagnostic('category.name', "{$path}/name", 'category name is required');
			else self::validateText($category['name'], "{$path}/name", 'category.name', $errors);
			if (!in_array($category['status'] ?? NULL, ['active', 'suspended', 'discontinued', 'tombstoned'], TRUE)) $errors[] = self::diagnostic('category.status', "{$path}/status", 'category status is invalid');
			foreach (['description', 'info'] as $field) if (!is_string($category[$field] ?? NULL)) $errors[] = self::diagnostic('category.' . $field, "{$path}/{$field}", "{$field} must be text"); else self::validateText($category[$field], "{$path}/{$field}", 'category.' . $field, $errors);
			if (!self::isMap($category['legacy_defaults'] ?? NULL)) $errors[] = self::diagnostic('category.defaults', "{$path}/legacy_defaults", 'legacy_defaults must be an object');
			elseif (!is_string($category['legacy_defaults']['action'] ?? NULL) || !is_string($category['legacy_defaults']['cron'] ?? NULL)) $errors[] = self::diagnostic('category.defaults.shape', "{$path}/legacy_defaults", 'legacy defaults require action and cron text');
			else { self::unknownKeys($category['legacy_defaults'], ['action', 'cron'], "{$path}/legacy_defaults", $errors); self::validateText($category['legacy_defaults']['action'], "{$path}/legacy_defaults/action", 'category.defaults.action', $errors); self::validateText($category['legacy_defaults']['cron'], "{$path}/legacy_defaults/cron", 'category.defaults.cron', $errors); }
			if (!self::isList($category['legacy_keys'] ?? NULL)) $errors[] = self::diagnostic('category.legacy_keys', "{$path}/legacy_keys", 'legacy_keys must be a list');
			elseif (count($category['legacy_keys']) > self::MAX_CATEGORY_KEYS) $errors[] = self::diagnostic('category.legacy_keys.limit', "{$path}/legacy_keys", 'legacy key collection exceeds the maximum count');
			if (!self::isList($category['feed_ids'] ?? NULL)) $errors[] = self::diagnostic('category.feed_ids', "{$path}/feed_ids", 'feed_ids must be a list');
			elseif (count($category['feed_ids']) > self::MAX_CATEGORY_FEEDS) $errors[] = self::diagnostic('category.feed_ids.limit', "{$path}/feed_ids", 'feed reference collection exceeds the maximum count');
			$seenKeys = [];
			foreach (self::isList($category['legacy_keys'] ?? NULL) ? $category['legacy_keys'] : [] as $legacyIndex => $legacy) {
				$lpath = "{$path}/legacy_keys/{$legacyIndex}";
				if (!self::isMap($legacy) || !in_array($legacy['type'] ?? NULL, ['ipv4', 'ipv6', 'dnsbl'], TRUE) || !is_string($legacy['key'] ?? NULL) || trim((string)$legacy['key']) === '') { $errors[] = self::diagnostic('category.legacy_key', $lpath, 'legacy key requires type and key'); continue; }
				self::unknownKeys($legacy, ['type', 'key', 'legacy_index', 'status', 'description', 'info', 'legacy_defaults'], $lpath, $errors);
				self::validateText($legacy['key'], "{$lpath}/key", 'category.legacy_key.key', $errors);
				if (($type === 'dnsbl' && $legacy['type'] !== 'dnsbl') || ($type === 'ip' && $legacy['type'] === 'dnsbl')) $errors[] = self::diagnostic('category.legacy_key.type', "{$lpath}/type", 'legacy key type conflicts with category type');
				$key = $legacy['type'] . '|' . $legacy['key']; if (isset($seenKeys[$key])) $errors[] = self::diagnostic('category.legacy_key.duplicate', $lpath, 'legacy key is duplicated'); $seenKeys[$key] = TRUE;
				if (!is_int($legacy['legacy_index'] ?? NULL) || $legacy['legacy_index'] < 0) $errors[] = self::diagnostic('category.legacy_key.index', "{$lpath}/legacy_index", 'legacy index must be a non-negative integer');
				if (!in_array($legacy['status'] ?? NULL, ['active', 'suspended', 'discontinued', 'tombstoned'], TRUE)) $errors[] = self::diagnostic('category.legacy_key.status', "{$lpath}/status", 'legacy status is invalid');
				foreach (['description', 'info'] as $field) if (!is_string($legacy[$field] ?? NULL)) $errors[] = self::diagnostic('category.legacy_key.' . $field, "{$lpath}/{$field}", "legacy {$field} must be text"); else self::validateText($legacy[$field], "{$lpath}/{$field}", 'category.legacy_key.' . $field, $errors);
				if (!self::isMap($legacy['legacy_defaults'] ?? NULL) || !is_string($legacy['legacy_defaults']['action'] ?? NULL) || !is_string($legacy['legacy_defaults']['cron'] ?? NULL)) $errors[] = self::diagnostic('category.legacy_key.defaults', "{$lpath}/legacy_defaults", 'legacy key defaults require action and cron text');
				elseif (self::isMap($legacy['legacy_defaults'])) { self::unknownKeys($legacy['legacy_defaults'], ['action', 'cron'], "{$lpath}/legacy_defaults", $errors); self::validateText($legacy['legacy_defaults']['action'], "{$lpath}/legacy_defaults/action", 'category.legacy_key.defaults.action', $errors); self::validateText($legacy['legacy_defaults']['cron'], "{$lpath}/legacy_defaults/cron", 'category.legacy_key.defaults.cron', $errors); }
				$categoryKeys[$legacy['type'] . '|' . $legacy['key']] = $id;
			}
			$seenFeeds = [];
			foreach (self::isList($category['feed_ids'] ?? NULL) ? $category['feed_ids'] : [] as $feedIndex => $feedId) {
				if (!is_string($feedId) || $feedId === '') { $errors[] = self::diagnostic('category.feed_ref', "{$path}/feed_ids/{$feedIndex}", 'feed reference must be text'); continue; }
				if (isset($seenFeeds[$feedId])) $errors[] = self::diagnostic('category.feed_ref.duplicate', "{$path}/feed_ids/{$feedIndex}", 'feed reference is duplicated');
				else $seenFeeds[$feedId] = TRUE;
			}
		}

		$feedIds = []; $feedById = [];
		foreach ($feeds as $index => $feed) {
			$path = "feeds/{$index}";
			if (!self::isMap($feed)) { $errors[] = self::diagnostic('feed.type', $path, 'feed must be an object'); continue; }
			self::unknownKeys($feed, ['id', 'type', 'name', 'status', 'family', 'category_ids', 'latest_url', 'past_urls', 'legacy_locators', 'metadata'], $path, $errors);
			$id = $feed['id'] ?? NULL; $type = $feed['type'] ?? NULL;
			if (!self::validId($id, 'feed')) $errors[] = self::diagnostic('feed.id', "{$path}/id", 'feed id is invalid');
			if (is_string($id) && isset($feedIds[$id])) $errors[] = self::diagnostic('feed.duplicate_id', "{$path}/id", 'feed id is duplicated');
			if (is_string($id)) { $feedIds[$id] = TRUE; $feedById[$id] = $feed; }
			if (!in_array($type, ['ip', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('feed.type', "{$path}/type", 'feed type is invalid');
			if (!is_string($feed['name'] ?? NULL) || trim((string)$feed['name']) === '') $errors[] = self::diagnostic('feed.name', "{$path}/name", 'feed name is required');
			else self::validateText($feed['name'], "{$path}/name", 'feed.name', $errors);
			if (!in_array($feed['status'] ?? NULL, ['active', 'suspended', 'discontinued', 'tombstoned'], TRUE)) $errors[] = self::diagnostic('feed.status', "{$path}/status", 'feed status is invalid');
			if ($type === 'ip' && !in_array($feed['family'] ?? NULL, ['ipv4', 'ipv6', 'both'], TRUE)) $errors[] = self::diagnostic('feed.family', "{$path}/family", 'IP feed family is invalid');
			if ($type === 'dnsbl' && array_key_exists('family', $feed)) $errors[] = self::diagnostic('feed.family', "{$path}/family", 'DNSBL feed cannot carry an IP family');
			if (!self::isList($feed['category_ids'] ?? NULL) || $feed['category_ids'] === []) $errors[] = self::diagnostic('feed.categories', "{$path}/category_ids", 'feed must have a non-empty category list');
			elseif (count($feed['category_ids']) > self::MAX_FEED_CATEGORIES) $errors[] = self::diagnostic('feed.category_ids.limit', "{$path}/category_ids", 'category reference collection exceeds the maximum count');
			if (!self::isList($feed['past_urls'] ?? NULL)) $errors[] = self::diagnostic('feed.past_urls', "{$path}/past_urls", 'past_urls must be a list');
			elseif (count($feed['past_urls']) > self::MAX_FEED_PAST_URLS) $errors[] = self::diagnostic('feed.past_urls.limit', "{$path}/past_urls", 'past URL collection exceeds the maximum count');
			if (!self::isMap($feed['metadata'] ?? NULL)) $errors[] = self::diagnostic('feed.metadata', "{$path}/metadata", 'metadata must be an object');
			else self::validateMetadata($feed['metadata'], "{$path}/metadata", $errors, FALSE, 'feed.metadata');
			self::validateUrl($feed['latest_url'] ?? NULL, "{$path}/latest_url", $errors);
			$seenUrls = []; foreach (self::isList($feed['past_urls'] ?? NULL) ? $feed['past_urls'] : [] as $pastIndex => $past) { self::validateUrl($past, "{$path}/past_urls/{$pastIndex}", $errors); if (is_string($past)) { if (isset($seenUrls[$past])) $errors[] = self::diagnostic('feed.past_url.duplicate', "{$path}/past_urls/{$pastIndex}", 'past URL is duplicated'); $seenUrls[$past] = TRUE; if ($past === ($feed['latest_url'] ?? NULL)) $errors[] = self::diagnostic('feed.latest_history', "{$path}/latest_url", 'latest URL must not be in past_urls'); } }
			$seenLocators = [];
			if (!self::isList($feed['legacy_locators'] ?? NULL) || $feed['legacy_locators'] === []) $errors[] = self::diagnostic('feed.locators', "{$path}/legacy_locators", 'feed must have a non-empty locator list');
			elseif (count($feed['legacy_locators']) > self::MAX_FEED_LOCATORS) $errors[] = self::diagnostic('feed.legacy_locators.limit', "{$path}/legacy_locators", 'legacy locator collection exceeds the maximum count');
			foreach (self::isList($feed['legacy_locators'] ?? NULL) ? $feed['legacy_locators'] : [] as $locatorIndex => $locator) {
				$lpath = "{$path}/legacy_locators/{$locatorIndex}";
				if (!self::isMap($locator)) { $errors[] = self::diagnostic('feed.locator.type', $lpath, 'locator must be an object'); continue; }
				self::unknownKeys($locator, ['role', 'legacy_type', 'legacy_category', 'legacy_header', 'legacy_order', 'former_parent_header', 'legacy_fields', 'metadata'], $lpath, $errors);
				$role = $locator['role'] ?? NULL; $legacyType = $locator['legacy_type'] ?? NULL;
				if (!in_array($role, ['primary', 'former_alternate'], TRUE)) $errors[] = self::diagnostic('feed.locator.role', "{$lpath}/role", 'locator role is invalid');
				if (!in_array($legacyType, ['ipv4', 'ipv6', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('feed.locator.type', "{$lpath}/legacy_type", 'locator legacy type is invalid');
				elseif (($type === 'dnsbl' && $legacyType !== 'dnsbl') || ($type === 'ip' && $legacyType === 'dnsbl')) $errors[] = self::diagnostic('feed.locator.cross_type', "{$lpath}/legacy_type", 'locator type conflicts with feed type');
				foreach (['legacy_category', 'legacy_header'] as $field) if (!is_string($locator[$field] ?? NULL) || trim((string)$locator[$field]) === '') $errors[] = self::diagnostic('feed.locator.' . $field, "{$lpath}/{$field}", "locator {$field} is required"); else self::validateText($locator[$field], "{$lpath}/{$field}", 'feed.locator.' . $field, $errors);
				if (!self::isMap($locator['metadata'] ?? NULL)) $errors[] = self::diagnostic('feed.locator.metadata', "{$lpath}/metadata", 'locator metadata must be an object');
				else self::validateMetadata($locator['metadata'], "{$lpath}/metadata", $errors, TRUE, 'feed.locator.metadata');
				if (!self::isList($locator['legacy_fields'] ?? NULL)) $errors[] = self::diagnostic('feed.locator.fields', "{$lpath}/legacy_fields", 'legacy_fields must be a list');
				foreach (self::isList($locator['legacy_fields'] ?? NULL) ? $locator['legacy_fields'] : [] as $fieldIndex => $field) if (!is_string($field)) $errors[] = self::diagnostic('feed.locator.fields.scalar', "{$lpath}/legacy_fields/{$fieldIndex}", 'legacy field names must be text');
				if (isset($locator['legacy_order']) && (!is_int($locator['legacy_order']) || $locator['legacy_order'] < 0)) $errors[] = self::diagnostic('feed.locator.order', "{$lpath}/legacy_order", 'legacy_order must be a non-negative integer');
				if ($role === 'former_alternate' && (!is_string($locator['former_parent_header'] ?? NULL) || trim((string)$locator['former_parent_header']) === '')) $errors[] = self::diagnostic('feed.locator.parent', "{$lpath}/former_parent_header", 'former alternate needs a parent header');
				elseif ($role === 'former_alternate') self::validateText($locator['former_parent_header'], "{$lpath}/former_parent_header", 'feed.locator.parent', $errors);
				if ($role !== 'former_alternate' && array_key_exists('former_parent_header', $locator)) $errors[] = self::diagnostic('feed.locator.parent.unexpected', "{$lpath}/former_parent_header", 'primary locator cannot carry a former parent header');
				$signature = serialize([$role, $legacyType, $locator['legacy_category'] ?? NULL, $locator['legacy_header'] ?? NULL, $locator['former_parent_header'] ?? NULL]);
				if (isset($seenLocators[$signature])) $errors[] = self::diagnostic('feed.locator.duplicate', $lpath, 'locator is duplicated'); $seenLocators[$signature] = TRUE;
			}
			$seenCategories = [];
			foreach (self::isList($feed['category_ids'] ?? NULL) ? $feed['category_ids'] : [] as $catIndex => $catId) { if (is_string($catId)) { if (isset($seenCategories[$catId])) $errors[] = self::diagnostic('feed.category_ref.duplicate', "{$path}/category_ids/{$catIndex}", 'category reference is duplicated'); $seenCategories[$catId] = TRUE; } else $errors[] = self::diagnostic('feed.category_ref', "{$path}/category_ids/{$catIndex}", 'category reference must be text'); }
		}
		$primaries = [];
		foreach ($feeds as $feedIndex => $feed) if (self::isMap($feed)) foreach (self::isList($feed['legacy_locators'] ?? NULL) ? $feed['legacy_locators'] : [] as $locatorIndex => $locator) if (self::isMap($locator) && ($locator['role'] ?? NULL) === 'primary' && is_string($locator['legacy_type'] ?? NULL) && is_string($locator['legacy_category'] ?? NULL) && is_string($locator['legacy_header'] ?? NULL)) {
			$key = $locator['legacy_type'] . '|' . $locator['legacy_category'] . '|' . $locator['legacy_header'];
			$primaries[$key][] = [$feedIndex, $locatorIndex, $locator];
		}
		foreach ($feeds as $index => $feed) if (self::isMap($feed)) foreach (self::isList($feed['legacy_locators'] ?? NULL) ? $feed['legacy_locators'] : [] as $locatorIndex => $locator) if (self::isMap($locator) && ($locator['role'] ?? NULL) === 'former_alternate' && is_string($locator['legacy_type'] ?? NULL) && is_string($locator['legacy_category'] ?? NULL) && is_string($locator['former_parent_header'] ?? NULL)) {
				$key = $locator['legacy_type'] . '|' . $locator['legacy_category'] . '|' . $locator['former_parent_header'];
				$matches = $primaries[$key] ?? [];
				$lpath = "feeds/{$index}/legacy_locators/{$locatorIndex}";
				if (count($matches) !== 1) { $errors[] = self::diagnostic('feed.locator.parent', "{$lpath}/former_parent_header", 'former alternate parent must resolve exactly one primary'); continue; }
				$primary = $matches[0][2];
				if (!is_int($locator['legacy_order'] ?? NULL) || !is_int($primary['legacy_order'] ?? NULL) || $locator['legacy_order'] <= $primary['legacy_order']) $errors[] = self::diagnostic('feed.locator.order', "{$lpath}/legacy_order", 'former alternate order must follow its primary');
			}
		foreach ($categories as $index => $category) if (self::isMap($category) && self::isList($category['feed_ids'] ?? NULL)) foreach ($category['feed_ids'] as $feedIndex => $feedId) {
			$path = "categories/{$index}/feed_ids/{$feedIndex}";
			if (!is_string($feedId) || !isset($feedIds[$feedId])) { $errors[] = self::diagnostic('category.feed_ref', $path, 'category feed reference is invalid'); continue; }
			$feed = $feedById[$feedId]; if (($category['type'] ?? NULL) !== $feed['type']) $errors[] = self::diagnostic('category.feed_ref.cross_type', $path, 'category and feed types conflict');
			if (!in_array($category['id'], $feed['category_ids'] ?? [], TRUE)) $errors[] = self::diagnostic('category.feed_ref.reciprocal', $path, 'category/feed reference is not reciprocal');
		}
		foreach ($feeds as $index => $feed) if (self::isMap($feed) && self::isList($feed['category_ids'] ?? NULL)) foreach ($feed['category_ids'] as $catIndex => $catId) {
			$path = "feeds/{$index}/category_ids/{$catIndex}";
			if (!is_string($catId) || !isset($categoryIds[$catId])) { $errors[] = self::diagnostic('feed.category_ref', $path, 'feed category reference is invalid'); continue; }
			if (($categoryById[$catId]['type'] ?? NULL) !== ($feed['type'] ?? NULL)) $errors[] = self::diagnostic('feed.category_ref.cross_type', $path, 'feed and category types conflict');
			if (!in_array($feed['id'], $categoryById[$catId]['feed_ids'] ?? [], TRUE)) $errors[] = self::diagnostic('feed.category_ref.reciprocal', $path, 'feed/category reference is not reciprocal');
		}
		foreach ($feeds as $index => $feed) if (self::isMap($feed)) foreach (self::isList($feed['legacy_locators'] ?? NULL) ? $feed['legacy_locators'] : [] as $locatorIndex => $locator) if (self::isMap($locator)) {
			if (!is_string($locator['legacy_type'] ?? NULL) || !is_string($locator['legacy_category'] ?? NULL)) continue;
			$key = $locator['legacy_type'] . '|' . $locator['legacy_category'];
			if (!isset($categoryKeys[$key])) $errors[] = self::diagnostic('feed.locator.category', "feeds/{$index}/legacy_locators/{$locatorIndex}", 'locator category does not exist');
			elseif (!in_array($categoryKeys[$key], $feed['category_ids'] ?? [], TRUE)) $errors[] = self::diagnostic('feed.locator.reciprocal', "feeds/{$index}/legacy_locators/{$locatorIndex}", 'locator category is not referenced by feed');
		}

		$tombstoneIds = []; $tombstoneTypes = []; $tombstoneById = [];
		foreach ($tombstones as $row) if (self::isMap($row) && is_string($row['id'] ?? NULL)) {
			$tombstoneById[$row['id']] = $row;
		}
		foreach ($tombstones as $index => $tombstone) {
			$path = "tombstones/{$index}";
			if (!self::isMap($tombstone)) { $errors[] = self::diagnostic('tombstone.type', $path, 'tombstone must be an object'); continue; }
			$id = $tombstone['id'] ?? NULL; $kind = $tombstone['kind'] ?? $tombstone['type'] ?? NULL;
			if (!in_array($kind, ['feed', 'category'], TRUE)) $errors[] = self::diagnostic('tombstone.kind', "{$path}/kind", 'tombstone kind must be feed or category');
			$allowedTombstoneKeys = ['id', 'kind', 'type', 'name', 'status', 'revision', 'reason'];
			if ($kind === 'feed') $allowedTombstoneKeys = array_merge($allowedTombstoneKeys, ['family', 'latest_url', 'past_urls', 'category_ids', 'legacy_locators']);
			elseif ($kind === 'category') $allowedTombstoneKeys = array_merge($allowedTombstoneKeys, ['legacy_keys', 'feed_ids']);
			self::unknownKeys($tombstone, $allowedTombstoneKeys, $path, $errors);
			if (!is_string($id) || (!self::validId($id, 'feed') && !self::validId($id, 'cat'))) $errors[] = self::diagnostic('tombstone.id', "{$path}/id", 'tombstone id is invalid');
			if ($kind === 'feed' && !self::validId($id, 'feed')) $errors[] = self::diagnostic('tombstone.kind', "{$path}/kind", 'feed tombstone id must be a feed id');
			if ($kind === 'category' && !self::validId($id, 'cat')) $errors[] = self::diagnostic('tombstone.kind', "{$path}/kind", 'category tombstone id must be a category id');
			if (($tombstone['status'] ?? NULL) !== 'tombstoned') $errors[] = self::diagnostic('tombstone.status', "{$path}/status", 'tombstone status must be tombstoned');
			$domainType = is_string($id) && preg_match('/^(?:feed|cat)\.(ip|dnsbl)\./', $id, $match) ? $match[1] : NULL;
			if (!in_array($tombstone['type'] ?? NULL, ['ip', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('tombstone.domain_type', "{$path}/type", 'tombstone type must be ip or dnsbl');
			elseif ($domainType !== NULL && $tombstone['type'] !== $domainType) $errors[] = self::diagnostic('tombstone.domain_type', "{$path}/type", 'tombstone type conflicts with id');
			if (!is_string($tombstone['name'] ?? NULL) || trim((string)$tombstone['name']) === '') $errors[] = self::diagnostic('tombstone.name', "{$path}/name", 'tombstone name is required');
			else self::validateText($tombstone['name'], "{$path}/name", 'tombstone.name', $errors);
			foreach (['revision', 'reason'] as $field) if (array_key_exists($field, $tombstone) && !is_string($tombstone[$field])) $errors[] = self::diagnostic('tombstone.' . $field, "{$path}/{$field}", 'optional tombstone metadata must be text'); else if (array_key_exists($field, $tombstone)) self::validateText($tombstone[$field], "{$path}/{$field}", 'tombstone.' . $field, $errors, FALSE);
			if ($kind === 'feed') {
				if (($tombstone['type'] ?? NULL) === 'ip' && !in_array($tombstone['family'] ?? NULL, ['ipv4', 'ipv6', 'both'], TRUE)) $errors[] = self::diagnostic('tombstone.family', "{$path}/family", 'IP feed tombstone requires an IP family');
				if (($tombstone['type'] ?? NULL) === 'dnsbl' && array_key_exists('family', $tombstone)) $errors[] = self::diagnostic('tombstone.family', "{$path}/family", 'DNSBL tombstone cannot carry an IP family');
				self::validateUrl($tombstone['latest_url'] ?? NULL, "{$path}/latest_url", $errors);
				if (!self::isList($tombstone['past_urls'] ?? NULL)) $errors[] = self::diagnostic('tombstone.past_urls', "{$path}/past_urls", 'feed tombstone past_urls must be a list');
				elseif (count($tombstone['past_urls']) > self::MAX_FEED_PAST_URLS) $errors[] = self::diagnostic('tombstone.past_urls.limit', "{$path}/past_urls", 'tombstone past URL collection exceeds the maximum count');
				$seenTombstoneUrls = [];
				foreach (self::isList($tombstone['past_urls'] ?? NULL) ? $tombstone['past_urls'] : [] as $pastIndex => $past) {
					self::validateUrl($past, "{$path}/past_urls/{$pastIndex}", $errors);
					if (is_string($past)) {
						if (isset($seenTombstoneUrls[$past])) $errors[] = self::diagnostic('tombstone.past_url.duplicate', "{$path}/past_urls/{$pastIndex}", 'tombstone past URL is duplicated');
						$seenTombstoneUrls[$past] = TRUE;
						if ($past === ($tombstone['latest_url'] ?? NULL)) $errors[] = self::diagnostic('tombstone.latest_history', "{$path}/latest_url", 'latest URL must not be in tombstone history');
					}
				}
				if (!self::isList($tombstone['category_ids'] ?? NULL)) $errors[] = self::diagnostic('tombstone.category_ids', "{$path}/category_ids", 'feed tombstone category_ids must be a list');
				elseif (count($tombstone['category_ids']) > self::MAX_FEED_CATEGORIES) $errors[] = self::diagnostic('tombstone.category_ids.limit', "{$path}/category_ids", 'tombstone category reference collection exceeds the maximum count');
			$seenTombstoneCategories = [];
			foreach (self::isList($tombstone['category_ids'] ?? NULL) ? $tombstone['category_ids'] : [] as $categoryIndex => $categoryId) {
				$refPath = "{$path}/category_ids/{$categoryIndex}";
				if (!is_string($categoryId) || $categoryId === '') { $errors[] = self::diagnostic('tombstone.category_ref', $refPath, 'feed tombstone category ids must be text'); continue; }
				if (isset($seenTombstoneCategories[$categoryId])) $errors[] = self::diagnostic('tombstone.category_ref.duplicate', $refPath, 'tombstone category reference is duplicated');
				$seenTombstoneCategories[$categoryId] = TRUE;
				if (!self::validId($categoryId, 'cat') || !str_starts_with($categoryId, 'cat.' . (string)($tombstone['type'] ?? '') . '.')) { $errors[] = self::diagnostic('tombstone.category_ref.type', $refPath, 'feed tombstone category type conflicts with feed type'); continue; }
				$activeType = $categoryById[$categoryId]['type'] ?? NULL;
				$tombstoneRef = $tombstoneById[$categoryId] ?? NULL;
				if (($activeType !== ($tombstone['type'] ?? NULL)) && !(self::isMap($tombstoneRef) && ($tombstoneRef['kind'] ?? NULL) === 'category' && ($tombstoneRef['type'] ?? NULL) === ($tombstone['type'] ?? NULL))) $errors[] = self::diagnostic('tombstone.category_ref', $refPath, 'feed tombstone category reference is dangling');
			}
				if (!self::isList($tombstone['legacy_locators'] ?? NULL) || $tombstone['legacy_locators'] === []) $errors[] = self::diagnostic('tombstone.locators', "{$path}/legacy_locators", 'feed tombstone must retain legacy locators');
				elseif (count($tombstone['legacy_locators']) > self::MAX_FEED_LOCATORS) $errors[] = self::diagnostic('tombstone.legacy_locators.limit', "{$path}/legacy_locators", 'tombstone locator collection exceeds the maximum count');
				foreach (self::isList($tombstone['legacy_locators'] ?? NULL) ? $tombstone['legacy_locators'] : [] as $locatorIndex => $locator) self::validateRetainedLocator($locator, "{$path}/legacy_locators/{$locatorIndex}", (string)($tombstone['type'] ?? ''), $errors);
			} elseif ($kind === 'category') {
				if (!self::isList($tombstone['legacy_keys'] ?? NULL)) $errors[] = self::diagnostic('tombstone.legacy_keys', "{$path}/legacy_keys", 'category tombstone must retain legacy keys');
				elseif (count($tombstone['legacy_keys']) > self::MAX_CATEGORY_KEYS) $errors[] = self::diagnostic('tombstone.legacy_keys.limit', "{$path}/legacy_keys", 'tombstone legacy key collection exceeds the maximum count');
				foreach (self::isList($tombstone['legacy_keys'] ?? NULL) ? $tombstone['legacy_keys'] : [] as $legacyIndex => $legacy) self::validateRetainedLegacyKey($legacy, "{$path}/legacy_keys/{$legacyIndex}", (string)($tombstone['type'] ?? ''), $errors);
				if (!self::isList($tombstone['feed_ids'] ?? NULL)) $errors[] = self::diagnostic('tombstone.feed_ids', "{$path}/feed_ids", 'category tombstone must retain feed ids');
				elseif (count($tombstone['feed_ids']) > self::MAX_CATEGORY_FEEDS) $errors[] = self::diagnostic('tombstone.feed_ids.limit', "{$path}/feed_ids", 'tombstone feed reference collection exceeds the maximum count');
				$seenTombstoneFeeds = [];
				foreach (self::isList($tombstone['feed_ids'] ?? NULL) ? $tombstone['feed_ids'] : [] as $feedIndex => $feedId) {
					$refPath = "{$path}/feed_ids/{$feedIndex}";
					if (!is_string($feedId) || $feedId === '') { $errors[] = self::diagnostic('tombstone.feed_ref', $refPath, 'category tombstone feed ids must be text'); continue; }
					if (isset($seenTombstoneFeeds[$feedId])) $errors[] = self::diagnostic('tombstone.feed_ref.duplicate', $refPath, 'tombstone feed reference is duplicated');
					$seenTombstoneFeeds[$feedId] = TRUE;
					if (!self::validId($feedId, 'feed') || !str_starts_with($feedId, 'feed.' . (string)($tombstone['type'] ?? '') . '.')) { $errors[] = self::diagnostic('tombstone.feed_ref.type', $refPath, 'category tombstone feed type conflicts with category type'); continue; }
					$activeType = $feedById[$feedId]['type'] ?? NULL;
					$tombstoneRef = $tombstoneById[$feedId] ?? NULL;
					if (($activeType !== ($tombstone['type'] ?? NULL)) && !(self::isMap($tombstoneRef) && ($tombstoneRef['kind'] ?? NULL) === 'feed' && ($tombstoneRef['type'] ?? NULL) === ($tombstone['type'] ?? NULL))) $errors[] = self::diagnostic('tombstone.feed_ref', $refPath, 'category tombstone feed reference is dangling');
				}
			}
			if (is_string($id)) { if (isset($tombstoneIds[$id])) $errors[] = self::diagnostic('tombstone.duplicate', "{$path}/id", 'tombstone id is duplicated'); if (isset($feedIds[$id]) || isset($categoryIds[$id])) $errors[] = self::diagnostic('tombstone.reuse', "{$path}/id", 'tombstone id is still active'); $tombstoneIds[$id] = TRUE; $tombstoneTypes[$id] = $kind; }
		}
		if ($prior !== NULL) self::validateTransition($prior, $candidate, $errors);
		return self::sortDiagnostics($errors);
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGraphRoot(array $root, string $name, array $allowed, array &$errors): void
	{
		foreach (array_keys($root) as $key) {
			if (!is_string($key) || !in_array($key, $allowed, TRUE)) {
				$errors[] = self::diagnostic('field.unknown', $name, 'structural root contains an unknown field');
			}
		}
	}

	/** @return list<mixed> */
	private static function boundedList(mixed $value): array
	{
		return self::isList($value) ? array_slice($value, 0, self::MAX_GRAPH_ITEMS) : [];
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGraphCaps(mixed $value, string $path, array &$errors, int $depth = 0): void
	{
		if (is_string($value)) {
			if (strlen($value) > self::MAX_TEXT) $errors[] = self::diagnostic('graph.text.limit', $path, 'graph text exceeds the maximum length');
			return;
		}
		if (!is_array($value)) return;
		if ($depth > self::MAX_GRAPH_DEPTH) {
			$errors[] = self::diagnostic('graph.depth.limit', $path, 'graph nesting exceeds the maximum depth');
			return;
		}
		if (self::isList($value)) {
			if (count($value) > self::MAX_GRAPH_ITEMS) $errors[] = self::diagnostic('graph.list.limit', $path, 'graph list exceeds the maximum count');
			foreach (array_slice($value, 0, self::MAX_GRAPH_ITEMS) as $index => $child) self::validateGraphCaps($child, "{$path}/{$index}", $errors, $depth + 1);
			return;
		}
		if (count($value) > self::MAX_GRAPH_MAP_KEYS) $errors[] = self::diagnostic('graph.map.limit', $path, 'graph object exceeds the maximum key count');
		foreach (array_slice($value, 0, self::MAX_GRAPH_MAP_KEYS, TRUE) as $key => $child) self::validateGraphCaps($child, $path . '/' . (is_string($key) ? $key : (string)$key), $errors, $depth + 1);
	}

	/** @param array<string,array<string,mixed>> $catalogFeeds @param array<string,array<string,mixed>> $catalogCategories @param list<array{code:string,path:string,severity:string,message:string}> $errors @return array<string,array<string,mixed>> */
	private static function validateRuntimeFeeds(array $model, array $catalogFeeds, array $catalogCategories, array &$errors): array
	{
		$rawFeeds = $model['feeds'] ?? NULL;
		if (!self::isList($rawFeeds)) {
			$errors[] = self::diagnostic('field.type', 'feed_model/feeds', 'feeds must be a list');
			return [];
		}
		if (count($rawFeeds) > self::MAX_GRAPH_ITEMS) $errors[] = self::diagnostic('field.limit', 'feed_model/feeds', 'feeds exceed the maximum count');
		$index = [];
		foreach (self::boundedList($rawFeeds) as $number => $feed) {
			$path = "feed_model/feeds/{$number}";
			if (!self::isMap($feed)) { $errors[] = self::diagnostic('field.type', $path, 'feed must be an object'); continue; }
			$allowed = ['id', 'type', 'name', 'alias', 'url', 'custom_url', 'family', 'parser', 'update_policy', 'schedule', 'provenance'];
			$allowed = array_merge($allowed, ['source_interface', 'pre_script', 'post_script']);
			foreach (array_keys($feed) as $key) if (!is_string($key) || !in_array($key, $allowed, TRUE)) $errors[] = self::diagnostic('field.unknown', $path, 'feed contains an unknown field');
			$id = $feed['id'] ?? NULL;
			if (!self::runtimeId($id, 'feed-instance')) $errors[] = self::diagnostic('field.value', "{$path}/id", 'feed id is invalid');
			if (is_string($id) && isset($index[$id])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/id", 'feed id is duplicated');
			if (!is_string($id)) $id = "#{$number}";
			$index[$id] = $feed;
			$type = $feed['type'] ?? NULL;
			if (!in_array($type, ['ip', 'dnsbl'], TRUE)) $errors[] = self::diagnostic(is_array($type) ? 'field.type' : 'field.value', "{$path}/type", 'feed type is invalid');
			if (!is_string($feed['name'] ?? NULL) || trim((string)$feed['name']) === '') $errors[] = self::diagnostic('field.required', "{$path}/name", 'feed name is required');
			else self::validateText($feed['name'], "{$path}/name", 'field.value', $errors);
			if (!is_string($feed['alias'] ?? NULL) || trim((string)$feed['alias']) === '') $errors[] = self::diagnostic('field.required', "{$path}/alias", 'feed alias is required');
			elseif (preg_match('/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/D', $feed['alias']) !== 1) $errors[] = self::diagnostic('field.value', "{$path}/alias", 'feed alias is invalid');
			foreach (['source_interface', 'pre_script', 'post_script'] as $field) if (isset($feed[$field]) && (!is_string($feed[$field]) || strlen($feed[$field]) > self::MAX_TEXT)) $errors[] = self::diagnostic('field.value', "{$path}/{$field}", 'feed field must be bounded text');
			if ($type === 'ip' && !in_array($feed['family'] ?? NULL, ['ipv4', 'ipv6', 'both'], TRUE)) $errors[] = self::diagnostic('field.value', "{$path}/family", 'IP feed family is invalid');
			if ($type === 'dnsbl' && array_key_exists('family', $feed)) $errors[] = self::diagnostic('field.value', "{$path}/family", 'DNSBL feed cannot carry an IP family');
			$parser = $feed['parser'] ?? NULL;
			$allowedParsers = $type === 'ip' ? ['auto', 'geoip', 'regex', 'whois', 'asn', 'rsync'] : ['auto', 'rsync'];
			if (!in_array($parser, $allowedParsers, TRUE)) $errors[] = self::diagnostic('feed.parser', "{$path}/parser", 'feed parser is invalid for its type');
			if (!in_array($feed['update_policy'] ?? NULL, ['normal', 'hold', 'flex'], TRUE)) $errors[] = self::diagnostic('feed.update_policy', "{$path}/update_policy", 'feed update policy is invalid');
			if ($type === 'dnsbl' && array_key_exists('dnsbl_mode', $feed)) $errors[] = self::diagnostic('feed.dnsbl_mode', "{$path}/dnsbl_mode", 'DNSBL feed cannot carry mode');
			if ($type === 'ip' && array_key_exists('dnsbl_mode', $feed)) $errors[] = self::diagnostic('feed.dnsbl_mode', "{$path}/dnsbl_mode", 'IP feed cannot carry DNSBL mode');
			$provenance = $feed['provenance'] ?? NULL;
			if (!self::isMap($provenance)) {
				$errors[] = self::diagnostic('field.required', "{$path}/provenance", 'feed provenance is required');
				continue;
			}
			self::unknownKeys($provenance, ['kind', 'catalog_feed_id', 'origin_category_id', 'legacy_rows'], "{$path}/provenance", $errors);
			self::validateLegacyRows($provenance['legacy_rows'] ?? NULL, "{$path}/provenance/legacy_rows", $errors);
			$kind = $provenance['kind'] ?? NULL;
			if (!in_array($kind, ['catalog', 'custom'], TRUE)) { $errors[] = self::diagnostic('field.value', "{$path}/provenance/kind", 'feed provenance kind is invalid'); continue; }
			$catalogId = $provenance['catalog_feed_id'] ?? NULL;
			$categoryId = $provenance['origin_category_id'] ?? NULL;
			if ($kind === 'catalog') {
				if (!is_string($catalogId) || $catalogId === '') $errors[] = self::diagnostic('field.required', "{$path}/provenance/catalog_feed_id", 'catalog feed reference is required');
				elseif (!isset($catalogFeeds[$catalogId])) $errors[] = self::diagnostic('reference.dangling', "{$path}/provenance/catalog_feed_id", 'catalog feed reference is dangling');
				elseif (($catalogFeeds[$catalogId]['type'] ?? NULL) !== $type) $errors[] = self::diagnostic('reference.wrong_type', "{$path}/provenance/catalog_feed_id", 'catalog feed type conflicts with runtime feed');
				if ($categoryId !== NULL && $categoryId !== '') {
					if (!is_string($categoryId)) $errors[] = self::diagnostic('field.value', "{$path}/provenance/origin_category_id", 'origin category reference is invalid');
					elseif (!isset($catalogCategories[$categoryId])) $errors[] = self::diagnostic('reference.dangling', "{$path}/provenance/origin_category_id", 'origin category reference is dangling');
					elseif (($catalogCategories[$categoryId]['type'] ?? NULL) !== $type) $errors[] = self::diagnostic('reference.wrong_type', "{$path}/provenance/origin_category_id", 'origin category type conflicts with runtime feed');
				}
				self::validateRuntimeUrl($feed['url'] ?? NULL, "{$path}/url", $errors, TRUE);
				if (array_key_exists('custom_url', $feed)) {
					if ($feed['custom_url'] === '') $errors[] = self::diagnostic('feed.custom_url.blank', "{$path}/custom_url", 'feed custom URL cannot be blank');
					else self::validateRuntimeUrl($feed['custom_url'], "{$path}/custom_url", $errors, TRUE);
				}
			} else {
				if ($catalogId !== '' && $catalogId !== NULL) $errors[] = self::diagnostic('feed.provenance.ownership', "{$path}/provenance/catalog_feed_id", 'custom feed cannot reference a catalog feed');
				if ($categoryId !== '' && $categoryId !== NULL) $errors[] = self::diagnostic('feed.provenance.ownership', "{$path}/provenance/origin_category_id", 'custom feed cannot reference a catalog category');
				if (array_key_exists('url', $feed) && $feed['url'] !== '') $errors[] = self::diagnostic('feed.url.ownership', "{$path}/url", 'custom feed cannot own a managed URL');
				if (!array_key_exists('custom_url', $feed)) $errors[] = self::diagnostic('field.required', "{$path}/custom_url", 'custom feed URL is required');
				elseif ($feed['custom_url'] === '') $errors[] = self::diagnostic('feed.custom_url.blank', "{$path}/custom_url", 'custom feed URL cannot be blank');
				self::validateRuntimeUrl($feed['custom_url'] ?? NULL, "{$path}/custom_url", $errors, FALSE);
			}
			self::validateFeedSchedule($feed['schedule'] ?? NULL, "{$path}/schedule", $errors);
		}
		return $index;
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGroupNested(array $group, string $path, string $type, array &$errors): void
	{
		if ($type === 'ip') {
			foreach (['inbound', 'outbound'] as $direction) {
				$value = $group[$direction] ?? NULL;
				if (!self::isMap($value)) { $errors[] = self::diagnostic('group.advanced', "{$path}/{$direction}", 'advanced direction must be an object'); continue; }
				$allowed = $direction === 'inbound' ? ['invert_feed_endpoint', 'destination_port', 'destination', 'protocol', 'gateway'] : ['invert_feed_endpoint', 'destination_port', 'source', 'protocol', 'gateway'];
				self::unknownKeys($value, $allowed, "{$path}/{$direction}", $errors);
				self::validateBoolean($value['invert_feed_endpoint'] ?? NULL, "{$path}/{$direction}/invert_feed_endpoint", $errors);
				foreach ([$direction === 'inbound' ? 'destination' : 'source', 'destination_port'] as $nested) {
					if (!self::isMap($value[$nested] ?? NULL)) { $errors[] = self::diagnostic('group.advanced', "{$path}/{$direction}/{$nested}", 'advanced option must be an object'); continue; }
					$nestedAllowed = $nested === 'destination_port' ? ['enabled', 'alias'] : ['enabled', 'invert', 'alias'];
					self::unknownKeys($value[$nested], $nestedAllowed, "{$path}/{$direction}/{$nested}", $errors);
					self::validateBoolean($value[$nested]['enabled'] ?? NULL, "{$path}/{$direction}/{$nested}/enabled", $errors);
					if ($nested !== 'destination_port') self::validateBoolean($value[$nested]['invert'] ?? NULL, "{$path}/{$direction}/{$nested}/invert", $errors);
					if (!is_string($value[$nested]['alias'] ?? NULL)) $errors[] = self::diagnostic('group.advanced', "{$path}/{$direction}/{$nested}/alias", 'advanced alias must be text');
				}
				if (!is_string($value['protocol'] ?? NULL) || trim($value['protocol']) === '') $errors[] = self::diagnostic('group.advanced', "{$path}/{$direction}/protocol", 'protocol is required');
				if (!is_string($value['gateway'] ?? NULL) || trim($value['gateway']) === '') $errors[] = self::diagnostic('group.advanced', "{$path}/{$direction}/gateway", 'gateway is required');
			}
			$custom = $group['custom'] ?? NULL;
			if (!self::isMap($custom)) $errors[] = self::diagnostic('group.custom', "{$path}/custom", 'IP custom settings must be an object');
			else {
				self::unknownKeys($custom, ['ipv4', 'ipv6'], "{$path}/custom", $errors);
				foreach (['ipv4', 'ipv6'] as $family) {
					if (!self::isMap($custom[$family] ?? NULL)) { $errors[] = self::diagnostic('group.custom', "{$path}/custom/{$family}", 'IP custom family must be an object'); continue; }
					self::unknownKeys($custom[$family], ['entry'], "{$path}/custom/{$family}", $errors);
					if (!self::isList($custom[$family]['entry'] ?? NULL)) $errors[] = self::diagnostic('group.custom', "{$path}/custom/{$family}/entry", 'IP custom entries must be a list');
				}
			}
		} else {
			$custom = $group['custom'] ?? NULL;
			if (!self::isMap($custom)) $errors[] = self::diagnostic('group.custom', "{$path}/custom", 'DNSBL custom settings must be an object');
			else {
				self::unknownKeys($custom, ['domains'], "{$path}/custom", $errors);
				if (!self::isMap($custom['domains'] ?? NULL)) $errors[] = self::diagnostic('group.custom', "{$path}/custom/domains", 'DNSBL custom domains must be an object');
				elseif (!self::isList($custom['domains']['domain'] ?? NULL)) $errors[] = self::diagnostic('group.custom', "{$path}/custom/domains/domain", 'DNSBL custom domains must be a list');
			}
		}
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateRuntimeUrl(mixed $url, string $path, array &$errors, bool $required): void
	{
		if (!is_string($url) || trim($url) === '') {
			if ($required) $errors[] = self::diagnostic('field.required', $path, 'feed URL is required');
			return;
		}
		self::validateUrl($url, $path, $errors);
		$parts = parse_url($url);
		if (is_array($parts) && (isset($parts['user']) || isset($parts['pass']))) $errors[] = self::diagnostic('url.credentials', $path, 'URL userinfo is not permitted');
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateFeedSchedule(mixed $schedule, string $path, array &$errors): void
	{
		if (!self::isMap($schedule)) {
			$errors[] = self::diagnostic($schedule === NULL ? 'field.required' : 'field.type', $path, 'feed schedule must be an object');
			return;
		}
		self::unknownKeys($schedule, ['cadence', 'time', 'weekdays'], $path, $errors);
		$cadence = $schedule['cadence'] ?? NULL;
		if (!in_array($cadence, ['never', '1h', '2h', '3h', '4h', '6h', '8h', '12h', 'daily', 'weekly'], TRUE)) $errors[] = self::diagnostic('feed.schedule.cadence', "{$path}/cadence", 'feed cadence is invalid');
		$time = $schedule['time'] ?? NULL;
		if (!is_string($time) || preg_match('/^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/D', $time) !== 1) $errors[] = self::diagnostic('feed.schedule.time', "{$path}/time", 'feed schedule time must be HH:MM');
		$weekdays = $schedule['weekdays'] ?? NULL;
		if (!self::isList($weekdays)) $errors[] = self::diagnostic('feed.schedule.weekdays', "{$path}/weekdays", 'feed schedule weekdays must be a list');
		else {
			$seen = [];
			foreach (self::boundedList($weekdays) as $index => $day) {
				if (!is_int($day) || $day < 1 || $day > 7 || isset($seen[$day])) $errors[] = self::diagnostic('feed.schedule.weekdays', "{$path}/weekdays/{$index}", 'feed weekday must be a unique ISO day 1-7');
				$seen[$day] = TRUE;
			}
			if ($cadence === 'weekly' && count($weekdays) !== 1) $errors[] = self::diagnostic('feed.schedule.weekdays', "{$path}/weekdays", 'weekly cadence requires exactly one weekday');
			if ($cadence !== 'weekly' && $weekdays !== []) $errors[] = self::diagnostic('feed.schedule.weekdays', "{$path}/weekdays", 'non-weekly cadence cannot carry weekdays');
		}
	}

	/** @param array<string,array<string,mixed>> $feedIndex @param list<array{code:string,path:string,severity:string,message:string}> $errors @return array<string,array<string,mixed>> */
	private static function validateRuntimeGroups(array $model, array $feedIndex, array &$errors): array
	{
		$rawGroups = $model['groups'] ?? NULL;
		if (!self::isList($rawGroups)) { $errors[] = self::diagnostic('field.type', 'feed_model/groups', 'groups must be a list'); return []; }
		if (count($rawGroups) > self::MAX_GRAPH_ITEMS) $errors[] = self::diagnostic('field.limit', 'feed_model/groups', 'groups exceed the maximum count');
		$index = [];
		$crossGroupMemberships = [];
		$userTypes = ['ip' => FALSE, 'dnsbl' => FALSE];
		foreach (self::boundedList($rawGroups) as $number => $group) {
			$path = "feed_model/groups/{$number}";
			if (!self::isMap($group)) { $errors[] = self::diagnostic('field.type', $path, 'group must be an object'); continue; }
			$allowed = ['id', 'type', 'managed_by', 'source_group_id', 'name', 'alias', 'description', 'enabled', 'action', 'sort_entries', 'memberships', 'log_firewall', 'remove_states', 'whois_convert', 'suppression_prefix', 'family_override', 'inbound', 'outbound', 'custom', 'order', 'response_mode', 'log_queries', 'filter_top1m'];
			foreach (array_keys($group) as $key) if (!is_string($key) || !in_array($key, $allowed, TRUE)) $errors[] = self::diagnostic('field.unknown', $path, 'group contains an unknown field');
			$id = $group['id'] ?? NULL;
			if (!self::runtimeId($id, 'group')) $errors[] = self::diagnostic('field.value', "{$path}/id", 'group id is invalid');
			if (is_string($id) && isset($index[$id])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/id", 'group id is duplicated');
			if (!is_string($id)) $id = "#{$number}";
			$index[$id] = $group;
			$groupId = $id;
			$type = $group['type'] ?? NULL;
			if (!in_array($type, ['ip', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('field.value', "{$path}/type", 'group type is invalid');
			$managedBy = $group['managed_by'] ?? NULL;
			if (!in_array($managedBy, ['user', 'dnsblip'], TRUE)) $errors[] = self::diagnostic('group.managed_by', "{$path}/managed_by", 'group manager is invalid');
			elseif ($managedBy === 'user' && in_array($type, ['ip', 'dnsbl'], TRUE)) $userTypes[$type] = TRUE;
			if ($managedBy === 'dnsblip') {
				if ($type !== 'ip') $errors[] = self::diagnostic('group.dnsblip.type', "{$path}/type", 'DNSBLIP groups must be IP groups');
				if (!is_string($group['source_group_id'] ?? NULL) || $group['source_group_id'] === '') $errors[] = self::diagnostic('group.dnsblip.source', "{$path}/source_group_id", 'DNSBLIP source group is required');
			} elseif (($group['source_group_id'] ?? '') !== '') $errors[] = self::diagnostic('group.source', "{$path}/source_group_id", 'user groups cannot carry a source group');
			if (!is_string($group['name'] ?? NULL) || trim((string)$group['name']) === '') $errors[] = self::diagnostic('field.required', "{$path}/name", 'group name is required');
			if (!is_string($group['alias'] ?? NULL) || trim((string)$group['alias']) === '') $errors[] = self::diagnostic('field.required', "{$path}/alias", 'group alias is required');
			self::validateBoolean($group['enabled'] ?? NULL, "{$path}/enabled", $errors);
			$action = $group['action'] ?? NULL;
			$actions = $type === 'dnsbl' ? ['unbound'] : ['deny_inbound', 'deny_outbound', 'deny_both', 'permit_inbound', 'permit_outbound', 'permit_both', 'match_inbound', 'match_outbound', 'match_both', 'alias_deny', 'alias_permit', 'alias_match', 'alias_native'];
			if (!in_array($action, $actions, TRUE)) $errors[] = self::diagnostic('group.action', "{$path}/action", 'group action is invalid');
			if ($type === 'dnsbl') {
				if (!in_array($group['order'] ?? NULL, ['default', 'primary'], TRUE)) $errors[] = self::diagnostic('group.order', "{$path}/order", 'DNSBL ordering mode is invalid');
				if (!in_array($group['response_mode'] ?? NULL, ['vip', 'null', 'nxdomain'], TRUE)) $errors[] = self::diagnostic('group.response_mode', "{$path}/response_mode", 'DNSBL response mode is invalid');
				self::validateBoolean($group['log_queries'] ?? NULL, "{$path}/log_queries", $errors);
				self::validateBoolean($group['filter_top1m'] ?? NULL, "{$path}/filter_top1m", $errors);
				foreach (['family_override', 'log_firewall', 'remove_states', 'whois_convert', 'inbound', 'outbound'] as $field) if (array_key_exists($field, $group)) $errors[] = self::diagnostic('field.unknown', "{$path}/{$field}", 'field is not valid for DNSBL group');
			} elseif (array_key_exists('family_override', $group) && $group['family_override'] !== NULL && !in_array($group['family_override'], ['ipv4', 'ipv6'], TRUE)) $errors[] = self::diagnostic('group.family', "{$path}/family_override", 'group family override is invalid');
			if ($type === 'ip') {
				foreach (['log_firewall', 'remove_states', 'whois_convert'] as $field) self::validateBoolean($group[$field] ?? NULL, "{$path}/{$field}", $errors);
				foreach (['order', 'response_mode', 'log_queries', 'filter_top1m'] as $field) if (array_key_exists($field, $group)) $errors[] = self::diagnostic('field.unknown', "{$path}/{$field}", 'field is not valid for IP group');
			}
			self::validateGroupNested($group, $path, $type, $errors);
			$memberships = $group['memberships'] ?? NULL;
			if (!self::isList($memberships)) { $errors[] = self::diagnostic('field.type', "{$path}/memberships", 'memberships must be a list'); continue; }
			if ($type === 'ip' && array_key_exists('suppression_prefix', $group) && $group['suppression_prefix'] !== NULL) {
				$bounds = self::suppressionBounds($group, $memberships, $feedIndex);
				$prefix = $group['suppression_prefix'];
				if ($bounds === NULL || !is_int($prefix) || $prefix < $bounds[0] || $prefix > $bounds[1]) $errors[] = self::diagnostic('group.suppression', "{$path}/suppression_prefix", 'suppression prefix is invalid');
			}
			$seen = [];
			foreach (self::boundedList($memberships) as $memberNumber => $membership) {
				$memberPath = "{$path}/memberships/{$memberNumber}";
				if (!self::isMap($membership)) { $errors[] = self::diagnostic('field.type', $memberPath, 'membership must be an object'); continue; }
				$idRef = $membership['feed_id'] ?? NULL;
				$membershipAllowed = ['feed_id', 'enabled', 'grandfathered_overlap', 'legacy_rows'];
				if ($type === 'dnsbl') $membershipAllowed[] = 'dnsbl_mode';
				foreach (array_keys($membership) as $key) if (!is_string($key) || !in_array($key, $membershipAllowed, TRUE)) $errors[] = self::diagnostic('field.unknown', $memberPath, 'membership contains an unknown field');
				if (!is_string($idRef) || $idRef === '') { $errors[] = self::diagnostic('field.required', "{$memberPath}/feed_id", 'membership feed reference is required'); continue; }
				$grandfathered = ($membership['grandfathered_overlap'] ?? NULL) === 'true';
				if (isset($seen[$idRef])) $errors[] = self::diagnostic('membership.duplicate', "{$memberPath}/feed_id", 'membership feed reference is duplicated');
				$seen[$idRef] = $membership;
				if (!isset($feedIndex[$idRef])) { $errors[] = self::diagnostic('reference.dangling', "{$memberPath}/feed_id", 'membership feed reference is dangling'); continue; }
				if (($feedIndex[$idRef]['type'] ?? NULL) !== $type) { $errors[] = self::diagnostic('reference.wrong_type', "{$memberPath}/feed_id", 'membership feed type conflicts with group type'); continue; }
				self::validateBoolean($membership['enabled'] ?? NULL, "{$memberPath}/enabled", $errors);
				self::validateBoolean($membership['grandfathered_overlap'] ?? NULL, "{$memberPath}/grandfathered_overlap", $errors);
				self::validateLegacyRows($membership['legacy_rows'] ?? NULL, "{$memberPath}/legacy_rows", $errors);
				if ($type === 'dnsbl' && !in_array($membership['dnsbl_mode'] ?? NULL, ['deny', 'permit'], TRUE)) $errors[] = self::diagnostic('membership.dnsbl_mode', "{$memberPath}/dnsbl_mode", 'DNSBL membership mode is required');
				if ($grandfathered && $type !== 'ip') $errors[] = self::diagnostic('membership.overlap', "{$memberPath}/grandfathered_overlap", 'grandfathered overlap applies only to IP memberships');
				if ($grandfathered && (!self::isList($membership['legacy_rows'] ?? NULL) || $membership['legacy_rows'] === [])) $errors[] = self::diagnostic('membership.grandfathered.evidence', "{$memberPath}/legacy_rows", 'grandfathered overlap requires migrated legacy row evidence');
				if (isset($group['family_override']) && $group['family_override'] !== NULL && $type === 'ip' && ($feedIndex[$idRef]['family'] ?? NULL) !== 'both' && $feedIndex[$idRef]['family'] !== $group['family_override']) {
					$errors[] = self::diagnostic('family.intersection', "{$memberPath}/feed_id", 'feed and group families do not intersect');
				}
				if ($type === 'ip' && ($membership['enabled'] ?? NULL) === 'true') {
					$feedFamily = $feedIndex[$idRef]['family'] ?? NULL;
					$membershipFamilies = ($group['family_override'] ?? NULL) ?: $feedFamily;
					$membershipFamilies = $membershipFamilies === 'both' ? ['ipv4', 'ipv6'] : (in_array($membershipFamilies, ['ipv4', 'ipv6'], TRUE) ? [$membershipFamilies] : []);
					foreach ($crossGroupMemberships[$idRef] ?? [] as $priorMembership) if ($priorMembership['group_id'] !== $groupId && array_intersect($priorMembership['families'], $membershipFamilies) !== [] && (!$grandfathered || !$priorMembership['grandfathered'])) {
						$errors[] = self::diagnostic('membership.overlap', "{$memberPath}/feed_id", 'enabled feed memberships overlap across groups');
					}
					$crossGroupMemberships[$idRef][] = ['group_id' => $groupId, 'families' => $membershipFamilies, 'grandfathered' => $grandfathered];
				}
			}
		}
		foreach ($index as $groupId => $group) if (($group['managed_by'] ?? NULL) === 'dnsblip') {
			$source = $group['source_group_id'] ?? '';
			if (!isset($index[$source]) || ($index[$source]['type'] ?? NULL) !== 'dnsbl') $errors[] = self::diagnostic('reference.wrong_type', "feed_model/groups/{$groupId}/source_group_id", 'DNSBLIP source must be a DNSBL group');
			if (($group['memberships'] ?? []) !== []) $errors[] = self::diagnostic('group.dnsblip.memberships', "feed_model/groups/{$groupId}/memberships", 'DNSBLIP groups cannot carry memberships');
		}
		if (!$userTypes['ip']) $errors[] = self::diagnostic('group.required', 'feed_model/groups', 'at least one user-managed IP group is required');
		if (!$userTypes['dnsbl']) $errors[] = self::diagnostic('group.required', 'feed_model/groups', 'at least one user-managed DNSBL group is required');
		return $index;
	}

	/** @param list<mixed> $memberships @param array<string,array<string,mixed>> $feedIndex @return array{int,int}|null */
	private static function suppressionBounds(array $group, array $memberships, array $feedIndex): ?array
	{
		$family = $group['family_override'] ?? NULL;
		if ($family === NULL) {
			$families = [];
			foreach ($memberships as $membership) {
				if (!self::isMap($membership)) continue;
				$feed = $feedIndex[$membership['feed_id'] ?? ''] ?? NULL;
				if (($feed['type'] ?? NULL) !== 'ip') continue;
				$feedFamily = $feed['family'] ?? NULL;
				if (in_array($feedFamily, ['ipv4', 'ipv6', 'both'], TRUE)) $families[$feedFamily] = TRUE;
			}
			if ($families === []) return NULL;
			$family = array_keys($families);
		} else {
			$family = [$family];
		}
		$min = 8;
		$max = 128;
		foreach ($family as $item) {
			if ($item === 'ipv4') $max = min($max, 32);
			elseif ($item === 'ipv6') $min = max($min, 32);
			elseif ($item === 'both') { $min = max($min, 32); $max = min($max, 32); }
		}
		return [$min, $max];
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateLegacyRows(mixed $rows, string $path, array &$errors): void
	{
		if (!self::isList($rows)) { $errors[] = self::diagnostic('field.type', $path, 'legacy rows must be a list'); return; }
		foreach (self::boundedList($rows) as $index => $row) {
			$itemPath = "{$path}/{$index}";
			if (!self::isMap($row)) { $errors[] = self::diagnostic('field.type', $itemPath, 'legacy row must be an object'); continue; }
			self::unknownKeys($row, ['section', 'group_index', 'row_index', 'header'], $itemPath, $errors);
			if (!is_string($row['section'] ?? NULL) || trim((string)$row['section']) === '') $errors[] = self::diagnostic('field.required', "{$itemPath}/section", 'legacy row section is required');
			foreach (['group_index', 'row_index'] as $field) if (!is_int($row[$field] ?? NULL) || $row[$field] < 0) $errors[] = self::diagnostic('field.value', "{$itemPath}/{$field}", 'legacy row index is invalid');
			if (!is_string($row['header'] ?? NULL) || trim((string)$row['header']) === '') $errors[] = self::diagnostic('field.required', "{$itemPath}/header", 'legacy row header is required');
		}
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGraphPolicies(array $root, array $feedIndex, array $groupIndex, array $categories, array $catalog, array &$errors, ?array $nativeRefs = NULL): void
	{
		$baseline = $root['baseline'] ?? NULL;
		if (!self::isMap($baseline)) {
			$errors[] = self::diagnostic('baseline.invariant', 'group_policy/baseline', 'Baseline must be an object');
		} else {
			foreach (['id', 'name', 'description', 'enabled', 'dnsbl_group_ids', 'bypass_all', 'deny_domains', 'permit_domains', 'deny_regex', 'permit_regex', 'tld_allow', 'wildcard', 'tld_blacklist', 'top1m', 'idn', 'cname_validation', 'no_aaaa', 'safe_search', 'doh_hostnames', 'default_response', 'default_logging'] as $field) if (!array_key_exists($field, $baseline)) $errors[] = self::diagnostic('baseline.invariant', "group_policy/baseline/{$field}", 'Baseline field is required');
			foreach (['audience', 'user_group_ids', 'schedule', 'order'] as $field) if (array_key_exists($field, $baseline)) $errors[] = self::diagnostic('baseline.invariant', "group_policy/baseline/{$field}", 'Baseline cannot carry upper-policy topology');
			if (($baseline['id'] ?? NULL) !== 'group-policy.dnsbl.baseline') $errors[] = self::diagnostic('baseline.invariant', 'group_policy/baseline/id', 'Baseline identity is reserved');
			if (($baseline['name'] ?? NULL) !== 'Baseline') $errors[] = self::diagnostic('baseline.invariant', 'group_policy/baseline/name', 'Baseline name is reserved');
			if (($baseline['enabled'] ?? NULL) !== 'true') $errors[] = self::diagnostic('baseline.invariant', 'group_policy/baseline/enabled', 'Baseline must remain enabled');
			if (($baseline['bypass_all'] ?? NULL) !== 'false') $errors[] = self::diagnostic('baseline.invariant', 'group_policy/baseline/bypass_all', 'Baseline cannot be bypass-all');
			self::validatePolicyLayer($baseline, 'group_policy/baseline', TRUE, $feedIndex, $groupIndex, $root, $errors);
		}
		$userGroups = $root['user_groups'] ?? NULL;
		$userIndex = [];
		$userNames = [];
		if (!self::isList($userGroups)) $errors[] = self::diagnostic('field.type', 'group_policy/user_groups', 'user groups must be a list');
		else foreach (self::boundedList($userGroups) as $number => $group) {
			$path = "group_policy/user_groups/{$number}";
			if (!self::isMap($group)) { $errors[] = self::diagnostic('field.type', $path, 'user group must be an object'); continue; }
			self::unknownKeys($group, ['id', 'name', 'description', 'selectors'], $path, $errors);
			$id = $group['id'] ?? NULL;
			if (!self::runtimeId($id, 'user-group')) $errors[] = self::diagnostic('field.value', "{$path}/id", 'user group id is invalid');
			if (is_string($id) && isset($userIndex[$id])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/id", 'user group id is duplicated');
			if (!is_string($id)) $id = "#{$number}";
			$userIndex[$id] = $group;
			if (!is_string($group['name'] ?? NULL) || trim((string)$group['name']) === '') $errors[] = self::diagnostic('field.required', "{$path}/name", 'user group name is required');
			elseif (isset($userNames[strtolower(trim($group['name']))])) $errors[] = self::diagnostic('name.duplicate', "{$path}/name", 'user group name is duplicated case-insensitively');
			else $userNames[strtolower(trim($group['name']))] = TRUE;
			$selectors = $group['selectors'] ?? NULL;
			if (!self::isList($selectors)) { $errors[] = self::diagnostic('field.type', "{$path}/selectors", 'selectors must be a list'); continue; }
			$seen = [];
			foreach (self::boundedList($selectors) as $selectorNumber => $selector) self::validateSelector($selector, "{$path}/selectors/{$selectorNumber}", $seen, $errors, $nativeRefs);
		}
		$policies = $root['policies'] ?? NULL;
		if (!self::isList($policies)) $errors[] = self::diagnostic('field.type', 'group_policy/policies', 'policies must be a list');
		else {
			$seenPolicies = [];
			$policyNames = [];
			$policyOrders = [];
			foreach (self::boundedList($policies) as $number => $policy) {
				$path = "group_policy/policies/{$number}";
				if (!self::isMap($policy)) { $errors[] = self::diagnostic('field.type', $path, 'policy must be an object'); continue; }
				$id = $policy['id'] ?? NULL;
				if (!self::runtimeId($id, 'group-policy')) $errors[] = self::diagnostic('field.value', "{$path}/id", 'policy id is invalid');
				if (is_string($id) && isset($seenPolicies[$id])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/id", 'policy id is duplicated');
				if (is_string($id)) $seenPolicies[$id] = TRUE;
				if (!is_string($policy['name'] ?? NULL) || trim((string)$policy['name']) === '') {
					// Layer validator emits the typed required-field diagnostic.
				} elseif (isset($policyNames[strtolower(trim($policy['name']))])) $errors[] = self::diagnostic('name.duplicate', "{$path}/name", 'policy name is duplicated case-insensitively');
				else $policyNames[strtolower(trim($policy['name']))] = TRUE;
				if (array_key_exists('order', $policy)) $errors[] = self::diagnostic('policy.order', "{$path}/order", 'policy order is not a stored field');
				if (array_key_exists('user_group_ids', $policy)) $errors[] = self::diagnostic('policy.topology', "{$path}/user_group_ids", 'audience is the only policy topology field');
				self::validatePolicyLayer($policy, $path, FALSE, $feedIndex, $groupIndex, $root, $errors, $userIndex, $catalog);
				$schedule = $policy['schedule'] ?? '';
				if ($schedule !== '') {
					if (!is_string($schedule)) $errors[] = self::diagnostic('field.value', "{$path}/schedule", 'schedule reference is invalid');
					elseif ($nativeRefs === NULL) $errors[] = self::diagnostic('reference.context', "{$path}/schedule", 'native schedule context is required');
					elseif (!isset($nativeRefs['schedules']) || !is_array($nativeRefs['schedules']) || !array_key_exists($schedule, $nativeRefs['schedules'])) $errors[] = self::diagnostic('reference.dangling', "{$path}/schedule", 'policy schedule reference is dangling');
				}
				$audience = self::policyAudience($policy);
				if (self::isList($audience)) foreach (self::boundedList($audience) as $audienceNumber => $userId) {
					if (!is_string($userId) || !isset($userIndex[$userId])) $errors[] = self::diagnostic('reference.dangling', "{$path}/audience/{$audienceNumber}", 'policy audience reference is dangling');
					elseif (($userIndex[$userId]['selectors'] ?? NULL) === []) $errors[] = self::diagnostic('policy.audience', "{$path}/audience/{$audienceNumber}", 'policy audience cannot target a draft user group');
				}
			}
		}
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors @param array<string,bool> $seen */
	private static function validateSelector(mixed $selector, string $path, array &$seen, array &$errors, ?array $nativeRefs = NULL): void
	{
		if (!self::isMap($selector)) { $errors[] = self::diagnostic('selector.invalid', $path, 'selector must be an object'); return; }
		self::unknownKeys($selector, ['type', 'value'], $path, $errors);
		$type = $selector['type'] ?? NULL;
		$value = $selector['value'] ?? NULL;
		if (!in_array($type, ['address', 'network', 'alias'], TRUE) || !is_string($value) || trim($value) === '') {
			$errors[] = self::diagnostic('selector.invalid', $path, 'selector type and value are invalid');
			return;
		}
		$value = trim($value);
		$normalized = $value;
		if ($type === 'address') {
			$normalized = self::normalizeIp($value);
			if ($normalized === NULL) $errors[] = self::diagnostic('selector.invalid', "{$path}/value", 'address selector is invalid');
		} elseif ($type === 'network') {
			$network = self::normalizeNetwork($value);
			if ($network === NULL) $errors[] = self::diagnostic('selector.invalid', "{$path}/value", 'network selector is invalid');
			else {
				$normalized = $network['value'];
				if ($network['host_bits']) $errors[] = self::diagnostic('selector.host_bits', "{$path}/value", 'network selector contains host bits');
			}
		} elseif (str_starts_with($value, 'pfB_') || preg_match('/[\x00-\x20\x7f]/', $value) === 1 || preg_match('/^[A-Za-z0-9_.-]+$/D', $value) !== 1) {
			$errors[] = self::diagnostic('selector.invalid', "{$path}/value", 'alias selector is invalid');
			return;
		} elseif ($nativeRefs === NULL) {
			$errors[] = self::diagnostic('reference.context', "{$path}/value", 'native alias context is required');
		} elseif (!isset($nativeRefs['aliases']) || !is_array($nativeRefs['aliases']) || !array_key_exists($value, $nativeRefs['aliases'])) {
			$errors[] = self::diagnostic('reference.dangling', "{$path}/value", 'native alias reference is dangling');
		} elseif (!in_array($nativeRefs['aliases'][$value], ['host', 'network'], TRUE)) {
			$errors[] = self::diagnostic('reference.wrong_type', "{$path}/value", 'native alias is not a Host or Network alias');
		}
		$key = $type . '|' . strtolower(is_string($normalized) ? $normalized : $value);
		if (isset($seen[$key])) $errors[] = self::diagnostic('selector.duplicate', $path, 'selector is duplicated after normalization');
		$seen[$key] = TRUE;
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validatePolicyLayer(array $policy, string $path, bool $baseline, array $feedIndex, array $groupIndex, array $root, array &$errors, array $userIndex = [], array $catalog = []): void
	{
		$allowed = ['id', 'name', 'description', 'enabled', 'audience', 'schedule', 'dnsbl_group_ids', 'bypass_all', 'deny_domains', 'permit_domains', 'deny_regex', 'permit_regex', 'tld_allow', 'wildcard', 'tld_blacklist', 'top1m', 'idn', 'cname_validation', 'no_aaaa', 'safe_search', 'doh_hostnames', 'default_response', 'default_logging'];
		foreach (array_keys($policy) as $key) if (!is_string($key) || !in_array($key, $allowed, TRUE)) $errors[] = self::diagnostic('field.unknown', $path, 'policy contains an unknown field');
		if (!is_string($policy['name'] ?? NULL) || trim((string)$policy['name']) === '') $errors[] = self::diagnostic('field.required', "{$path}/name", 'policy name is required');
		self::validateBoolean($policy['enabled'] ?? NULL, "{$path}/enabled", $errors);
		if (isset($policy['schedule']) && $policy['schedule'] !== '' && (!is_string($policy['schedule']) || trim($policy['schedule']) === '')) $errors[] = self::diagnostic('field.value', "{$path}/schedule", 'schedule reference is invalid');
		if (isset($policy['order']) && (!is_int($policy['order']) || $policy['order'] < 0)) $errors[] = self::diagnostic('policy.order', "{$path}/order", 'policy order must be non-negative');
		$audience = self::policyAudience($policy);
		if (!$baseline && (!self::isList($audience) || $audience === [])) $errors[] = self::diagnostic('policy.audience', "{$path}/audience", 'upper policy audience must be non-empty');
		if (self::isList($audience)) {
			$seen = [];
			foreach (self::boundedList($audience) as $number => $id) {
				if (!is_string($id)) { $errors[] = self::diagnostic('field.type', "{$path}/audience/{$number}", 'audience references must be text'); continue; }
				if (isset($seen[$id])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/audience/{$number}", 'audience reference is duplicated');
				$seen[$id] = TRUE;
			}
		}
		$selected = $policy['dnsbl_group_ids'] ?? NULL;
		if (!self::isList($selected)) $errors[] = self::diagnostic('field.type', "{$path}/dnsbl_group_ids", 'selected DNSBL groups must be a list');
		else {
			$seen = [];
			foreach (self::boundedList($selected) as $number => $id) {
				$refPath = "{$path}/dnsbl_group_ids/{$number}";
				if (!is_string($id)) { $errors[] = self::diagnostic('field.type', $refPath, 'group references must be text'); continue; }
				if (isset($seen[$id])) $errors[] = self::diagnostic('reference.duplicate', $refPath, 'selected group reference is duplicated');
				$seen[$id] = TRUE;
				if (!isset($groupIndex[$id])) $errors[] = self::diagnostic('reference.dangling', $refPath, 'selected group reference is dangling');
				elseif (($groupIndex[$id]['type'] ?? NULL) !== 'dnsbl') $errors[] = self::diagnostic('reference.wrong_type', $refPath, 'selected group is not DNSBL');
				elseif (($groupIndex[$id]['enabled'] ?? NULL) !== 'true') $errors[] = self::diagnostic('policy.dnsbl_group.disabled', $refPath, 'selected DNSBL group is disabled');
			}
		}
		$bypass = $policy['bypass_all'] ?? NULL;
		self::validateBoolean($bypass, "{$path}/bypass_all", $errors);
		$lanes = ['deny_domains', 'permit_domains', 'deny_regex', 'permit_regex', 'tld_allow', 'tld_blacklist', 'no_aaaa', 'safe_search', 'doh_hostnames'];
		$hasProducer = FALSE;
		foreach ($lanes as $lane) {
			$value = $policy[$lane] ?? NULL;
			if (!self::isList($value)) { $errors[] = self::diagnostic('field.type', "{$path}/{$lane}", 'decision lane must be a list'); continue; }
			if ($value !== []) $hasProducer = TRUE;
			if (in_array($lane, ['deny_domains', 'permit_domains', 'tld_allow', 'tld_blacklist'], TRUE)) self::validateDomainLane($value, "{$path}/{$lane}", $errors);
			else foreach (self::boundedList($value) as $number => $entry) if (!is_string($entry) || trim($entry) === '') $errors[] = self::diagnostic('field.value', "{$path}/{$lane}/{$number}", 'decision lane value is invalid');
		}
		$wildcard = $policy['wildcard'] ?? NULL;
		if (!self::isMap($wildcard)) $errors[] = self::diagnostic('field.type', "{$path}/wildcard", 'wildcard settings must be an object');
		else {
			self::unknownKeys($wildcard, ['enabled', 'exclusions'], "{$path}/wildcard", $errors);
			self::validateBoolean($wildcard['enabled'] ?? NULL, "{$path}/wildcard/enabled", $errors);
			if (!self::isList($wildcard['exclusions'] ?? NULL)) $errors[] = self::diagnostic('field.type', "{$path}/wildcard/exclusions", 'wildcard exclusions must be a list');
			elseif ($wildcard['exclusions'] !== []) $hasProducer = TRUE;
		}
		$top1m = $policy['top1m'] ?? NULL;
		if (!self::isMap($top1m)) $errors[] = self::diagnostic('field.type', "{$path}/top1m", 'TOP1M settings must be an object');
		else {
			self::unknownKeys($top1m, ['enabled', 'provider', 'count', 'tld_filters'], "{$path}/top1m", $errors);
			self::validateBoolean($top1m['enabled'] ?? NULL, "{$path}/top1m/enabled", $errors);
			if (!is_int($top1m['count'] ?? NULL) || $top1m['count'] < 0) $errors[] = self::diagnostic('field.value', "{$path}/top1m/count", 'TOP1M count is invalid');
			if (!self::isList($top1m['tld_filters'] ?? NULL)) $errors[] = self::diagnostic('field.type', "{$path}/top1m/tld_filters", 'TOP1M TLD filters must be a list');
			if (($top1m['enabled'] ?? NULL) === 'true') $hasProducer = TRUE;
		}
		$idn = $policy['idn'] ?? NULL;
		if (!self::isMap($idn)) $errors[] = self::diagnostic('field.type', "{$path}/idn", 'IDN settings must be an object');
		else {
			self::unknownKeys($idn, ['mode', 'confusable'], "{$path}/idn", $errors);
			if (!in_array($idn['mode'] ?? NULL, ['off', 'on', 'confusable'], TRUE) || !in_array($idn['confusable'] ?? NULL, ['off', 'on'], TRUE)) $errors[] = self::diagnostic('field.value', "{$path}/idn", 'IDN settings are invalid');
		}
		self::validateBoolean($policy['cname_validation'] ?? NULL, "{$path}/cname_validation", $errors);
		if (!in_array($policy['default_response'] ?? NULL, ['vip', 'null', 'nxdomain'], TRUE)) $errors[] = self::diagnostic('policy.response', "{$path}/default_response", 'default response is invalid');
		self::validateBoolean($policy['default_logging'] ?? NULL, "{$path}/default_logging", $errors);
		if (!$baseline && ($bypass ?? 'false') !== 'true' && !$hasProducer && ($selected ?? []) === []) $errors[] = self::diagnostic('policy.content', $path, 'upper policy must contain a complete decision lane or bypass');
		if (($bypass ?? 'false') === 'true' && (($selected ?? []) !== [] || $hasProducer)) $errors[] = self::diagnostic('policy.bypass.exclusive', "{$path}/bypass_all", 'bypass-all is mutually exclusive with decision producers');
	}

	/** @param list<mixed> $values @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateDomainLane(array $values, string $path, array &$errors): void
	{
		$seen = [];
		foreach (self::boundedList($values) as $number => $entry) {
			$value = is_string($entry) ? $entry : (self::isMap($entry) ? ($entry['value'] ?? ($entry['domain'] ?? NULL)) : NULL);
			if (!is_string($value) || trim($value) === '' || strtolower(trim($value, " .\t\r\n")) === '') { $errors[] = self::diagnostic('field.value', "{$path}/{$number}", 'domain lane value is invalid'); continue; }
			$normalized = strtolower(rtrim(trim($value), '.'));
			if ($normalized === '') { $errors[] = self::diagnostic('field.value', "{$path}/{$number}", 'DNS root is not a valid domain rule'); continue; }
			if (isset($seen[$normalized])) $errors[] = self::diagnostic('reference.duplicate', "{$path}/{$number}", 'domain lane value is duplicated after normalization');
			$seen[$normalized] = TRUE;
		}
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGraphNotices(mixed $notices, string $path, array $feedIndex, array $groupIndex, array $policy, array &$errors): void
	{
		if (!self::isList($notices)) { $errors[] = self::diagnostic('field.type', $path, 'notices must be a list'); return; }
		$seen = [];
		foreach (self::boundedList($notices) as $number => $notice) {
			$itemPath = "{$path}/{$number}";
			if (!self::isMap($notice)) { $errors[] = self::diagnostic('field.type', $itemPath, 'notice must be an object'); continue; }
			self::unknownKeys($notice, ['id', 'code', 'severity', 'subject_type', 'subject_id', 'status', 'details', 'resolution'], $itemPath, $errors);
			$id = $notice['id'] ?? NULL;
			if (!is_string($id) || $id === '') $errors[] = self::diagnostic('notice.identity', "{$itemPath}/id", 'notice identity is required');
			elseif (isset($seen[$id])) $errors[] = self::diagnostic('notice.identity', "{$itemPath}/id", 'notice identity is duplicated');
			else $seen[$id] = TRUE;
			if (!is_string($notice['code'] ?? NULL) || trim((string)$notice['code']) === '') $errors[] = self::diagnostic('notice.code', "{$itemPath}/code", 'notice code is required');
			if (!in_array($notice['severity'] ?? NULL, ['info', 'warning', 'error'], TRUE)) $errors[] = self::diagnostic('notice.severity', "{$itemPath}/severity", 'notice severity is invalid');
			if (!in_array($notice['status'] ?? NULL, ['open', 'resolved'], TRUE)) $errors[] = self::diagnostic('notice.status', "{$itemPath}/status", 'notice status is invalid');
			if (!is_string($notice['subject_type'] ?? NULL) || !is_string($notice['subject_id'] ?? NULL) || trim((string)$notice['subject_id']) === '') $errors[] = self::diagnostic('notice.subject', "{$itemPath}/subject_id", 'notice subject is required');
			elseif (!in_array($notice['subject_type'], ['feed', 'group', 'membership', 'policy', 'user_group', 'catalog'], TRUE)) $errors[] = self::diagnostic('notice.subject', "{$itemPath}/subject_type", 'notice subject type is invalid');
			elseif (!self::graphSubjectExists($notice['subject_type'], $notice['subject_id'], $feedIndex, $groupIndex, $policy)) $errors[] = self::diagnostic('reference.dangling', "{$itemPath}/subject_id", 'notice subject reference is dangling');
			if (!is_string($notice['details'] ?? NULL)) $errors[] = self::diagnostic('notice.details', "{$itemPath}/details", 'notice details must be redacted text');
			elseif (self::containsSecretMaterial($notice['details'])) $errors[] = self::diagnostic('notice.secret', "{$itemPath}/details", 'notice details must not contain secrets or raw requests');
			if (!is_string($notice['resolution'] ?? NULL) || (($notice['status'] ?? NULL) === 'resolved' && trim((string)$notice['resolution']) === '') || (($notice['status'] ?? NULL) === 'open' && trim((string)($notice['resolution'] ?? '')) !== '')) $errors[] = self::diagnostic('notice.resolution', "{$itemPath}/resolution", 'notice resolution does not match status');
		}
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateGraphProvenance(mixed $rows, string $path, array $feedIndex, array $groupIndex, array $policy, array $catalog, array &$errors): void
	{
		if (!self::isList($rows)) { $errors[] = self::diagnostic('field.type', $path, 'provenance must be a list'); return; }
		$seen = [];
		foreach (self::boundedList($rows) as $number => $row) {
			$itemPath = "{$path}/{$number}";
			if (!self::isMap($row)) { $errors[] = self::diagnostic('field.type', $itemPath, 'provenance row must be an object'); continue; }
			$id = $row['id'] ?? NULL;
			if (!is_string($id) || $id === '') $errors[] = self::diagnostic('provenance.identity', "{$itemPath}/id", 'provenance identity is required');
			elseif (isset($seen[$id])) $errors[] = self::diagnostic('provenance.append', "{$itemPath}/id", 'provenance identity is duplicated');
			else $seen[$id] = TRUE;
			foreach (['subject_type', 'subject_id', 'origin', 'event', 'catalog_revision', 'config_revision', 'trigger', 'source_locator'] as $field) if (!is_string($row[$field] ?? NULL) || trim((string)$row[$field]) === '') $errors[] = self::diagnostic('field.required', "{$itemPath}/{$field}", 'provenance field is required');
			self::unknownKeys($row, ['id', 'subject_type', 'subject_id', 'origin', 'event', 'catalog_revision', 'config_revision', 'trigger', 'source_locator', 'immutable', 'before', 'after'], $itemPath, $errors);
			if (is_string($row['subject_type'] ?? NULL) && is_string($row['subject_id'] ?? NULL) && !self::graphSubjectExists($row['subject_type'], $row['subject_id'], $feedIndex, $groupIndex, $policy)) $errors[] = self::diagnostic('provenance.reference', "{$itemPath}/subject_id", 'provenance subject reference is dangling');
			if (isset($row['immutable']) && $row['immutable'] !== 'true' && $row['immutable'] !== TRUE) $errors[] = self::diagnostic('provenance.immutable', "{$itemPath}/immutable", 'provenance rows are immutable');
			if (!self::isMap($row['before'] ?? NULL) || !self::isMap($row['after'] ?? NULL)) $errors[] = self::diagnostic('provenance.shape', $itemPath, 'provenance before and after snapshots must be objects');
			if (self::containsSecretMaterial($row) || self::containsSecretKey($row['before'] ?? NULL) || self::containsSecretKey($row['after'] ?? NULL)) $errors[] = self::diagnostic('provenance.secret', $itemPath, 'provenance evidence must not contain credentials or raw requests');
		}
	}

	private static function containsSecretKey(mixed $value): bool
	{
		if (!is_array($value)) return FALSE;
		foreach ($value as $key => $child) {
			if (is_string($key) && preg_match('/(?:secret|token|password|authorization|credential|raw.?request|header)/i', $key) === 1) return TRUE;
			if (self::containsSecretKey($child)) return TRUE;
		}
		return FALSE;
	}

	private static function containsSecretMaterial(mixed $value): bool
	{
		if (is_array($value)) {
			foreach ($value as $key => $child) {
				if (is_string($key) && preg_match('/(?:secret|token|password|authorization|cookie|credential|raw.?request|header|userinfo)/i', $key) === 1) return TRUE;
				if (self::containsSecretMaterial($child)) return TRUE;
			}
			return FALSE;
		}
		if (!is_string($value)) return FALSE;
		$value = urldecode($value);
		$queryParts = preg_split('/[?&;]/', $value) ?: [];
		array_shift($queryParts);
		foreach ($queryParts as $pair) {
			$key = urldecode(explode('=', $pair, 2)[0]);
			$normalized = preg_replace('/[^a-z0-9]+/', '', strtolower($key));
			if (in_array($normalized, ['apikey', 'authorization', 'cookie', 'credential', 'password', 'secret', 'token'], TRUE)) return TRUE;
		}
		return preg_match('/(?:authorization\s*:|cookie\s*:|(?:token|password|secret|credential)\s*=|https?:\/\/[^\s\/@:]+:[^\s\/@]+@)/i', $value) === 1;
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateBoolean(mixed $value, string $path, array &$errors): void
	{
		if ($value !== 'true' && $value !== 'false') $errors[] = self::diagnostic('field.value', $path, 'boolean storage value must be true or false');
	}

	private static function runtimeId(mixed $value, string $prefix): bool
	{
		if (!is_string($value) || $value === '' || strlen($value) > 160) return FALSE;
		if ($prefix === 'group' && in_array($value, ['group.ip.default', 'group.dnsbl.default'], TRUE)) return TRUE;
		$uuid = '[a-f0-9]{12}4[a-f0-9]{3}[89ab][a-f0-9]{15}';
		$slug = '[a-z0-9][a-z0-9.-]*';
		$pattern = match ($prefix) {
			'feed-instance' => '/^feed-instance\\.(?:ip|dnsbl)\\.' . $slug . '_'.$uuid.'$/D',
			'group' => '/^group\\.(?:ip|dnsbl)\\.' . $slug . '_'.$uuid.'$/D',
			'user-group' => '/^user-group\\.' . $slug . '_'.$uuid.'$/D',
			'group-policy' => '/^group-policy\\.(?:ip|dnsbl)\\.' . $slug . '_'.$uuid.'$/D',
			default => '/^' . preg_quote($prefix, '/') . '$/D',
		};
		return (bool) preg_match($pattern, $value);
	}

	/** @return list<mixed>|null */
	private static function policyAudience(array $policy): ?array
	{
		$audience = $policy['audience'] ?? NULL;
		return self::isList($audience) ? $audience : NULL;
	}

	private static function normalizeIp(string $value): ?string
	{
		$packed = @inet_pton($value);
		if ($packed === FALSE) return NULL;
		$normalized = @inet_ntop($packed);
		return $normalized === FALSE ? NULL : $normalized;
	}

	/** @return array{value:string,host_bits:bool}|null */
	private static function normalizeNetwork(string $value): ?array
	{
		$parts = explode('/', $value, 2);
		if (count($parts) !== 2 || !is_numeric($parts[1]) || (string)(int)$parts[1] !== $parts[1]) return NULL;
		$packed = @inet_pton($parts[0]);
		if ($packed === FALSE) return NULL;
		$prefix = (int)$parts[1];
		$bits = strlen($packed) * 8;
		if ($prefix < 0 || $prefix > $bits) return NULL;
		$masked = '';
		for ($offset = 0; $offset < strlen($packed); $offset++) {
			$remaining = $prefix - ($offset * 8);
			$mask = $remaining >= 8 ? 255 : ($remaining <= 0 ? 0 : (256 - (1 << (8 - $remaining))));
			$masked .= chr(ord($packed[$offset]) & $mask);
		}
		$normalized = @inet_ntop($masked);
		if ($normalized === FALSE) return NULL;
		return ['value' => $normalized . '/' . $prefix, 'host_bits' => $masked !== $packed];
	}

	private static function graphSubjectExists(string $type, string $id, array $feedIndex, array $groupIndex, array $policy): bool
	{
		return match ($type) {
			'feed' => isset($feedIndex[$id]),
			'group' => isset($groupIndex[$id]),
			'membership' => self::membershipSubjectExists($id, $groupIndex),
			'policy' => $id === ($policy['baseline']['id'] ?? NULL) || in_array($id, array_column(self::boundedList($policy['policies'] ?? NULL), 'id'), TRUE),
			'user_group' => in_array($id, array_column(self::boundedList($policy['user_groups'] ?? NULL), 'id'), TRUE),
			'catalog' => $id === 'catalog',
			default => FALSE,
		};
	}

	private static function membershipSubjectExists(string $id, array $groupIndex): bool
	{
		$parts = explode('|', $id, 2);
		if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '' || !isset($groupIndex[$parts[0]])) return FALSE;
		foreach (self::boundedList($groupIndex[$parts[0]]['memberships'] ?? NULL) as $membership) {
			if (self::isMap($membership) && ($membership['feed_id'] ?? NULL) === $parts[1]) return TRUE;
		}
		return FALSE;
	}

	/** @param array<string,mixed> $catalog @return array<string,mixed> */
	public static function legacyCatalog(array $catalog): array
	{
		$diagnostics = self::validateCatalog($catalog);
		if ($diagnostics !== []) throw new PfbRegistryException($diagnostics);
		$out = [];
		if (is_array($catalog['legacy_root'] ?? NULL)) {
			if (array_key_exists('description', $catalog['legacy_root'])) $out['description'] = $catalog['legacy_root']['description'];
			if (array_key_exists('copyright', $catalog['legacy_root'])) $out['copyright'] = $catalog['legacy_root']['copyright'];
		}
		$categoryById = [];
		foreach ($catalog['categories'] as $category) $categoryById[$category['id']] = $category;
		$pendingAlternates = [];
		foreach ($catalog['feeds'] as $feed) {
			foreach ($feed['legacy_locators'] as $locator) {
				$type = $locator['legacy_type']; $categoryKey = $locator['legacy_category']; $catId = NULL;
				foreach ($feed['category_ids'] as $candidate) foreach ($categoryById[$candidate]['legacy_keys'] as $legacy) if ($legacy['type'] === $type && $legacy['key'] === $categoryKey) $catId = $candidate;
				if ($catId === NULL) continue;
				$category = $categoryById[$catId];
				$legacyMeta = ['info'=>$category['info'], 'description'=>$category['description'], 'action'=>$category['legacy_defaults']['action'] ?? '', 'cron'=>$category['legacy_defaults']['cron'] ?? ''];
				foreach ($category['legacy_keys'] as $legacyRecord) if (is_array($legacyRecord) && ($legacyRecord['type'] ?? NULL) === $type && ($legacyRecord['key'] ?? NULL) === $categoryKey) {
					$legacyMeta = [];
					if (($legacyRecord['status'] ?? 'active') !== 'active') $legacyMeta['status'] = $legacyRecord['status'];
					$legacyMeta += ['info'=>$legacyRecord['info'] ?? '', 'description'=>$legacyRecord['description'] ?? '', 'action'=>$legacyRecord['legacy_defaults']['action'] ?? '', 'cron'=>$legacyRecord['legacy_defaults']['cron'] ?? ''];
					break;
				}
				$out[$type][$categoryKey] ??= $legacyMeta + ['feeds'=>[]];
				$row = self::legacyRow($feed, $locator);
				$row['_legacy_order'] = (int)($locator['legacy_order'] ?? PHP_INT_MAX);
				if (($locator['role'] ?? '') === 'former_alternate') {
					$attached = FALSE;
					foreach ($out[$type][$categoryKey]['feeds'] as &$primary) if (($primary['header'] ?? '') === ($locator['former_parent_header'] ?? '')) { $primary['alternate'][] = $row; $attached = TRUE; break; }
					unset($primary);
					if (!$attached) $pendingAlternates[] = [$type, $categoryKey, (string)($locator['former_parent_header'] ?? ''), $row];
				} else $out[$type][$categoryKey]['feeds'][] = $row;
			}
		}
		foreach ($pendingAlternates as [$type, $categoryKey, $parentHeader, $row]) {
			foreach ($out[$type][$categoryKey]['feeds'] as &$primary) if (($primary['header'] ?? '') === $parentHeader) {
				$primary['alternate'][] = $row;
				break;
			}
			unset($primary);
		}
		foreach (['ipv4', 'ipv6', 'dnsbl'] as $legacyType) {
			if (!isset($out[$legacyType])) continue;
			foreach ($out[$legacyType] as &$group) {
			usort($group['feeds'], static fn(array $left, array $right): int => (int)($left['_legacy_order'] ?? PHP_INT_MAX) <=> (int)($right['_legacy_order'] ?? PHP_INT_MAX));
			foreach ($group['feeds'] as &$row) {
				if (isset($row['alternate']) && is_array($row['alternate'])) {
					usort($row['alternate'], static fn(array $left, array $right): int => (int)($left['_legacy_order'] ?? PHP_INT_MAX) <=> (int)($right['_legacy_order'] ?? PHP_INT_MAX));
					foreach ($row['alternate'] as &$alternate) unset($alternate['_legacy_order']);
					unset($alternate);
				}
				if (isset($row['_legacy_after_alternate']) && is_array($row['_legacy_after_alternate'])) {
					$afterAlternate = $row['_legacy_after_alternate'];
					unset($row['_legacy_after_alternate']);
					foreach ($afterAlternate as $key => $value) $row[$key] = $value;
				}
				unset($row['_legacy_order']);
			}
				unset($row);
			}
			unset($group);
		}
		$legacyOrder = ['ipv4'=>[], 'ipv6'=>[], 'dnsbl'=>[]];
		foreach ($catalog['categories'] as $category) foreach ($category['legacy_keys'] as $legacyRecord) {
			if (is_array($legacyRecord) && isset($legacyOrder[$legacyRecord['type'] ?? ''])) $legacyOrder[$legacyRecord['type']][] = $legacyRecord;
		}
		foreach ($legacyOrder as $type => $records) {
			usort($records, static fn(array $left, array $right): int => (int)($left['legacy_index'] ?? PHP_INT_MAX) <=> (int)($right['legacy_index'] ?? PHP_INT_MAX));
			$ordered = [];
			foreach ($records as $record) if (isset($out[$type][$record['key']])) $ordered[$record['key']] = $out[$type][$record['key']];
			foreach ($out[$type] ?? [] as $key => $value) if (!isset($ordered[$key])) $ordered[$key] = $value;
			$out[$type] = $ordered;
		}
		return $out;
	}

	/** @return array<string,mixed> */
	private static function legacyRow(array $feed, array $locator): array
	{
		$metadata = is_array($locator['metadata'] ?? NULL) ? $locator['metadata'] : [];
		$fields = is_array($locator['legacy_fields'] ?? NULL) ? $locator['legacy_fields'] : [];
		if ($fields !== []) {
			$row = [];
			$afterAlternate = FALSE;
			$afterAlternateFields = [];
			foreach ($fields as $field) {
				if (!is_string($field) || in_array($field, ['primary_header', 'legacy_order'], TRUE)) continue;
				if ($field === '__legacy_alt__') { $afterAlternate = TRUE; continue; }
				$present = TRUE;
				$value = NULL;
				if ($field === 'url') $value = $feed['latest_url'];
				elseif ($field === 'header') $value = $locator['legacy_header'];
				elseif ($field === 'status') {
					$present = (($feed['status'] ?? 'active') !== 'active');
					$value = (($feed['status'] ?? '') === 'suspended') ? 'Suspended' : ($feed['status'] ?? 'active');
				} elseif ($field === 'past_urls') {
					$present = (($feed['past_urls'] ?? []) !== []);
					$value = $feed['past_urls'] ?? [];
				} elseif (array_key_exists($field, $metadata)) $value = $metadata[$field];
				else $present = FALSE;
				if ($present) {
					if ($afterAlternate) $afterAlternateFields[$field] = $value;
					else $row[$field] = $value;
				}
			}
			if (($locator['role'] ?? '') !== 'former_alternate' && !isset($row['feed']) && !isset($row['Feed'])) $row['feed'] = $feed['name'];
			if ($afterAlternateFields !== []) $row['_legacy_after_alternate'] = $afterAlternateFields;
			return $row;
		}
		$row = [];
		if (($feed['status'] ?? 'active') !== 'active') $row['status'] = ($feed['status'] === 'suspended') ? 'Suspended' : $feed['status'];
		foreach ($metadata as $key => $value) $row[$key] = $value;
		$row['url'] = $feed['latest_url'];
		if (($feed['past_urls'] ?? []) !== []) $row['past_urls'] = $feed['past_urls'];
		$row['header'] = $locator['legacy_header'];
		if (!isset($row['feed']) && !isset($row['Feed'])) $row['feed'] = $feed['name'];
		return $row;
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateTransition(array $prior, array $candidate, array &$errors): void
	{
		$oldFeeds = []; foreach (self::isList($prior['feeds'] ?? NULL) ? $prior['feeds'] : [] as $feed) if (self::isMap($feed) && is_string($feed['id'] ?? NULL)) $oldFeeds[$feed['id']] = $feed;
		$newFeeds = []; foreach (self::isList($candidate['feeds'] ?? NULL) ? $candidate['feeds'] : [] as $feed) if (self::isMap($feed) && is_string($feed['id'] ?? NULL)) $newFeeds[$feed['id']] = $feed;
		$oldCategories = []; foreach (self::isList($prior['categories'] ?? NULL) ? $prior['categories'] : [] as $category) if (self::isMap($category) && is_string($category['id'] ?? NULL)) $oldCategories[$category['id']] = $category;
		$newCategories = []; foreach (self::isList($candidate['categories'] ?? NULL) ? $candidate['categories'] : [] as $category) if (self::isMap($category) && is_string($category['id'] ?? NULL)) $newCategories[$category['id']] = $category;
		$tombstones = []; foreach (self::isList($candidate['tombstones'] ?? NULL) ? $candidate['tombstones'] : [] as $row) if (self::isMap($row) && is_string($row['id'] ?? NULL)) $tombstones[$row['id']] = $row;
		$oldTombstones = []; foreach (self::isList($prior['tombstones'] ?? NULL) ? $prior['tombstones'] : [] as $row) if (self::isMap($row) && is_string($row['id'] ?? NULL)) $oldTombstones[$row['id']] = $row;
		foreach ($oldFeeds as $id => $old) {
			if (!isset($newFeeds[$id])) {
				if (!isset($tombstones[$id])) $errors[] = self::diagnostic('transition.tombstone', "feeds/{$id}", 'removed feed requires a tombstone');
				elseif (($tombstones[$id]['kind'] ?? $tombstones[$id]['type'] ?? NULL) !== 'feed' || ($tombstones[$id]['type'] ?? NULL) !== ($old['type'] ?? NULL)) $errors[] = self::diagnostic('transition.tombstone.shape', "tombstones/{$id}", 'feed removal tombstone must retain feed domain type');
				continue;
			}
			$new = $newFeeds[$id];
			if (($old['type'] ?? NULL) !== ($new['type'] ?? NULL)) $errors[] = self::diagnostic('transition.identity', "feeds/{$id}/type", 'feed domain type cannot change');
			if (($old['latest_url'] ?? NULL) !== ($new['latest_url'] ?? NULL) && !in_array($old['latest_url'] ?? NULL, $new['past_urls'] ?? [], TRUE)) $errors[] = self::diagnostic('transition.history', "feeds/{$id}/past_urls", 'previous latest URL must remain in history');
			foreach (self::isList($old['past_urls'] ?? NULL) ? $old['past_urls'] : [] as $url) if (!in_array($url, self::isList($new['past_urls'] ?? NULL) ? $new['past_urls'] : [], TRUE)) $errors[] = self::diagnostic('transition.history_delete', "feeds/{$id}/past_urls", 'feed history cannot be deleted');
		}
		foreach ($oldCategories as $id => $old) {
			if (!isset($newCategories[$id])) {
				if (!isset($tombstones[$id])) $errors[] = self::diagnostic('transition.tombstone', "categories/{$id}", 'removed category requires a tombstone');
				elseif (($tombstones[$id]['kind'] ?? $tombstones[$id]['type'] ?? NULL) !== 'category' || ($tombstones[$id]['type'] ?? NULL) !== ($old['type'] ?? NULL)) $errors[] = self::diagnostic('transition.tombstone.shape', "tombstones/{$id}", 'category removal tombstone must retain category domain type');
				continue;
			}
			if (($old['type'] ?? NULL) !== ($newCategories[$id]['type'] ?? NULL)) $errors[] = self::diagnostic('transition.identity', "categories/{$id}/type", 'category domain type cannot change');
		}
		foreach ($oldTombstones as $id => $old) {
			if (!isset($tombstones[$id])) $errors[] = self::diagnostic('transition.tombstone_delete', "tombstones/{$id}", 'tombstones cannot be deleted');
			else {
				$current = $tombstones[$id];
				foreach (['kind', 'id', 'type', 'name', 'status', 'family', 'latest_url', 'past_urls', 'category_ids', 'legacy_locators', 'legacy_keys', 'feed_ids'] as $field) if (($old[$field] ?? NULL) !== ($current[$field] ?? NULL)) $errors[] = self::diagnostic('transition.tombstone_reuse', "tombstones/{$id}/{$field}", 'tombstone identity/evidence cannot change');
			}
		}
		foreach ($newFeeds as $id => $feed) foreach ($tombstones as $tombstoneId => $tombstone) {
			if ($id === $tombstoneId || ($tombstone['kind'] ?? $tombstone['type'] ?? NULL) !== 'feed' || ($feed['type'] ?? NULL) !== ($tombstone['type'] ?? NULL)) continue;
			$sameIdentity = FALSE;
			foreach ($feed['legacy_locators'] ?? [] as $locator) foreach ($tombstone['legacy_locators'] ?? [] as $priorLocator) if (self::sameStableLocator($locator, $priorLocator)) { $sameIdentity = TRUE; break 2; }
			if ($sameIdentity) $errors[] = self::diagnostic('transition.identity', "feeds/{$id}/id", 'feed identity evidence cannot move to a new id');
		}
		foreach ($newFeeds as $id => $_feed) if (isset($oldTombstones[$id])) $errors[] = self::diagnostic('transition.revive', "feeds/{$id}", 'tombstone cannot be revived');
		foreach ($newCategories as $id => $_category) if (isset($oldTombstones[$id])) $errors[] = self::diagnostic('transition.revive', "categories/{$id}", 'tombstone cannot be revived');
	}

	private static function sameStableLocator(mixed $left, mixed $right): bool
	{
		if (!self::isMap($left) || !self::isMap($right)) return FALSE;
		foreach (['role', 'legacy_type', 'legacy_category', 'legacy_header'] as $field) if (($left[$field] ?? NULL) !== ($right[$field] ?? NULL)) return FALSE;
		return TRUE;
	}

	private static function validId(mixed $value, string $kind): bool
	{
		if (!is_string($value) || $value === '' || strlen($value) > 128) return FALSE;
		return (bool)preg_match('/^' . preg_quote($kind, '/') . '\.(?:ip|dnsbl)\.[a-z0-9]+(?:[.-][a-z0-9]+)*\z/', $value);
	}

	private static function validateUrl(mixed $url, string $path, array &$errors): void
	{
		if (!is_string($url) || strlen($url) > 4096 || preg_match('/[\x00-\x20\x7f]/', (string)$url)) { $errors[] = self::diagnostic('url.invalid', $path, 'URL must be bounded HTTP(S) text'); return; }
		if (strpbrk($url, '[]') !== FALSE && preg_match('/^https?:\/\/\[[^\]]+\](?::[0-9]+)?(?:[\/?#]|$)/iD', $url) !== 1) { $errors[] = self::diagnostic('url.invalid', $path, 'URL must be absolute HTTP(S)'); return; }
		$parts = parse_url($url);
		$host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
		if (!is_array($parts) || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], TRUE) || trim($host) === '' || (strpbrk($host, '[]') !== FALSE && filter_var(trim($host, '[]'), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === FALSE)) $errors[] = self::diagnostic('url.invalid', $path, 'URL must be absolute HTTP(S)');
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateRetainedLocator(mixed $locator, string $path, string $feedType, array &$errors): void
	{
		if (!self::isMap($locator)) { $errors[] = self::diagnostic('tombstone.locator.type', $path, 'retained locator must be an object'); return; }
		self::unknownKeys($locator, ['role', 'legacy_type', 'legacy_category', 'legacy_header', 'legacy_order', 'former_parent_header', 'legacy_fields', 'metadata'], $path, $errors);
		$role = $locator['role'] ?? NULL; $legacyType = $locator['legacy_type'] ?? NULL;
		if (!in_array($role, ['primary', 'former_alternate'], TRUE)) $errors[] = self::diagnostic('tombstone.locator.role', "{$path}/role", 'retained locator role is invalid');
		if (!in_array($legacyType, ['ipv4', 'ipv6', 'dnsbl'], TRUE)) $errors[] = self::diagnostic('tombstone.locator.type', "{$path}/legacy_type", 'retained locator type is invalid');
		elseif (($feedType === 'dnsbl' && $legacyType !== 'dnsbl') || ($feedType === 'ip' && $legacyType === 'dnsbl')) $errors[] = self::diagnostic('tombstone.locator.cross_type', "{$path}/legacy_type", 'retained locator type conflicts with feed type');
		foreach (['legacy_category', 'legacy_header'] as $field) if (!is_string($locator[$field] ?? NULL) || trim((string)$locator[$field]) === '') $errors[] = self::diagnostic('tombstone.locator.' . $field, "{$path}/{$field}", 'retained locator field is required text'); else self::validateText($locator[$field], "{$path}/{$field}", 'tombstone.locator.' . $field, $errors);
		if (isset($locator['legacy_order']) && (!is_int($locator['legacy_order']) || $locator['legacy_order'] < 0)) $errors[] = self::diagnostic('tombstone.locator.order', "{$path}/legacy_order", 'retained locator order must be a non-negative integer');
		if (!self::isList($locator['legacy_fields'] ?? NULL)) $errors[] = self::diagnostic('tombstone.locator.fields', "{$path}/legacy_fields", 'retained locator fields must be a list');
		foreach (self::isList($locator['legacy_fields'] ?? NULL) ? $locator['legacy_fields'] : [] as $fieldIndex => $field) if (!is_string($field)) $errors[] = self::diagnostic('tombstone.locator.fields.scalar', "{$path}/legacy_fields/{$fieldIndex}", 'retained locator field names must be text');
		if (!self::isMap($locator['metadata'] ?? NULL)) $errors[] = self::diagnostic('tombstone.locator.metadata', "{$path}/metadata", 'retained locator metadata must be an object');
		else self::validateMetadata($locator['metadata'], "{$path}/metadata", $errors, TRUE, 'tombstone.locator.metadata');
		if ($role === 'former_alternate' && (!is_string($locator['former_parent_header'] ?? NULL) || trim((string)$locator['former_parent_header']) === '')) $errors[] = self::diagnostic('tombstone.locator.parent', "{$path}/former_parent_header", 'retained former alternate needs a parent header');
		elseif ($role === 'former_alternate') self::validateText($locator['former_parent_header'], "{$path}/former_parent_header", 'tombstone.locator.parent', $errors);
		if ($role !== 'former_alternate' && array_key_exists('former_parent_header', $locator)) $errors[] = self::diagnostic('tombstone.locator.parent.unexpected', "{$path}/former_parent_header", 'retained primary cannot carry a former parent header');
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateRetainedLegacyKey(mixed $legacy, string $path, string $categoryType, array &$errors): void
	{
		if (!self::isMap($legacy)) { $errors[] = self::diagnostic('tombstone.legacy_key', $path, 'retained legacy key must be an object'); return; }
		self::unknownKeys($legacy, ['type', 'key', 'legacy_index', 'status', 'description', 'info', 'legacy_defaults'], $path, $errors);
		$type = $legacy['type'] ?? NULL;
		if (!in_array($type, ['ipv4', 'ipv6', 'dnsbl'], TRUE) || !is_string($legacy['key'] ?? NULL) || trim((string)$legacy['key']) === '') $errors[] = self::diagnostic('tombstone.legacy_key', $path, 'retained legacy key requires type and key');
		elseif (($categoryType === 'dnsbl' && $type !== 'dnsbl') || ($categoryType === 'ip' && $type === 'dnsbl')) $errors[] = self::diagnostic('tombstone.legacy_key.cross_type', "{$path}/type", 'retained legacy key type conflicts with category type');
		else self::validateText($legacy['key'], "{$path}/key", 'tombstone.legacy_key.key', $errors);
		if (!is_int($legacy['legacy_index'] ?? NULL) || $legacy['legacy_index'] < 0) $errors[] = self::diagnostic('tombstone.legacy_key.index', "{$path}/legacy_index", 'retained legacy index must be a non-negative integer');
		if (!in_array($legacy['status'] ?? NULL, ['active', 'suspended', 'discontinued', 'tombstoned'], TRUE)) $errors[] = self::diagnostic('tombstone.legacy_key.status', "{$path}/status", 'retained legacy status is invalid');
		foreach (['description', 'info'] as $field) if (!is_string($legacy[$field] ?? NULL)) $errors[] = self::diagnostic('tombstone.legacy_key.' . $field, "{$path}/{$field}", 'retained legacy field must be text'); else self::validateText($legacy[$field], "{$path}/{$field}", 'tombstone.legacy_key.' . $field, $errors);
		if (!self::isMap($legacy['legacy_defaults'] ?? NULL) || !is_string($legacy['legacy_defaults']['action'] ?? NULL) || !is_string($legacy['legacy_defaults']['cron'] ?? NULL)) $errors[] = self::diagnostic('tombstone.legacy_key.defaults', "{$path}/legacy_defaults", 'retained legacy defaults require action and cron text');
		elseif (self::isMap($legacy['legacy_defaults'])) { self::unknownKeys($legacy['legacy_defaults'], ['action', 'cron'], "{$path}/legacy_defaults", $errors); self::validateText($legacy['legacy_defaults']['action'], "{$path}/legacy_defaults/action", 'tombstone.legacy_key.defaults.action', $errors); self::validateText($legacy['legacy_defaults']['cron'], "{$path}/legacy_defaults/cron", 'tombstone.legacy_key.defaults.cron', $errors); }
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function unknownKeys(array $value, array $allowed, string $path, array &$errors): void
	{
		foreach (array_keys($value) as $key) if (!is_string($key) || !in_array($key, $allowed, TRUE)) $errors[] = self::diagnostic('catalog.field.unknown', $path . '/' . (is_string($key) ? $key : (string)$key), 'unknown structural field');
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateText(mixed $value, string $path, string $code, array &$errors, bool $required = TRUE): void
	{
		if (!is_string($value)) {
			if ($required) $errors[] = self::diagnostic($code, $path, 'text value is required');
			return;
		}
		if (strlen($value) > self::MAX_TEXT) $errors[] = self::diagnostic($code . '.length', $path, 'text value exceeds the maximum length');
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateMetadata(mixed $metadata, string $path, array &$errors, bool $locator, string $scope): void
	{
		if (!self::isMap($metadata)) return;
		if (count($metadata) > self::MAX_METADATA_KEYS) $errors[] = self::diagnostic($scope . '.limit', $path, 'metadata exceeds the maximum key count');
		$allowed = ['feed', 'Feed', 'website', 'info', 'contact', 'register', 'donate', 'delist'];
		if ($locator) $allowed[] = 'Internic6';
		self::validateMetadataMap($metadata, $path, $allowed, $errors, 0, $scope);
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function validateMetadataMap(array $metadata, string $path, array $allowed, array &$errors, int $depth, string $scope): void
	{
		if ($depth > self::MAX_METADATA_DEPTH) { $errors[] = self::diagnostic($scope . '.depth', $path, 'metadata nesting exceeds the maximum depth'); return; }
		if (count($metadata) > self::MAX_METADATA_KEYS) $errors[] = self::diagnostic($scope . '.limit', $path, 'metadata exceeds the maximum key count');
		foreach ($metadata as $key => $value) {
			$keyPath = $path . '/' . (is_string($key) ? $key : (string)$key);
			if (!is_string($key) || !in_array($key, $allowed, TRUE)) $errors[] = self::diagnostic('catalog.field.unknown', $keyPath, 'unknown metadata field');
			if (is_array($value)) {
				if (!self::isMap($value)) $errors[] = self::diagnostic('catalog.metadata.value', $keyPath, 'metadata values must be scalar text or maps');
				else self::validateMetadataMap($value, $keyPath, $allowed, $errors, $depth + 1, $scope);
			} elseif (!is_string($value)) $errors[] = self::diagnostic($scope . '.value', $keyPath, 'metadata values must be scalar text or maps');
			elseif (strlen($value) > self::MAX_TEXT) $errors[] = self::diagnostic($scope . '.value.length', $keyPath, 'metadata value exceeds the maximum length');
			if (is_string($key) && strlen($key) > self::MAX_TEXT) $errors[] = self::diagnostic($scope . '.key.length', $keyPath, 'metadata key exceeds the maximum length');
		}
	}

	private static function isList(mixed $value): bool
	{
		return is_array($value) && array_is_list($value);
	}

	private static function isMap(mixed $value): bool
	{
		return is_array($value) && ($value === [] || !array_is_list($value));
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $errors */
	private static function forbiddenKeys(mixed $value, string $path, array &$errors): void
	{
		if (!is_array($value)) return;
		foreach ($value as $key => $child) {
			$childPath = $path . '/' . (is_int($key) ? $key : $key);
			if (is_string($key) && in_array($key, ['source_options', 'default_source_option_id', 'alternate', 'preference'], TRUE)) $errors[] = self::diagnostic('catalog.forbidden_key', $childPath, 'forbidden legacy option key');
			self::forbiddenKeys($child, $childPath, $errors);
		}
	}

	/** Return first duplicate object-key token, or NULL. */
	private static function duplicateJsonKey(string $raw): ?string
	{
		$length = strlen($raw); $stack = []; $i = 0;
		while ($i < $length) {
			$char = $raw[$i];
			if (ctype_space($char)) { $i++; continue; }
			if ($char === '{') { $stack[] = ['keys'=>[]]; $i++; continue; }
			if ($char === '[') { $stack[] = NULL; $i++; continue; }
			if ($char === '}' || $char === ']') { array_pop($stack); $i++; continue; }
			if ($char !== '"') { $i++; continue; }
			$start = $i++; $decoded = '';
			while ($i < $length) {
				if ($raw[$i] === '\\') { $i += 2; continue; }
				if ($raw[$i] === '"') { $i++; break; }
				$i++;
			}
			$j = $i; while ($j < $length && ctype_space($raw[$j])) $j++;
			if ($j < $length && $raw[$j] === ':' && $stack !== [] && is_array($stack[count($stack)-1])) {
				$key = json_decode(substr($raw, $start, $i - $start), TRUE);
				if (is_string($key)) { $top = count($stack) - 1; if (isset($stack[$top]['keys'][$key])) return $key; $stack[$top]['keys'][$key] = TRUE; }
			}
		}
		return NULL;
	}

	/** @return array{code:string,path:string,severity:string,message:string} */
	private static function diagnostic(string $code, string $path, string $message): array
	{
		return ['code'=>$code, 'path'=>$path, 'severity'=>'error', 'message'=>$message];
	}

	/** @param list<array{code:string,path:string,severity:string,message:string}> $diagnostics @return list<array{code:string,path:string,severity:string,message:string}> */
	private static function sortDiagnostics(array $diagnostics): array
	{
		usort($diagnostics, static fn(array $left, array $right): int => [$left['path'], $left['code']] <=> [$right['path'], $right['code']]);
		return $diagnostics;
	}
}
