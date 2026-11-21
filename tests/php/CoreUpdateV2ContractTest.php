<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4037 (slice 8a): the version 2 contract of the update command, frozen as tests/core/fixtures/apply_contract_v2.json
 * (docs/misc/core-api-protocol.md, "Update command, version 2"). Nothing calls these functions in production yet: Core's
 * worker writes version 1 until #4038, which runs the same fixture from Go.
 *   - a request is validated whole before anything runs: a refused one is refused with its reason, word for word, and an
 *     accepted one comes back in one normal form (defaults filled, each ip-set and ip-aggregate with its alias, each issue's
 *     message cut to bounded text);
 *   - a resource id maps to an alias by one rule (decision 1 of the issue), and an id that maps to none refuses the request:
 *     distinct ids never share an alias, as an ip-set cannot take an aggregate's;
 *   - a request names at most the fixture's limits.ids ids, and the report of every request accepted fits one result line
 *     (testTheLongestReportOfARequestAtTheBoundFitsOneResultLine);
 *   - a result line is written in one fixed shape, never longer than the fixture's resultLineBytes (a failure message longer
 *     than the placeholder is shortened first), and a report the contract does not hold is refused, never written.
 */
#[CoversFunction('pfb_core_update_v2_request')]
#[CoversFunction('pfb_core_update_v2_alias')]
#[CoversFunction('pfb_core_update_v2_result')]
final class CoreUpdateV2ContractTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/apply_contract_v2.json';

	/** The issue's hostile-input rows this slice owns, plus the brief's: a fixture that drops one of them fails. */
	private const HOSTILE_ROWS = [
		'not-json', 'json-array', 'two-objects', 'data-after-the-object', 'over-1-mib', 'ten-mib', 'version-1', 'unknown-field',
		'duplicate-id', 'duplicate-id-across-removed', 'id-dot-dot', 'id-slash-in-a-segment', 'id-control-character', 'id-nul',
		'id-line-break', 'resources-10000', 'resources-4097', 'id-dnsbl', 'id-settings', 'alias-collision', 'generation-number',
		'generation-negative', 'generation-fraction', 'entries-negative', 'entries-fraction', 'action-unknown', 'direction-unknown',
		'token-nul', 'token-line-break', 'dnsbl-group-name-nul', 'issue-code-nul', 'issue-resource-line-break',
		'issue-message-of-1-mib', 'issue-message-in-a-request-of-1-mib', 'issue-message-as-text',
	];

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	private static function rows(string $section): array
	{
		$rows = [];
		foreach (self::fixture()[$section] as $row) {
			$rows[$row['id']] = [$row];
		}
		return $rows;
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function requests(): array
	{
		return self::rows('requests');
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function results(): array
	{
		return self::rows('results');
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function aliases(): array
	{
		$rows = [];
		foreach (self::fixture()['aliases'] as $row) {
			$rows[json_encode($row['id'])] = [$row];
		}
		return $rows;
	}

	/**
	 * Bytes given as a string, or as a list of parts joined in order, each a string or {repeat, times}: the string written times
	 * times, every '{i}' in it replaced by the repetition's index from 0 (see the fixture's `about`).
	 *
	 * @param string|list<string|stdClass> $parts
	 */
	private static function joined(string|array $parts): string
	{
		$bytes = '';
		foreach (is_array($parts) ? $parts : [$parts] as $part) {
			if (is_string($part)) {
				$bytes .= $part;
				continue;
			}
			for ($i = 0; $i < $part->times; $i++) {
				$bytes .= str_replace('{i}', (string) $i, $part->repeat);
			}
		}
		return $bytes;
	}

	/** The row $id of $section, decoded as objects, so that {} stays an object and the keys keep their order. */
	private static function raw(string $section, string $id): stdClass
	{
		foreach (json_decode((string) file_get_contents(self::FIXTURE), FALSE, 512, JSON_THROW_ON_ERROR)->{$section} as $row) {
			if ($row->id === $id) {
				return $row;
			}
		}
		throw new LogicException("no {$section} row {$id}");
	}

	/** The stdin of a request row: its `request` written as JSON, or its `stdin` joined. */
	private static function stdin(string $id): string
	{
		$row = self::raw('requests', $id);
		if (property_exists($row, 'request')) {
			return json_encode($row->request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
		}
		return self::joined($row->stdin);
	}

	/**
	 * The report of a result row: its `report`, or its `reportJSON` joined and decoded; and its `line` joined.
	 *
	 * @return array{0: array<string, mixed>, 1: ?string}
	 */
	private static function resultRow(string $id): array
	{
		$row = self::raw('results', $id);
		$report = property_exists($row, 'report') ? json_decode(json_encode($row->report, JSON_THROW_ON_ERROR), TRUE, 512, JSON_THROW_ON_ERROR)
			: json_decode(self::joined($row->reportJSON), TRUE, 512, JSON_THROW_ON_ERROR);
		return [$report, property_exists($row, 'line') ? self::joined($row->line) : NULL];
	}

	public function testTheFixtureIsTheVersion2ContractAndHoldsEveryHostileRow(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('update-command-version-2', $doc['contract']);
		foreach (['requests', 'results', 'aliases'] as $section) {
			$ids = array_column($doc[$section], 'id');
			$this->assertSame(array_values(array_unique($ids)), $ids, "{$section}: a row id appears once");
		}
		$ids = array_column($doc['requests'], 'id');
		$this->assertSame([], array_values(array_diff(self::HOSTILE_ROWS, $ids)), 'every hostile-input row is in the fixture');
		foreach ($doc['requests'] as $row) {
			$this->assertCount(1, array_intersect(['request', 'stdin'], array_keys($row)), "{$row['id']}: one input");
			$this->assertCount(1, array_intersect(['accepted', 'acceptedCounts', 'refused'], array_keys($row)), "{$row['id']}: one verdict");
		}
		foreach (['over-1-mib' => $doc['limits']['requestBytes'] + 1, 'issue-message-in-a-request-of-1-mib' => $doc['limits']['requestBytes'],
			'ten-mib' => 10 * $doc['limits']['requestBytes']] as $id => $bytes) {
			$this->assertGreaterThanOrEqual($bytes, strlen(self::stdin($id)), "{$id}: the input is as large as the row says");
		}
		$this->assertSame($doc['limits']['requestBytes'], strlen(self::stdin('issue-message-in-a-request-of-1-mib')), 'the boundary row is exactly at the bound');
		$this->assertSame($doc['limits']['requestBytes'] + 1, strlen(self::stdin('over-1-mib')), 'the row over the bound is one byte over it');
		$this->assertSame(PFB_CORE_UPDATE_MAX_REQUEST, $doc['limits']['requestBytes'], 'the bound is the one pfblockerng.inc reads stdin to');
		$this->assertSame(PFB_CORE_UPDATE_V2_LINE_BYTES, $doc['limits']['resultLineBytes'], 'the bound is the one the result writer keeps to');
		$this->assertSame(PFB_CORE_UPDATE_V2_MAX_IDS, $doc['limits']['ids'], 'the bound on the ids of a request and of a report');
		foreach ($doc['results'] as $row) {
			$this->assertCount(1, array_intersect(['report', 'reportJSON'], array_keys($row)), "{$row['id']}: one report");
			$this->assertCount(1, array_intersect(['line', 'refused'], array_keys($row)), "{$row['id']}: one verdict");
		}
		$this->assertSame($doc['limits']['resultLineBytes'], strlen((string) self::resultRow('failed-line-at-the-bound')[1]), 'the boundary line is exactly at the bound');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('requests')]
	public function testTheValidatorGivesTheRowsVerdict(array $row): void
	{
		$stdin = self::stdin($row['id']);
		if (array_key_exists('refused', $row)) {
			try {
				$request = pfb_core_update_v2_request($stdin);
			} catch (InvalidArgumentException $e) {
				$this->assertSame($row['refused'], $e->getMessage(), "{$row['id']}: the reason of the refusal");
				return;
			}
			$this->fail("{$row['id']}: accepted, expected the refusal \"{$row['refused']}\"; got " . json_encode($request, JSON_PARTIAL_OUTPUT_ON_ERROR));
		}
		$request = pfb_core_update_v2_request($stdin);
		if (array_key_exists('acceptedCounts', $row)) {
			foreach ($row['acceptedCounts'] as $list => $count) {
				$this->assertCount($count, $request[$list], "{$row['id']}: {$list}");
			}
			$this->assertSame(array_values(array_unique(array_column($request['resources'], 'alias'))), array_column($request['resources'], 'alias'),
				"{$row['id']}: every resource has an alias of its own");
			return;
		}
		$this->assertSame($row['accepted'], $request, "{$row['id']}: the normal form");
	}

	/** @param array{id: string, alias: ?string} $row */
	#[DataProvider('aliases')]
	public function testAResourceIdMapsToItsAliasByOneRule(array $row): void
	{
		$this->assertSame($row['alias'], pfb_core_update_v2_alias($row['id']), json_encode($row['id']) . ': its alias');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('results')]
	public function testTheResultWriterGivesTheRowsLine(array $row): void
	{
		[$report, $expected] = self::resultRow($row['id']);
		if (array_key_exists('refused', $row)) {
			try {
				$line = pfb_core_update_v2_result($report);
			} catch (InvalidArgumentException $e) {
				$this->assertSame($row['refused'], $e->getMessage(), "{$row['id']}: the reason of the refusal");
				return;
			}
			$this->fail("{$row['id']}: written as a line of " . strlen($line) . " bytes, expected the refusal \"{$row['refused']}\"");
		}
		$line = pfb_core_update_v2_result($report);
		if (strlen((string) $expected) > 8192) {
			// a large line is compared by its length and digest, so that a failure does not print megabytes
			$this->assertSame([strlen((string) $expected), hash('sha256', (string) $expected)], [strlen($line), hash('sha256', $line)],
				"{$row['id']}: the line, byte for byte; it begins " . substr($line, 0, 300));
		} else {
			$this->assertSame($expected, $line, "{$row['id']}: the line, byte for byte");
		}
		$this->assertLessThanOrEqual(self::fixture()['limits']['resultLineBytes'], strlen($line), "{$row['id']}: within the bound of a line");
		$this->assertStringEndsWith("\n", $line);
		$this->assertSame(1, substr_count($line, "\n"), "{$row['id']}: one line");
		$this->assertSame(1, preg_match('/^[\x20-\x7e]*\n\z/', $line), "{$row['id']}: printable ASCII and one newline");
		$this->assertSame(2, json_decode($line, TRUE, 8, JSON_THROW_ON_ERROR)['version'], "{$row['id']}: of version 2");
	}

	/** @return array<string, array{0: string}> */
	public static function everyIdOfOneKind(): array
	{
		return ['every id failed' => ['failed'], 'every id applied' => ['applied'], 'every id removed' => ['removed']];
	}

	/**
	 * The report of a request at the bound fits one result line, whatever the apply did. A line is the sum of its entries, so
	 * the longest is a report whose every id is of one kind: failed, applied or removed (a mix lies between them, and a line that
	 * fits before its failure messages are shortened is written as it is). Each is built from the rules the code holds: the
	 * longest id the request takes, the longest generation, a message as long as it may be written, an alias for every table.
	 */
	#[DataProvider('everyIdOfOneKind')]
	public function testTheLongestReportOfARequestAtTheBoundFitsOneResultLine(string $kind): void
	{
		$limits = self::fixture()['limits'];
		$group = $limits['idBytes'];
		while (pfb_core_update_v2_alias('ip-set/' . str_repeat('G', $group) . '/ipv4') === NULL) {
			$group--;
		}
		$generation = '18446744073709551615';
		$this->assertTrue(pfb_core_generation($generation) && !pfb_core_generation("{$generation}0") && !pfb_core_generation('18446744073709551616'),
			'the longest generation');
		$ids = $aliases = $resources = [];
		for ($i = 0; $i < $limits['ids']; $i++) {
			$ids[] = $id = 'ip-set/' . str_pad((string) $i, $group, 'G', STR_PAD_LEFT) . '/ipv' . ($i % 2 === 0 ? '4' : '6');
			$aliases[] = (string) pfb_core_update_v2_alias($id);
			$resources[] = ['id' => $id, 'generation' => $generation, 'action' => 'deny', 'direction' => ['ingress', 'egress'], 'entries' => PHP_INT_MAX];
		}
		$this->assertGreaterThan(strlen('ip-aggregate/permit/ipv6'), strlen($ids[0]), 'an ip-set id is the longest an alias allows');
		$request = ['version' => 2, 'trigger' => 'scheduled'] + ($kind === 'removed' ? ['removed' => $ids] : ['resources' => $resources]);
		$accepted = pfb_core_update_v2_request(json_encode($request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
		$this->assertCount($limits['ids'], [...$accepted['resources'], ...$accepted['removed']], 'the request is at the bound, and accepted');

		$report = match ($kind) {
			'failed'  => ['failed' => array_map(static fn (string $id): array => ['id' => $id, 'stage' => 'apply',
				'message' => str_repeat('a', 2 * $limits['messageBytes'])], $ids)],
			'applied' => ['applied' => array_fill_keys($ids, $generation)],
			default   => ['removed' => $ids],
		};
		$line = pfb_core_update_v2_result($report + ['changedAliases' => $aliases, 'ipChanged' => FALSE, 'dnsblChanged' => FALSE,
			'reloadLaunched' => FALSE]);

		$this->assertLessThanOrEqual($limits['resultLineBytes'], strlen($line), "every id {$kind}: within the bound of a line");
		if ($kind === 'failed') {
			$this->assertSame(286826, strlen($line), 'the longest line the docs state (docs/misc/core-api-protocol.md states the same 286826: change both together)');
		}
		$this->assertSame($limits['ids'], substr_count($line, '"pfB_'), "every id {$kind}: every alias is on the line");
	}

	/** A failure message's invalid UTF-8 is replaced before its line break becomes a space. JSON cannot hold the byte: no row can. */
	public function testAFailureMessageOfInvalidUtf8BesideALineBreakIsWrittenAsText(): void
	{
		$this->assertSame('{"version":2,"failed":[{"id":"geo-catalog","stage":"apply","message":"a? b"}]}' . "\n",
			pfb_core_update_v2_result(['failed' => [['id' => 'geo-catalog', 'stage' => 'apply', 'message' => "a\xff\nb"]]]));
	}
}
