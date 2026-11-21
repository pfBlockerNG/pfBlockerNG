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
 *   - a resource id maps to an alias by one rule (decision 1 of the issue), and an id that maps to none, or two ids that map
 *     to one alias, refuse the request;
 *   - a result line is written in one fixed shape, and a report the contract does not hold is refused, never written.
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

	/** The stdin of a request row: its `request` written as JSON, or its `stdin` parts joined (see the fixture's `about`). */
	private static function stdin(string $id): string
	{
		$raw = (string) file_get_contents(self::FIXTURE);
		foreach (json_decode($raw, FALSE, 512, JSON_THROW_ON_ERROR)->requests as $row) {
			if ($row->id !== $id) {
				continue;
			}
			if (property_exists($row, 'request')) {
				// decoded as objects, so that {} stays an object and the keys keep their order
				return json_encode($row->request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
			}
			$stdin = '';
			foreach (is_array($row->stdin) ? $row->stdin : [$row->stdin] as $part) {
				if (is_string($part)) {
					$stdin .= $part;
					continue;
				}
				for ($i = 0; $i < $part->times; $i++) {
					$stdin .= str_replace('{i}', (string) $i, $part->repeat);
				}
			}
			return $stdin;
		}
		throw new LogicException("no request row {$id}");
	}

	public function testTheFixtureIsTheVersion2ContractAndHoldsEveryHostileRow(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('update-command-version-2', $doc['contract']);
		foreach (['requests', 'results'] as $section) {
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
		if (array_key_exists('refused', $row)) {
			try {
				$line = pfb_core_update_v2_result($row['report']);
			} catch (InvalidArgumentException $e) {
				$this->assertSame($row['refused'], $e->getMessage(), "{$row['id']}: the reason of the refusal");
				return;
			}
			$this->fail("{$row['id']}: written as {$line}, expected the refusal \"{$row['refused']}\"");
		}
		$line = pfb_core_update_v2_result($row['report']);
		$this->assertSame($row['line'], $line, "{$row['id']}: the line, byte for byte");
		$this->assertStringEndsWith("\n", $line);
		$this->assertSame(1, substr_count($line, "\n"), "{$row['id']}: one line");
		$this->assertSame(1, preg_match('/^[\x20-\x7e]*\n\z/', $line), "{$row['id']}: printable ASCII and one newline");
		$this->assertSame(2, json_decode($line, TRUE, 8, JSON_THROW_ON_ERROR)['version'], "{$row['id']}: of version 2");
	}
}
