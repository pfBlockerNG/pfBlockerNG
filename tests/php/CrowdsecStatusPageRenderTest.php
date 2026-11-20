<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4124 -- what the CrowdSec Status subtab prints of data it does not control (docs/specs/crowdsec-integration.md, D7).
 * The page cannot be loaded off-appliance, so its own helpers and regions are extracted from the shipped source and evaluated
 * (PageStatementLoader.php): a change to the page changes these tests' subject, never a stand-in.
 *
 * Pinned here:
 *   - an origin of the status file, which the LAPI's decisions name, is printed escaped, and one JSON reads back as an integer key
 *     is printed too;
 *   - each field of a lookup's decision (value, scope, origin, scenario, type, duration) is printed escaped;
 *   - a table's contents are paged 100 entries to a page, each table with its own page number, and the count line names the pages.
 */
final class CrowdsecStatusPageRenderTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_crowdsec_status.php';
	private const HOSTILE = '<img src=x onerror=1>"\'';
	private const HOSTILE_ESCAPED = '&lt;img src=x onerror=1&gt;&quot;&#039;';
	private const LOOKUP_FIELDS = ['value', 'scope', 'origin', 'scenario', 'type', 'duration'];

	private string $root = '';
	private mixed $savedPfb;
	/** @var array<string, mixed> */
	private array $savedGet = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		if (!defined('PFB_CROWDSEC_PAGE_SIZE')) {
			pfb_test_page_eval(pfb_test_page_statement(self::PAGE, '/const PFB_CROWDSEC_PAGE_SIZE\s*=/'), []);
		}
	}

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->savedGet = $_GET;
		$this->root = sys_get_temp_dir() . '/pfb_crowdsec_page_' . bin2hex(random_bytes(8));
		mkdir($this->root);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		$_GET = $this->savedGet;
		rmdir_recursive($this->root);
	}

	/** The page's own $families, $h and $panel, which its regions use. */
	private static function helpers(): string
	{
		return implode("\n", array_map(static fn (string $name): string => pfb_test_page_statement(self::PAGE, "/\\\${$name}\\s*=/"),
		    ['families', 'h', 'panel']));
	}

	/**
	 * What the page prints for the region between two of its comments.
	 *
	 * @param array<string, mixed> $vars the region's variables
	 */
	private static function render(string $from, string $to, array $vars): string
	{
		ob_start();
		try {
			pfb_test_page_eval(self::helpers() . "\n" . pfb_test_page_region(self::PAGE, $from, $to), $vars);
			return (string) ob_get_contents();
		} finally {
			ob_end_clean();
		}
	}

	/** The status file as the page reads it, with $origins as the IPv4 origins. */
	private function statusRead(array $origins): array
	{
		$path = "{$this->root}/status.json";
		file_put_contents($path, json_encode([
			'version' => '0.1.0', 'start_time' => 1, 'update_frequency_seconds' => 10, 'updated_at' => 1000, 'last_pull' => 4,
			'last_error_time' => 0, 'last_error' => '', 'lapi_requests' => 9, 'lapi_errors' => 0,
			'banned' => ['ipv4' => ['total' => array_sum($origins), 'origins' => (object) $origins], 'ipv6' => ['total' => 0, 'origins' => new stdClass()]],
			'dropped' => ['ipv4' => ['packets' => 0, 'bytes' => 0], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
		], JSON_THROW_ON_ERROR));
		$status = pfb_crowdsec_status_read($path);
		$this->assertIsArray($status, 'fixture: the status file reads');
		return $status;
	}

	// ---- the origins of the decisions -------------------------------------------------------------

	public function testAnOriginTheStatusFileNamesIsPrintedEscapedAndAnIntegerOneToo(): void
	{
		$origin = '<script>alert(1)</script>"\'&';
		$status = $this->statusRead([$origin => 2, '123' => 1]);
		$this->assertSame([$origin => 2, 123 => 1], $status['banned']['ipv4']['origins'], 'before-state: "123" reads back as an integer key');

		$html = self::render('// Decisions and counters', "// The tables' contents", ['status' => $status]);

		preg_match_all('~<tr class="cs-banned"><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td></tr>~', $html, $rows, PREG_SET_ORDER);
		$ipv4 = array_map(static fn (array $row): array => array_slice($row, 1), array_filter($rows, static fn (array $row): bool => $row[1] === 'IPv4'));
		$this->assertContains(['IPv4', '&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#039;&amp;', '2'], $ipv4, 'the hostile origin, escaped: ' . $html);
		$this->assertContains(['IPv4', '123', '1'], $ipv4, 'the integer origin');
		$this->assertStringNotContainsString('<script>', $html);
	}

	// ---- the lookup's decisions -------------------------------------------------------------------

	/** @return iterable<string, array{string, int}> the decision's field => its column */
	public static function lookupFields(): iterable
	{
		foreach (self::LOOKUP_FIELDS as $column => $field) {
			yield $field => [$field, $column];
		}
	}

	#[DataProvider('lookupFields')]
	public function testEachFieldOfALookupDecisionIsPrintedEscaped(string $field, int $column): void
	{
		$decision = ['value' => '192.0.2.1', 'scope' => 'Ip', 'origin' => 'crowdsec', 'scenario' => 'crowdsecurity/ssh-bf', 'type' => 'ban',
		    'duration' => '3h59m'];
		$expected = array_values($decision);
		$decision[$field] = self::HOSTILE;
		$expected[$column] = self::HOSTILE_ESCAPED;

		$html = self::render('// Lookup', '// Log', ['lookup' => ['error' => NULL, 'decisions' => [$decision]], 'lookup_ip' => '192.0.2.1']);

		$this->assertSame(1, preg_match('~<tr class="cs-decision">(.*?)</tr>~s', $html, $row), 'the decision is a row: ' . $html);
		preg_match_all('~<td>(.*?)</td>~s', $row[1], $cells);
		$this->assertSame($expected, $cells[1], "the {$field} cell, escaped");
		$this->assertStringNotContainsString('<img', $html);
	}

	// ---- a table's pages --------------------------------------------------------------------------

	/** @return iterable<string, array{int, int, int}> page => its first and last entry */
	public static function pages(): iterable
	{
		yield 'first'  => [1, 1, 100];
		yield 'second' => [2, 101, 200];
		yield 'last'   => [3, 201, 250];
	}

	#[DataProvider('pages')]
	public function testATableShowsOneHundredEntriesToAPage(int $page, int $first, int $last): void
	{
		$entries = array_map(static fn (int $n): string => "198.51.100.{$n}", range(1, 250));
		$entries6 = array_map(static fn (int $n): string => sprintf('2001:db8::%x', $n), range(1, 250));
		foreach (['crowdsec_v4' => $entries, 'crowdsec_v6' => $entries6] as $table => $list) {
			file_put_contents("{$this->root}/{$table}", implode('', array_map(static fn (string $entry): string => "   {$entry}\n", $list)));
		}
		$GLOBALS['pfb']['pfctl'] = "{$this->root}/pfctl";
		file_put_contents($GLOBALS['pfb']['pfctl'], "#!/bin/sh\ncat " . escapeshellarg("{$this->root}/") . "\"\$2\"\n");
		chmod($GLOBALS['pfb']['pfctl'], 0755);
		$_GET = ['page_ipv4' => (string) $page];

		$html = self::render("// The tables' contents", '// Lookup', []);

		$this->assertSame(1, preg_match('~<pre id="cs-table-ipv4">(.*?)</pre>~s', $html, $shown), 'the table is shown: ' . $html);
		$this->assertSame(array_slice($entries, $first - 1, $last - $first + 1), explode("\n", $shown[1]), "entries {$first} to {$last}");
		$this->assertStringContainsString("<p id=\"cs-table-ipv4-count\">250 entries; page {$page} of 3.</p>", $html);
		// The IPv6 table keeps its own page: the IPv4 page number does not move it
		$this->assertSame(1, preg_match('~<pre id="cs-table-ipv6">(.*?)</pre>~s', $html, $shown6), 'the IPv6 table is shown: ' . $html);
		$this->assertSame(array_slice($entries6, 0, 100), explode("\n", $shown6[1]), 'the IPv6 table stays on its first page');
		$this->assertStringContainsString('<p id="cs-table-ipv6-count">250 entries; page 1 of 3.</p>', $html);
	}
}
