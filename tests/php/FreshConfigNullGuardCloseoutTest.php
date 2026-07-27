<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Closes out issue #1768: a live functional-UI render sweep (run 30249107774)
 * found 2 "Passing null" deprecation sites the original #1768 commit missed.
 * Both are single-argument string calls reading a value that is absent on a
 * fresh box/request, exactly the same deprecation class #1768 already closed
 * ~85 other call sites for.
 *
 * - www/index.php:37 -- the per-request $ptype[$server_type] build reads
 *   $_SERVER[$server_type] directly for HTTP_REFERER/HTTP_USER_AGENT, which a
 *   client is not required to send; an absent key is NULL, passed straight
 *   into htmlspecialchars().
 * - pfblockerng.widget.php:695 -- the DNSBL row of the "Queries" stat block
 *   reads $pfb_table['stats']['DNSBL'], which is populated ONLY inside the
 *   `if (!empty($pfb_table))` loop over update-table entries; on a fresh box
 *   (no aliases/lists synced yet) that loop never runs and the key stays
 *   unset.
 *
 * Neither file is require()-able off-appliance (index.php is top-level page
 * execution; the widget file's stat block lives inside pfBlockerNG_get_header(),
 * a page-scoped function with prior SQLite/session setup this test does not
 * want to stand up) -- so, following DnsblFreshPconfigTest/AlertsFreshTopBlockTest's
 * established idiom, each narrow region is eval-extracted VERBATIM from the
 * real shipped source and run as a pure function of its inputs. The
 * extraction regexes are non-greedy / guard-state-agnostic, so this same test
 * file is red against the pre-fix source and green after the fix, unchanged.
 */
final class FreshConfigNullGuardCloseoutTest extends TestCase
{
	private const INDEX_PHP  = __DIR__ . '/../../src/usr/local/www/pfblockerng/www/index.php';
	private const WIDGET_PHP = __DIR__ . '/../../src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	public static function setUpBeforeClass(): void
	{
		if (!function_exists('pfb_index_oracle_ptype_server_field')) {
			$src = file_get_contents(self::INDEX_PHP);
			if ($src === FALSE) {
				throw new RuntimeException('test bootstrap: failed to read www/index.php');
			}
			if (!preg_match(
				'/\$ptype\[\$server_type\] = \(\$server_value = htmlspecialchars\(\$_SERVER\[\$server_type\][^\n]*\n/',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: index.php $ptype server-field line not found');
			}
			eval(
				'function pfb_index_oracle_ptype_server_field(bool $setKey, string $value = \'\'): string {'
				. ' $ptype = array(); $server_type = \'HTTP_REFERER\';'
				. ' if ($setKey) { $_SERVER[$server_type] = $value; } else { unset($_SERVER[$server_type]); }'
				. $m[0]
				. ' return $ptype[$server_type]; }'
			);
		}

		if (!function_exists('pfb_widget_oracle_dnsbl_stat')) {
			$src = file_get_contents(self::WIDGET_PHP);
			if ($src === FALSE) {
				throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
			}
			if (!preg_match(
				'/(if \(\$type == \'DNSBL\'\) \{\n.*?\n\t\t\t\})\n/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: widget DNSBL stat block not found');
			}
			eval(
				'function pfb_widget_oracle_dnsbl_stat(array $pfb, array $pfb_table): string {'
				. ' $stats = array(); $key = 0; $type = \'DNSBL\';'
				. $m[1]
				. ' return $stats[$key][$type]; }'
			);
		}
	}

	private bool $hadServerReferer;
	private mixed $savedServerReferer;

	protected function setUp(): void
	{
		$this->hadServerReferer   = array_key_exists('HTTP_REFERER', $_SERVER);
		$this->savedServerReferer = $_SERVER['HTTP_REFERER'] ?? null;
	}

	protected function tearDown(): void
	{
		if ($this->hadServerReferer) {
			$_SERVER['HTTP_REFERER'] = $this->savedServerReferer;
		} else {
			unset($_SERVER['HTTP_REFERER']);
		}
	}

	/** @return string[] the diagnostics whose message is a "Passing null" deprecation */
	private static function nullDeprecationsOnly(array $diagnostics): array
	{
		return array_values(array_filter(
			$diagnostics,
			static fn(string $d): bool => str_contains($d, 'Passing null')
		));
	}

	private function runCapturing(callable $fn): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		return [$result, $diagnostics];
	}

	// -----------------------------------------------------------------------
	// www/index.php:37 -- $ptype[$server_type] server-header read.
	// -----------------------------------------------------------------------

	public function testIndexPtypeServerFieldEmitsNoPassingNullDeprecationWhenHeaderAbsent(): void
	{
		[$result, $diagnostics] = $this->runCapturing(
			static fn (): string => pfb_index_oracle_ptype_server_field(FALSE)
		);

		$this->assertSame(
			[],
			self::nullDeprecationsOnly($diagnostics),
			"index.php's \$ptype server-field build must emit zero 'Passing null' deprecations when the client sends no Referer header, got:\n"
			. implode("\n", self::nullDeprecationsOnly($diagnostics))
		);
		$this->assertSame('Unknown', $result, 'an absent header must still fall back to "Unknown" (behaviour-preserving)');
	}

	public function testIndexPtypeServerFieldPassesThroughAPopulatedHeaderUnchanged(): void
	{
		[$result, $diagnostics] = $this->runCapturing(
			static fn (): string => pfb_index_oracle_ptype_server_field(TRUE, 'https://example.com/<script>')
		);

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertSame(
			'https://example.com/&lt;script&gt;',
			$result,
			'a present header must still pass through htmlspecialchars() unchanged (behaviour-preserving)'
		);
	}

	// -----------------------------------------------------------------------
	// pfblockerng.widget.php:695 -- Queries/DNSBL stat read.
	// -----------------------------------------------------------------------

	public function testWidgetDnsblStatEmitsNoPassingNullDeprecationOnAFreshBox(): void
	{
		// Fresh box: pfBlockerNG_update_table() returned nothing to accumulate,
		// so the 'DNSBL' key of $pfb_table['stats'] was never populated.
		[$result, $diagnostics] = $this->runCapturing(
			static fn (): string => pfb_widget_oracle_dnsbl_stat([], ['stats' => []])
		);

		$this->assertSame(
			[],
			self::nullDeprecationsOnly($diagnostics),
			"the widget's DNSBL 'Queries' stat read must emit zero 'Passing null' deprecations on a fresh box, got:\n"
			. implode("\n", self::nullDeprecationsOnly($diagnostics))
		);
		$this->assertSame('', $result, 'an absent DNSBL stat must render as an empty string, not the literal "0" or a warning');
	}

	public function testWidgetDnsblStatPassesThroughAPopulatedCountUnchanged(): void
	{
		[$result, $diagnostics] = $this->runCapturing(
			static fn (): string => pfb_widget_oracle_dnsbl_stat([], ['stats' => ['DNSBL' => 1500]])
		);

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertSame('1500', $result, 'a real populated count must still render unchanged (behaviour-preserving)');
	}

	public function testWidgetDnsblStatSqliteMissingBranchIsUnaffectedByTheGuard(): void
	{
		// The 'dnsbl_missing' branch never reaches the guarded read at all --
		// confirms the fix did not disturb the sibling branch.
		[$result, $diagnostics] = $this->runCapturing(
			static fn (): string => pfb_widget_oracle_dnsbl_stat(['dnsbl_missing' => TRUE], ['stats' => []])
		);

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertStringContainsString('Unknown', $result);
	}
}
