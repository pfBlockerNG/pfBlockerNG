<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_normalize_row_header() (issue #1270).
 *
 * sync_package_pfblockerng()'s periodic sync \W-strips a stored list-row
 * Header and persists the normalised value via config_set_path() +
 * write_config(), with NO reserved-name check -- so a Header arriving via
 * config import/XML restore/HA-sync (never through the GUI) can normalise
 * onto (or already equal) a reserved package-owned name and silently collide
 * on disk. This is the pure normalise-then-judge decision the runtime wiring
 * calls. Pure, brand-new function (no pre-existing behaviour to pin --
 * CLAUDE.md Test coverage #1 exception 2).
 */
#[CoversFunction('pfb_normalize_row_header')]
final class NormalizeRowHeaderTest extends TestCase
{
	protected function setUp(): void
	{
		$continents = $GLOBALS['pfb']['continents'] ?? null;
		if (!is_array($continents) || count($continents) !== 9) {
			throw new RuntimeException('$pfb[continents] must have exactly 9 entries; got: ' . var_export($continents, true));
		}
	}

	public static function casesProvider(): array
	{
		return [
			'already-reserved, no \W'                             => ['DNSBLIP', 'DNSBLIP', FALSE, TRUE],
			'strips onto reserved (DNSBL-IP -> DNSBLIP)'          => ['DNSBL-IP', 'DNSBLIP', TRUE, TRUE],
			"strips onto 'dedup' (out of #1270 scope, not reserved)" => ['de-dup', 'dedup', TRUE, FALSE],
			'underscore is \w -- no strip needed'                 => ['de_dup', 'de_dup', FALSE, FALSE],
			"strips to 'pfBAfrica', NOT the continent literal 'pfB_Africa'" => ['pfB.Africa', 'pfBAfrica', TRUE, FALSE],
			'clean, ordinary header'                              => ['MyBlocklist', 'MyBlocklist', FALSE, FALSE],
			'empty header'                                        => ['', '', FALSE, FALSE],
		];
	}

	#[DataProvider('casesProvider')]
	public function testNormalizeAndJudge(string $header, string $expectHeader, bool $expectChanged, bool $expectReserved): void
	{
		$out = pfb_normalize_row_header($header);

		$this->assertSame($expectHeader, $out['header'], "header for input '{$header}'");
		$this->assertSame($expectChanged, $out['changed'], "changed for input '{$header}'");
		if ($expectReserved) {
			$this->assertNotSame('', $out['reserved_error'], "reserved_error for input '{$header}'");
		} else {
			$this->assertSame('', $out['reserved_error'], "reserved_error for input '{$header}'");
		}
	}

	public function testReturnShapeHasExactlyTheThreeContractedKeys(): void
	{
		$out = pfb_normalize_row_header('x');
		$this->assertSame(['header', 'changed', 'reserved_error'], array_keys($out));
	}

	/**
	 * issue #1270: a config row missing 'header' (foreign/malformed config --
	 * exactly the audience this fix defends against) evaluates to NULL, which
	 * TypeErrors on the strict $header param -- pins WHY the call site casts.
	 */
	public function testUnguardedMissingHeaderKeyThrowsTypeError(): void
	{
		$row = ['url' => 'http://example.test'];
		// Isolates the hazard from the missing-key access itself: $missing is the
		// SAME null a bare $row['header'] would yield, without an extra warning.
		$missing = $row['header'] ?? null;
		$this->expectException(\TypeError::class);
		/** @phpstan-ignore-next-line intentionally uncast -- reproduces the pre-fix call site */
		pfb_normalize_row_header($missing);
	}

	/** The call-site's guard pattern -- (string) ($row['header'] ?? '') -- is safe. */
	public function testCallSiteCastPatternHandlesMissingHeaderKeySafely(): void
	{
		$row = ['url' => 'http://example.test'];
		$this->assertSame(
			['header' => '', 'changed' => FALSE, 'reserved_error' => ''],
			pfb_normalize_row_header((string) ($row['header'] ?? ''))
		);
	}
}
