<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * IP regex prefilter guards (pfblockerng.inc, inside sync_package_pfblockerng,
 * not unit-reachable directly — pinned here against the real regex literals
 * extracted from the production file).
 *
 * The two preg_match_all fallback parsers run on $oline (the original feed line,
 * which may carry IPs embedded in mid-line noise) and are gated by a cheap
 * necessary-condition prefilter that skips the regex engine when the line cannot
 * possibly contain a match:
 *
 *   IPv4 (~:12602):  substr_count($oline, '.') >= 3 && preg_match_all($pfb['ipv4'], ...)
 *   IPv6 (~:12675):  strpos($oline, ':') !== FALSE && preg_match_all($pfb['ipv6'], ...)
 *
 * The guards must be necessary conditions of a match — a line the guard rejects
 * can NEVER match the regex — so the guarded path returns the byte-identical set
 * the unguarded path did. The DANGEROUS rewrite this pins against is anchoring the
 * predicate to the START of the line (e.g. "starts with a digit / hex / colon"),
 * which would silently DROP the embedded-in-noise matches the fallback exists to
 * catch (<td>192.0.2.10</td>, "host blocked 198.51.100.7", <span>2001:db8::1</span>).
 *
 * Scenario: the prefilter never changes the parser's output.
 *   Background:
 *     Given the production IPv4/IPv6 regex literals read from pfblockerng.inc
 *     And a corpus spanning clean addresses, embedded-in-noise addresses, and
 *         negatives that fail the dot-count / colon necessary condition.
 *     When each line is run through the unguarded regex and the guarded predicate.
 *     Then the two produce the identical match set for every line.
 */
final class IpRegexPrefilterGuardTest extends TestCase
{
	private static string $reV4;
	private static string $reV6;
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
		self::$src = (string) file_get_contents($path);

		// Extract the real regex literals (single-line, single-quoted) so the
		// invariant tracks the shipped regex — a regex change that let a guarded
		// line slip through would break the equivalence assertions below.
		self::assertSame(1, preg_match("/\\\$pfb\\['ipv4'\\]\\s*=\\s*'(.*)';/", self::$src, $m4),
			'could not locate $pfb[\'ipv4\'] literal');
		self::assertSame(1, preg_match("/\\\$pfb\\['ipv6'\\]\\s*=\\s*'(.*)';/", self::$src, $m6),
			'could not locate $pfb[\'ipv6\'] literal');
		self::$reV4 = $m4[1];
		self::$reV6 = $m6[1];
	}

	/** Mimic the production IPv4 guarded path: dot-count guard then regex. */
	private function guardedV4(string $line): array
	{
		if (substr_count($line, '.') >= 3 && preg_match_all(self::$reV4, $line, $m)) {
			return $m[0];
		}
		return [];
	}

	/** Mimic the production IPv6 guarded path: colon-presence guard then regex. */
	private function guardedV6(string $line): array
	{
		if (strpos($line, ':') !== FALSE && preg_match_all(self::$reV6, $line, $m)) {
			return $m[0];
		}
		return [];
	}

	/** The unguarded reference: raw regex, exactly the pre-guard behaviour. */
	private function unguarded(string $re, string $line): array
	{
		return preg_match_all($re, $line, $m) ? $m[0] : [];
	}

	/**
	 * Lines where the IPv4 fallback regex extracts at least one address — clean
	 * AND embedded in mid-line noise (the cases a start-anchored guard would lose).
	 */
	public static function ipv4MatchingLines(): array
	{
		return [
			'clean address'            => ['192.168.0.1'],
			'clean cidr'               => ['203.0.113.5/24'],
			'embedded in html cell'    => ['<td class="ip">192.0.2.10</td>'],
			'leading words'            => ['host blocked 198.51.100.7 reason=x'],
			'leading whitespace'       => ["\t10.0.0.1"],
			'two addresses one line'   => ['from 192.0.2.1 to 192.0.2.9'],
		];
	}

	/** Lines the IPv4 dot-count guard rejects — none can contain a v4 match. */
	public static function ipv4NonMatchingLines(): array
	{
		return [
			'no dots, pure text'       => ['# a comment header, words only'],
			'two dots only'            => ['ver 1.2.3 not an address here'],
			'colon-only v6 line'       => ['2001:db8::1'],
			'empty'                    => [''],
		];
	}

	public static function ipv6MatchingLines(): array
	{
		return [
			'clean compressed'         => ['2001:db8::1'],
			'clean full'               => ['2001:db8:0:0:0:0:0:5'],
			'embedded in html span'    => ['<span>2001:db8::1</span>'],
			'leading words'            => ['deny 2001:db8:0:0:0:0:0:5 logged'],
			'v4-mapped leading colon'  => [' ::ffff:192.0.2.1 mapped'],
			'link-local'              => ['fe80::1 dev eth0'],
		];
	}

	/** Lines the IPv6 colon guard rejects — none can contain a v6 match. */
	public static function ipv6NonMatchingLines(): array
	{
		return [
			'no colon, pure text'      => ['plain-hostname-no-separator'],
			'dotted v4 only'           => ['192.168.0.1/24'],
			'empty'                    => [''],
		];
	}

	/**
	 * Then: guard PASSES and the guarded set equals the unguarded set (no loss).
	 */
	#[DataProvider('ipv4MatchingLines')]
	public function testIpv4GuardPreservesMatches(string $line): void
	{
		$unguarded = $this->unguarded(self::$reV4, $line);
		$this->assertNotEmpty($unguarded, 'fixture must be a matching line');
		$this->assertSame($unguarded, $this->guardedV4($line),
			"IPv4 guard changed the match set for: {$line}");
	}

	/**
	 * Then: guard REJECTS (or regex would anyway) — both yield the empty set.
	 */
	#[DataProvider('ipv4NonMatchingLines')]
	public function testIpv4GuardRejectsNonMatches(string $line): void
	{
		$this->assertSame([], $this->unguarded(self::$reV4, $line),
			'fixture must be a non-matching line');
		$this->assertSame([], $this->guardedV4($line));
	}

	/**
	 * Then: guard PASSES and the guarded set equals the unguarded set (no loss).
	 */
	#[DataProvider('ipv6MatchingLines')]
	public function testIpv6GuardPreservesMatches(string $line): void
	{
		$unguarded = $this->unguarded(self::$reV6, $line);
		$this->assertNotEmpty($unguarded, 'fixture must be a matching line');
		$this->assertSame($unguarded, $this->guardedV6($line),
			"IPv6 guard changed the match set for: {$line}");
	}

	/**
	 * Then: guard REJECTS (or regex would anyway) — both yield the empty set.
	 */
	#[DataProvider('ipv6NonMatchingLines')]
	public function testIpv6GuardRejectsNonMatches(string $line): void
	{
		$this->assertSame([], $this->unguarded(self::$reV6, $line),
			'fixture must be a non-matching line');
		$this->assertSame([], $this->guardedV6($line));
	}

	/**
	 * Source-pin: the shipped guards are the necessary-condition (presence) form,
	 * NOT a start-anchored one. If someone rewrites either guard to test the line
	 * START, the embedded-match data-provider cases above already fail; this pins
	 * the exact predicate so the guard cannot be silently dropped or re-shaped.
	 */
	public function testProductionGuardsArePresenceChecks(): void
	{
		$this->assertStringContainsString(
			"substr_count(\$oline, '.') >= 3 && preg_match_all(\$pfb['ipv4'], \$oline, \$matches)",
			self::$src, 'IPv4 dot-count prefilter guard missing or altered');
		$this->assertStringContainsString(
			"strpos(\$oline, ':') !== FALSE && preg_match_all(\$pfb['ipv6'], \$oline, \$matches)",
			self::$src, 'IPv6 colon prefilter guard missing or altered');
	}
}
