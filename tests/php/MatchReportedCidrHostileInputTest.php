<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_match_reported_cidr() -- hostile-input coverage for issue #1157.
 *
 * The CIDR candidates this function walks come from grep output over feed files
 * (semi-trusted external input) and are shape-checked only via strpos('/') before this
 * test's fix. A malformed mask/length (empty, non-numeric, oversized, negative-looking)
 * reaches raw arithmetic ("32 - $mask" / a left shift) and either fatals (TypeError,
 * ArithmeticError) or -- on the v6 side, via the off-appliance gen_subnetv6()/Net_IPv6
 * doubles -- returns a false-positive match. A malformed candidate must be silently
 * skipped (issue #843's existing skip pattern), never fatal, never a false match, and
 * never abort the scan of the remaining candidates.
 *
 * Feature: pfb_match_reported_cidr() treats a malformed CIDR candidate as "not a
 *          match candidate", not as a fatal error or an always-true stub
 *
 *   Scenario: v4 malformed masks
 *     empty mask, non-numeric mask, oversized mask (>32), and a leading '-' mask all
 *     yield NULL with no thrown error -- pre-fix the first three fatal (TypeError /
 *     ArithmeticError) and are reproduced here as genuine red rows.
 *
 *   Scenario: v4 valid rows keep their existing behaviour (before-state preserved)
 *     a real /24 containment hit, a real miss, and the boundary mask '/0' (0 is a
 *     legal mask -- the new guard must not reject it) all behave exactly as before
 *     the fix.
 *
 *   Scenario: v4 malformed address
 *     a non-IP address paired with an otherwise well-formed mask is rejected by the
 *     address predicate, not by the arithmetic -- 'banana/24' yields NULL, no throw.
 *
 *   Scenario: v6 malformed lengths
 *     empty length and non-numeric length are the false-positive-producing rows this
 *     issue names (pre-fix they return a spurious match against the off-appliance
 *     gen_subnetv6()/Net_IPv6 doubles); an oversized length (>128) is also rejected.
 *
 *   Scenario: v6 valid rows keep their existing behaviour (before-state preserved)
 *     a real /32 containment hit and a real miss behave exactly as before the fix.
 *
 *   Scenario: v6 malformed prefix
 *     a non-IP prefix paired with an otherwise well-formed length is rejected by the
 *     address predicate -- 'banana/32' yields NULL, no throw.
 *
 *   Scenario: skip, don't abort
 *     a malformed candidate followed by a real matching candidate in the same $result
 *     array still returns the real match -- the guard must `continue`, not stop the scan.
 */
#[CoversFunction('pfb_match_reported_cidr')]
final class MatchReportedCidrHostileInputTest extends TestCase
{
	// A bare E_WARNING is not fatal to PHPUnit by default; escalating it to an exception
	// makes an unguarded "32 - $mask" / bad-shift path deterministically visible as a red
	// run instead of a silently-passed warning. TypeError/ArithmeticError are already
	// uncaught Throwables and need no such escalation.
	private function assertNeverWarnsOrThrows(callable $call): mixed
	{
		set_error_handler(static function (int $errno, string $errstr): bool {
			throw new \ErrorException($errstr, 0, $errno);
		}, E_WARNING);

		try {
			return $call();
		} finally {
			restore_error_handler();
		}
	}

	// ------------------------------------------------------------------------------
	// v4 -- malformed masks
	// ------------------------------------------------------------------------------

	public function test_v4_empty_mask_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		$this->assertNull($match, 'expected an empty v4 mask to be skipped as NULL, got ' . var_export($match, true));
	}

	public function test_v4_non_numeric_mask_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/xx'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		$this->assertNull(
			$match,
			'expected a non-numeric v4 mask to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	public function test_v4_oversize_mask_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/99'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		$this->assertNull(
			$match,
			'expected an oversized (>32) v4 mask to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	public function test_v4_negative_mask_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/-1'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		$this->assertNull(
			$match,
			'expected a negative-looking v4 mask to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// v4 -- valid rows keep their existing behaviour
	// ------------------------------------------------------------------------------

	public function test_v4_valid_24_mask_matches_host_inside(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/24'];

		$match = pfb_match_reported_cidr($result, '1.2.3.4', TRUE);

		$this->assertSame(
			['DenyFeed', '1.2.3.0/24'],
			$match,
			'expected 1.2.3.4 (inside the /24) to match, got ' . var_export($match, true)
		);
	}

	public function test_v4_valid_24_mask_rejects_host_outside(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/24'];

		$match = pfb_match_reported_cidr($result, '9.9.9.9', TRUE);

		$this->assertNull(
			$match,
			'expected 9.9.9.9 (outside the /24) NOT to match, got ' . var_export($match, true)
		);
	}

	public function test_v4_zero_mask_is_a_legal_mask_not_rejected_by_the_guard(): void
	{
		// '/0' is a legal mask (matches every address) -- the ctype_digit guard must
		// not treat a falsy-looking '0' as malformed.
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:1.2.3.0/0'];

		$match = pfb_match_reported_cidr($result, '203.0.113.5', TRUE);

		$this->assertSame(
			['DenyFeed', '1.2.3.0/0'],
			$match,
			'expected a /0 mask to match any host, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// v4 -- malformed address
	// ------------------------------------------------------------------------------

	public function test_v4_garbage_address_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:banana/24'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		$this->assertNull(
			$match,
			'expected a non-IP v4 address to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// v6 -- malformed lengths
	// ------------------------------------------------------------------------------

	public function test_v6_empty_length_yields_null_not_a_false_positive_match(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8::/'];

		$match = pfb_match_reported_cidr($result, '2001:db8::1', FALSE);

		$this->assertNull(
			$match,
			'expected an empty v6 length to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	public function test_v6_non_numeric_length_yields_null_not_a_false_positive_match(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8::/zz'];

		$match = pfb_match_reported_cidr($result, '2001:db8::1', FALSE);

		$this->assertNull(
			$match,
			'expected a non-numeric v6 length to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	public function test_v6_oversize_length_yields_null(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8::/200'];

		$match = pfb_match_reported_cidr($result, '2001:db8::1', FALSE);

		$this->assertNull(
			$match,
			'expected an oversized (>128) v6 length to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// v6 -- valid rows keep their existing behaviour
	// ------------------------------------------------------------------------------

	public function test_v6_valid_32_length_matches_host_inside(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8::/32'];

		$match = pfb_match_reported_cidr($result, '2001:db8::1', FALSE);

		$this->assertSame(
			['DenyFeed', '2001:db8::/32'],
			$match,
			'expected 2001:db8::1 (inside the /32) to match, got ' . var_export($match, true)
		);
	}

	public function test_v6_valid_32_length_rejects_host_outside(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8::/32'];

		$match = pfb_match_reported_cidr($result, '2001:dead::1', FALSE);

		$this->assertNull(
			$match,
			'expected 2001:dead::1 (outside the /32) NOT to match, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// v6 -- malformed prefix
	// ------------------------------------------------------------------------------

	public function test_v6_garbage_prefix_yields_null_without_throwing(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:banana/32'];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '2001:db8::1', FALSE)
		);

		$this->assertNull(
			$match,
			'expected a non-IP v6 prefix to be skipped as NULL, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// skip, don't abort
	// ------------------------------------------------------------------------------

	public function test_malformed_candidate_does_not_abort_scan_of_later_valid_candidate(): void
	{
		// Given: a malformed v4 candidate FIRST in $result, followed by a real matching one.
		$result = [
			'/var/db/pfblockerng/deny/BadFeed.txt:1.2.3.0/xx',
			'/var/db/pfblockerng/deny/GoodFeed.txt:1.2.3.0/24',
		];

		$match = $this->assertNeverWarnsOrThrows(
			fn () => pfb_match_reported_cidr($result, '1.2.3.4', TRUE)
		);

		// Then: the scan continues past the malformed row and still finds the real match --
		// proves the guard `continue`s the loop rather than aborting it.
		$this->assertSame(
			['GoodFeed', '1.2.3.0/24'],
			$match,
			'expected the malformed candidate to be skipped and GoodFeed\'s /24 to still match, got '
				. var_export($match, true)
		);
	}
}
