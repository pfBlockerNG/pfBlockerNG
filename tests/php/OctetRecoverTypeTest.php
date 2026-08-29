<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for pfb_octet_recover_type() — the seamed recovery helper (ADR-45 Phase 3).
 *
 * No shell is used: $validator is a fake closure that returns TRUE/FALSE deterministically,
 * so these tests run anywhere without decompressor tools.
 *
 * These tests FAIL before Phase 3 (function absent — "Call to undefined function
 * pfb_octet_recover_type()") and PASS after. Red baseline recorded in RESULTS/03_Results.txt.
 */
#[CoversFunction('pfb_octet_recover_type')]
final class OctetRecoverTypeTest extends TestCase
{
	/**
	 * Scenario: validator matches the first candidate type
	 * Given  a validator that returns TRUE only for 'application/zip'
	 *        and a type list of ['application/zip', 'application/gzip']
	 * When   pfb_octet_recover_type() is called
	 * Then   it returns 'application/zip' (first match in list wins)
	 */
	public function test_recovers_first_matching_type(): void
	{
		$validator = fn(string $file, string $type): bool => ($type === 'application/zip');

		$result = pfb_octet_recover_type(
			'/tmp/test.bin',
			array('application/zip', 'application/gzip'),
			$validator
		);

		$this->assertSame('application/zip', $result,
			'Expected application/zip as the first matching type; got: ' . var_export($result, TRUE)
		);
	}

	/**
	 * Scenario: probe ORDER — first type wins and loop stops on first match
	 * Given  a validator that returns TRUE for every type
	 *        and a type list of ['application/zip', 'application/gzip']
	 * When   pfb_octet_recover_type() is called
	 * Then   it returns 'application/zip' (zip is first in the list)
	 *        and stops probing (gzip is never called — early-exit on first match)
	 */
	public function test_returns_first_type_in_list_and_stops_probing(): void
	{
		$probed    = [];
		$validator = function (string $file, string $type) use (&$probed): bool {
			$probed[] = $type;
			return TRUE;    // all types match
		};

		$result = pfb_octet_recover_type(
			'/tmp/test.bin',
			array('application/zip', 'application/gzip'),
			$validator
		);

		$this->assertSame('application/zip', $result,
			'Expected application/zip (first in list); got: ' . var_export($result, TRUE)
		);
		$this->assertSame(array('application/zip'), $probed,
			'Expected probing to stop after first match; probed: ' . implode(', ', $probed)
		);
	}

	/**
	 * Scenario: validator returns FALSE for ALL types (junk/HTML blob — caller rejects)
	 * Given  a validator that always returns FALSE
	 *        and the full production type list
	 * When   pfb_octet_recover_type() is called
	 * Then   it returns NULL — no supported archive matched, caller must reject
	 *
	 * This is the "genuinely-unknown octet-stream is still rejected" branch (ADR §7).
	 */
	public function test_returns_null_when_all_types_rejected(): void
	{
		$validator = fn(string $file, string $type): bool => FALSE;

		$result = pfb_octet_recover_type(
			'/tmp/test.bin',
			array('application/zip', 'application/gzip', 'application/x-bzip2'),
			$validator
		);

		$this->assertNull($result,
			'Expected NULL when all probes fail (junk blob); got: ' . var_export($result, TRUE)
		);
	}

	/**
	 * Scenario: empty supported-types list
	 * Given  an empty $supported_types array and a validator that would match anything
	 * When   pfb_octet_recover_type() is called
	 * Then   it returns NULL immediately (nothing to probe)
	 */
	public function test_returns_null_on_empty_type_list(): void
	{
		$validator = fn(string $file, string $type): bool => TRUE;    // would match if called

		$result = pfb_octet_recover_type('/tmp/test.bin', array(), $validator);

		$this->assertNull($result,
			'Expected NULL for empty type list; got: ' . var_export($result, TRUE)
		);
	}
}
