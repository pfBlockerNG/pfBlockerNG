<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_hash_line_classify() -- issue #995. Pure classifier for a DNSBL feed's
 * '#'-prefixed line: hpHosts end marker (stop), Spamhaus format banner (rev_format),
 * and the exact h3x CSV header (csv_type/csv_parser). Flags are report-only -- the
 * caller only WRITES a flag when the classifier reports it, so a plain comment line
 * must leave the caller's existing rev_format/csv_type/csv_parser state untouched.
 */
#[CoversFunction('pfb_dnsbl_hash_line_classify')]
final class PfbDnsblHashLineClassifyTest extends TestCase
{
	public function testHpHostsMarkerStopsRegardlessOfOtherContent(): void
	{
		// hpHosts end marker is checked FIRST and short-circuits the rest.
		$c = pfb_dnsbl_hash_line_classify('# Append critical updates below this line');
		$this->assertTrue($c['stop']);
		$this->assertFalse($c['rev_format']);
		$this->assertNull($c['csv_type']);
		$this->assertFalse($c['csv_parser']);
	}

	public function testSpamhausLineSetsRevFormat(): void
	{
		$c = pfb_dnsbl_hash_line_classify('# Copyright (c) The Spamhaus Project Ltd');
		$this->assertFalse($c['stop']);
		$this->assertTrue($c['rev_format']);
		$this->assertNull($c['csv_type']);
		$this->assertFalse($c['csv_parser']);
	}

	public function testExactH3xHeaderSetsCsvTypeAndParser(): void
	{
		$c = pfb_dnsbl_hash_line_classify(
			'#family,type,url,status,first_seen,first_active,last_active,last_update'
		);
		$this->assertFalse($c['stop']);
		$this->assertFalse($c['rev_format']);
		$this->assertSame('h3x', $c['csv_type']);
		$this->assertTrue($c['csv_parser']);
	}

	public function testPlainCommentLineIsSkipOnlyNoFlagsSet(): void
	{
		// A plain '#' comment: caller must not overwrite existing rev_format/csv_type/
		// csv_parser state -- this predicate reports nothing so the caller writes nothing.
		$c = pfb_dnsbl_hash_line_classify('# just a regular comment line');
		$this->assertFalse($c['stop']);
		$this->assertFalse($c['rev_format']);
		$this->assertNull($c['csv_type']);
		$this->assertFalse($c['csv_parser']);
	}

	public function testNearMissH3xHeaderMissingColumnDoesNotSetCsvType(): void
	{
		// Defeats vacuity on the exact-equality guard: one column dropped.
		$c = pfb_dnsbl_hash_line_classify(
			'#family,type,url,status,first_seen,first_active,last_active'
		);
		$this->assertNull($c['csv_type']);
		$this->assertFalse($c['csv_parser']);
	}

	public function testNearMissH3xHeaderExtraColumnDoesNotSetCsvType(): void
	{
		// Defeats vacuity on the exact-equality guard: one column added.
		$c = pfb_dnsbl_hash_line_classify(
			'#family,type,url,status,first_seen,first_active,last_active,last_update,extra'
		);
		$this->assertNull($c['csv_type']);
		$this->assertFalse($c['csv_parser']);
	}
}
