<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_reserved_header_skip_active() (issue #1270).
 *
 * sync_package_pfblockerng() reads list-row config independently in more than
 * one loop (the download loop and the alias/firewall-rule loop, besides the
 * header-normalize loop). Each calls this SAME predicate at its own
 * config-read site, so a regression in the guard (a dropped `!`, the wrong
 * marker key, `&&` flipped to `||`) fails every call site's test, not an
 * inline copy no production code executes. Pure, brand-new function (no
 * pre-existing behaviour to pin -- CLAUDE.md Test coverage #1 exception 2).
 */
#[CoversFunction('pfb_reserved_header_skip_active')]
final class ReservedHeaderSkipActiveTest extends TestCase
{
	/** A real user row whose Header collides with a reserved name must skip. */
	public function testRealUserRowWithReservedHeaderSkips(): void
	{
		$this->assertTrue(pfb_reserved_header_skip_active(FALSE, 'DNSBLIP'));
	}

	/** The package's OWN synthesized DNSBLIP row is exempt from its own guard. */
	public function testSynthesizedDnsblipRowIsExempt(): void
	{
		$this->assertFalse(pfb_reserved_header_skip_active(TRUE, 'DNSBLIP'));
	}

	/** An ordinary, non-reserved Header never skips, real row or synthesized. */
	public function testOrdinaryHeaderNeverSkips(): void
	{
		$this->assertFalse(pfb_reserved_header_skip_active(FALSE, 'MyBlocklist'));
		$this->assertFalse(pfb_reserved_header_skip_active(TRUE, 'MyBlocklist'));
	}

	/** A reserved continent alias on a real user row also skips (not DNSBLIP-only). */
	public function testRealUserRowWithReservedContinentAliasSkips(): void
	{
		$this->assertTrue(pfb_reserved_header_skip_active(FALSE, 'pfB_Africa'));
	}

	/** An empty Header (draft/incomplete row) never skips. */
	public function testEmptyHeaderNeverSkips(): void
	{
		$this->assertFalse(pfb_reserved_header_skip_active(FALSE, ''));
	}
}
