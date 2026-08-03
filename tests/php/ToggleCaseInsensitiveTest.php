<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — PfbToggle accepts its two tokens in any case.
 *
	 * Canonical writes are 'on'/empty; legacy 'off' remains readable in any case. This is
	 * about the READ path being forgiving of input the
 * package did not write itself: a hand-edited config.xml, a restored backup, an HA sync,
 * or another tool touching installedpackages/*. Before this, 'On' or 'OFF' fell through
 * tryFrom() to the parse fallback and silently read as Off — a disabled feature for an
 * operator who spelled it the obvious way, with nothing logged.
 *
 * Off is the fallback for genuinely unknown junk, which is why the case-only variants
 * have to be recognised explicitly rather than left to it: 'ON' reading as Off is the
 * failure this prevents, and it is indistinguishable from correct behaviour without
 * asserting the On direction specifically.
 */
final class ToggleCaseInsensitiveTest extends TestCase
{
	private const KEEP = 'installedpackages/pfblockerng/config/0/pfb_keep';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * @return list<array{0: string, 1: PfbToggle}>
	 */
	public static function caseVariants(): array
	{
		return [
			['on',  PfbToggle::On],
			['On',  PfbToggle::On],
			['ON',  PfbToggle::On],
			['oN',  PfbToggle::On],
			['off', PfbToggle::Off],
			['Off', PfbToggle::Off],
			['OFF', PfbToggle::Off],
			['oFf', PfbToggle::Off],
		];
	}

	public function testEveryCaseVariantParsesToTheRightCase(): void
	{
		foreach (self::caseVariants() as [$raw, $expected]) {
			$this->assertSame(
				$expected,
				PfbToggle::fromStored($raw),
				"stored '{$raw}' must parse to PfbToggle::{$expected->name}"
			);
		}
	}

	/**
	 * A mixed-case token reaching the gateway reads correctly and is rewritten canonical.
	 *
	 * The write half matters as much as the read: a recognised variant must normalise to
	 * lowercase on the next save rather than persisting forever in whatever case it
	 * arrived in.
	 *
	 * Uses the ON direction deliberately. 'OFF' would reach Off through the junk fallback
	 * even before this change, so an Off-direction version of this test passes without
	 * proving anything — only 'ON' distinguishes "recognised the token" from "gave up and
	 * defaulted".
	 */
	public function testMixedCaseIsReadCorrectlyAndRewrittenCanonical(): void
	{
		config_set_path(self::KEEP, 'ON');
		$this->assertSame('ON', config_get_path(self::KEEP), "before: pfb_keep seed is 'ON'");

		$enum = PfbConfig::read('gen/pfb_keep');
		$this->assertSame(PfbToggle::On, $enum, "stored 'ON' must read as On, not fall back to Off");

		PfbConfig::write('gen/pfb_keep', $enum);
		$this->assertSame('on', config_get_path(self::KEEP), "write must re-emit the canonical lowercase 'on'");
	}

	/**
	 * Genuine junk still falls back to Off — the fallback is not widened by this change.
	 *
	 * Without this, "be forgiving about case" could be satisfied by a parser that
	 * accepted anything, which would turn a typo into a silently enabled feature.
	 */
	public function testUnknownTokensStillFallBackToOff(): void
	{
		foreach (['', 'yes', 'true', '1', 'onn', 'o n', 'enabled', 'off ', ' on'] as $junk) {
			$this->assertSame(
				PfbToggle::Off,
				PfbToggle::fromStored($junk),
				"junk token '{$junk}' must fall back to Off"
			);
		}
	}
}
