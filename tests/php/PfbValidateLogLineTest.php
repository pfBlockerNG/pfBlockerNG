<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for pfb_validate_log_line() -- ADR-48 Phase 1.
 *
 * pfb_validate_log_line() is the pure formatter behind the canonical, greppable
 * download-validation reject line:
 *
 *   \npfb_validate: REJECT feed=<feed> stage=<stage> reason=<reason> detected=<detail>
 *
 * Every one of the four values is escaped independently: control bytes in
 * [\x00-\x1F\x7F] are first neutralised to a single space (these values may carry
 * attacker-influenced file(1) output, and a raw "\n"/"\r" would forge or split the
 * greppable line), THEN htmlspecialchars() is applied. Pure function: string in,
 * string out, no I/O, no globals.
 */
#[CoversFunction('pfb_validate_log_line')]
final class PfbValidateLogLineTest extends TestCase
{
	// --- Canonical shape, one exact-string oracle per stage token in the fixed
	// vocabulary (mime | structural | inner | member | plaintext | entries). None of
	// these values carry hostile bytes -- they pin the SHAPE; escaping is separately
	// pinned below.

	public function testCanonicalLineForStageMime(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed1 stage=mime reason=invalid-mime detected=application/x-msi",
			pfb_validate_log_line('pfB_Feed1', 'mime', 'invalid-mime', 'application/x-msi')
		);
	}

	public function testCanonicalLineForStageStructural(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed2 stage=structural reason=corrupt-archive detected=gzip: unexpected end of file",
			pfb_validate_log_line('pfB_Feed2', 'structural', 'corrupt-archive', 'gzip: unexpected end of file')
		);
	}

	public function testCanonicalLineForStageInner(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed3 stage=inner reason=invalid-mime detected=application/x-executable",
			pfb_validate_log_line('pfB_Feed3', 'inner', 'invalid-mime', 'application/x-executable')
		);
	}

	public function testCanonicalLineForStageMember(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed4 stage=member reason=path-traversal detected=../../etc/passwd",
			pfb_validate_log_line('pfB_Feed4', 'member', 'path-traversal', '../../etc/passwd')
		);
	}

	public function testCanonicalLineForStagePlaintext(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed5 stage=plaintext reason=non-ascii-content detected=0x00 byte at offset 42",
			pfb_validate_log_line('pfB_Feed5', 'plaintext', 'non-ascii-content', '0x00 byte at offset 42')
		);
	}

	public function testCanonicalLineForStageEntries(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=pfB_Feed6 stage=entries reason=wire_cap detected=17",
			pfb_validate_log_line('pfB_Feed6', 'entries', 'wire_cap', '17')
		);
	}

	// --- Empty detail: `detected=` still present (exact-string), both via an
	// explicit '' and via the omitted default parameter.

	public function testEmptyDetailStillPrintsDetectedEquals(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=F stage=mime reason=r detected=",
			pfb_validate_log_line('F', 'mime', 'r', '')
		);
	}

	public function testOmittedDetailDefaultsToEmptyDetectedEquals(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=F stage=mime reason=r detected=",
			pfb_validate_log_line('F', 'mime', 'r')
		);
	}

	// --- Hostile detail: raw file(1) output is attacker-influenced. A value
	// carrying a NUL byte, "\n", and HTML metacharacters -- including an embedded
	// fake "pfb_validate: REJECT" line, an attempt to forge a second greppable
	// entry -- must collapse to a SINGLE line (no "\n" past the leading one), with
	// every control byte turned into a space and <, >, & escaped.

	public function testHostileDetailNeutralisedToSingleEscapedLine(): void
	{
		$hostileDetail = "app\x00lication/zip\nfake pfb_validate: REJECT x <b>&";

		$result = pfb_validate_log_line('FeedZ', 'mime', 'hostile-detail', $hostileDetail);

		$this->assertSame(
			"\npfb_validate: REJECT feed=FeedZ stage=mime reason=hostile-detail detected="
			. 'app lication/zip fake pfb_validate: REJECT x &lt;b&gt;&amp;',
			$result
		);
		// Defensive: only the pinned leading "\n" may appear -- a hostile detail can
		// never split the canonical line into two greppable entries.
		$this->assertSame(
			1,
			substr_count($result, "\n"),
			"expected exactly one \\n (the leading one) in <{$result}>"
		);
	}

	// --- Hostile feed/reason/stage: same escaping code path as detail: one case
	// each is enough to prove it applies uniformly to all four values.

	public function testHostileFeedIsNeutralisedAndEscaped(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=Feed &lt;Name&gt;&amp; stage=mime reason=r detected=d",
			pfb_validate_log_line("Feed\x01<Name>&", 'mime', 'r', 'd')
		);
	}

	public function testHostileReasonIsNeutralisedAndEscaped(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=f stage=mime reason=bad reason&amp;x detected=d",
			pfb_validate_log_line('f', 'mime', "bad\x1freason&x", 'd')
		);
	}

	public function testHostileStageIsNeutralisedAndEscaped(): void
	{
		$this->assertSame(
			"\npfb_validate: REJECT feed=f stage=mi me&lt;x&gt; reason=r detected=d",
			pfb_validate_log_line('f', "mi\x7fme<x>", 'r', 'd')
		);
	}
}
