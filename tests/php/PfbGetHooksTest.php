<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12: pfb_get_hooks() / pfb_hook_timeout() — the pure selection logic of the
 * pre/post update hook runner. pfb_run_hooks() itself execs as root + logs (deep
 * runtime, ADR-04 live smoke), but the entry-selection + timeout-resolution it
 * delegates to are pure and pinned here. Branch coverage: pre/post, enabled
 * on/off, when mismatch, blank script, malformed entries, list order, and the
 * timeout fallback (set vs unset vs invalid).
 *
 * A hook entry references a SCRIPT FILE (basename, the security model — see
 * pfb_get_hooks()/pfb_run_hooks()), not a free-text command; the getter is pure and
 * does NOT touch the filesystem (the file's existence/allow-list is the runner's
 * run-time gate, pinned in PfbHookScriptsTest), so any non-empty string selects here.
 */
#[CoversFunction('pfb_get_hooks')]
#[CoversFunction('pfb_hook_timeout')]
final class PfbGetHooksTest extends TestCase
{
	/**
	 * A representative config with a mix of pre/post, enabled/disabled hooks, in
	 * the CANONICAL storage shape: entries nested under the 'row' listtag
	 * (config/0/hooks/row). See pfb_get_hooks() for why the rows live under 'row'.
	 */
	private static function sampleConfig(): array
	{
		return [
			'hooks' => ['row' => [
				['script' => 'hook_pre_1.sh',  'when' => 'pre',  'enabled' => 'on'],
				['script' => 'hook_post_1.sh', 'when' => 'post', 'enabled' => 'on'],
				['script' => 'hook_pre_2.sh',  'when' => 'pre',  'enabled' => ''],	// disabled
				['script' => 'hook_pre_3.sh',  'when' => 'pre',  'enabled' => 'on'],
				['script' => 'hook_post_2.sh', 'when' => 'post', 'enabled' => 'on'],
			]],
		];
	}

	public function testSelectsEnabledPreHooksInListOrder(): void
	{
		$hooks = pfb_get_hooks(self::sampleConfig(), 'pre');
		// pre2 is disabled and must be skipped; pre1 then pre3 in list order.
		$this->assertCount(2, $hooks);
		$this->assertSame('hook_pre_1.sh', $hooks[0]['script']);
		$this->assertSame('hook_pre_3.sh', $hooks[1]['script']);
	}

	public function testSelectsEnabledPostHooksInListOrder(): void
	{
		$hooks = pfb_get_hooks(self::sampleConfig(), 'post');
		$this->assertCount(2, $hooks);
		$this->assertSame('hook_post_1.sh', $hooks[0]['script']);
		$this->assertSame('hook_post_2.sh', $hooks[1]['script']);
	}

	public function testDisabledHookIsSkipped(): void
	{
		// Before: enabled => the hook is returned.
		$cfg = ['hooks' => ['row' => [['script' => 'hook_pre_x.sh', 'when' => 'pre', 'enabled' => 'on']]]];
		$this->assertCount(1, pfb_get_hooks($cfg, 'pre'));

		// After: disable it (any non-'on' value) => skipped.
		$cfg['hooks']['row'][0]['enabled'] = '';
		$this->assertSame([], pfb_get_hooks($cfg, 'pre'));
	}

	public function testWhenMismatchIsSkipped(): void
	{
		$cfg = ['hooks' => ['row' => [['script' => 'hook_post_x.sh', 'when' => 'post', 'enabled' => 'on']]]];
		$this->assertSame([], pfb_get_hooks($cfg, 'pre'));
		$this->assertCount(1, pfb_get_hooks($cfg, 'post'));
	}

	public function testBlankOrMissingScriptIsSkipped(): void
	{
		$cfg = ['hooks' => ['row' => [
			['script' => '   ', 'when' => 'pre', 'enabled' => 'on'],	// whitespace only
			['when' => 'pre', 'enabled' => 'on'],			// no script key
		]]];
		$this->assertSame([], pfb_get_hooks($cfg, 'pre'));
	}

	public function testInvalidWhenArgReturnsEmpty(): void
	{
		$this->assertSame([], pfb_get_hooks(self::sampleConfig(), 'mid'));
		$this->assertSame([], pfb_get_hooks(self::sampleConfig(), ''));
	}

	public function testMissingOrMalformedHooksConfigReturnsEmpty(): void
	{
		$this->assertSame([], pfb_get_hooks([], 'pre'));			// no 'hooks' key
		$this->assertSame([], pfb_get_hooks(['hooks' => 'nope'], 'pre'));	// not an array
		$this->assertSame([], pfb_get_hooks('not-an-array', 'pre'));		// config not an array
		$this->assertSame([], pfb_get_hooks(['hooks' => ['row' => 'nope']], 'pre'));	// row not an array
	}

	public function testRowListtagSingleAndMultiRowRoundTrip(): void
	{
		// 'hooks' is NOT a pfSense listtag (xmlparse.inc::listtags(): it lists
		// 'row'/'hosts'/'rule'/'item' but no 'hooks'), so a list set straight under
		// <hooks> serializes to invalid <0> child tags and never reloads. Entries
		// are stored under the 'row' listtag instead, which round-trips for any
		// count. A SINGLE row (a lone <row>) stays a 1-element list because 'row'
		// IS a listtag; this is the case a real user with exactly one hook hits.
		$single = ['hooks' => ['row' => [['script' => 'hook_post_solo.sh', 'when' => 'post', 'enabled' => 'on']]]];
		$got = pfb_get_hooks($single, 'post');
		$this->assertCount(1, $got);
		$this->assertSame('hook_post_solo.sh', $got[0]['script']);
		// The per-hook gate still applies under 'row': a when mismatch selects nothing.
		$this->assertSame([], pfb_get_hooks($single, 'pre'));

		// Multiple rows preserve list order and the enabled/when gates.
		$multi = ['hooks' => ['row' => [
			['script' => 'hook_post_a.sh', 'when' => 'post', 'enabled' => 'on'],
			['script' => 'hook_post_b.sh', 'when' => 'post', 'enabled' => ''],	// disabled
			['script' => 'hook_post_c.sh', 'when' => 'post', 'enabled' => 'on'],
		]]];
		$got = pfb_get_hooks($multi, 'post');
		$this->assertCount(2, $got);
		$this->assertSame('hook_post_a.sh', $got[0]['script']);
		$this->assertSame('hook_post_c.sh', $got[1]['script']);
	}

	public function testBareListAndFlatAssocFallbackShapesStillSelect(): void
	{
		// Tolerance for legacy/edge shapes the reader still accepts:
		//  (a) a bare numeric list directly under 'hooks' (the pre-fix shape);
		//  (b) a single hook as a flat associative array (a lone-element collapse,
		//      what a non-listtag <hooks> would yield if a hook were ever stored
		//      directly). Both must select identically to the canonical row shape.
		$bareList = ['hooks' => [['script' => 'hook_post_bl.sh', 'when' => 'post', 'enabled' => 'on']]];
		$got = pfb_get_hooks($bareList, 'post');
		$this->assertCount(1, $got);
		$this->assertSame('hook_post_bl.sh', $got[0]['script']);

		$flatAssoc = ['hooks' => ['script' => 'hook_post_fa.sh', 'when' => 'post', 'enabled' => 'on']];
		$got = pfb_get_hooks($flatAssoc, 'post');
		$this->assertCount(1, $got);
		$this->assertSame('hook_post_fa.sh', $got[0]['script']);
		// Gates apply to the flat-assoc shape too.
		$this->assertSame([], pfb_get_hooks($flatAssoc, 'pre'));
		$disabled = ['hooks' => ['script' => 'hook_post_fa.sh', 'when' => 'post', 'enabled' => '']];
		$this->assertSame([], pfb_get_hooks($disabled, 'post'));
	}

	public function testNonArrayHookEntryIsSkipped(): void
	{
		$cfg = ['hooks' => ['row' => [
			'garbage',	// non-array entry must not fatal
			['script' => 'hook_pre_good.sh', 'when' => 'pre', 'enabled' => 'on'],
		]]];
		$hooks = pfb_get_hooks($cfg, 'pre');
		$this->assertCount(1, $hooks);
		$this->assertSame('hook_pre_good.sh', $hooks[0]['script']);
	}

	public function testTimeoutHonoursValidOverride(): void
	{
		$this->assertSame(30, pfb_hook_timeout(['timeout' => '30']));
		$this->assertSame(5, pfb_hook_timeout(['timeout' => 5]));
	}

	public function testTimeoutFallsBackToDefaultWhenUnsetOrInvalid(): void
	{
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout([]));		// unset
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => 0]));	// zero
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => '-9']));	// negative
		$this->assertSame(PFB_HOOK_TIMEOUT_DEFAULT, pfb_hook_timeout(['timeout' => 'abc']));	// non-numeric
	}
}
