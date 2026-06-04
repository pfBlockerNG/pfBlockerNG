<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12: pfb_get_hooks() / pfb_hook_timeout() — the pure selection logic of the
 * pre/post update hook runner. pfb_run_hooks() itself execs as root + logs (deep
 * runtime, ADR-04 live smoke), but the entry-selection + timeout-resolution it
 * delegates to are pure and pinned here. Branch coverage: pre/post, enabled
 * on/off, when mismatch, blank command, malformed entries, list order, and the
 * timeout fallback (set vs unset vs invalid).
 */
#[CoversFunction('pfb_get_hooks')]
#[CoversFunction('pfb_hook_timeout')]
final class PfbGetHooksTest extends TestCase
{
	/** A representative config with a mix of pre/post, enabled/disabled hooks. */
	private static function sampleConfig(): array
	{
		return [
			'hooks' => [
				['command' => 'echo pre1',  'when' => 'pre',  'enabled' => 'on'],
				['command' => 'echo post1', 'when' => 'post', 'enabled' => 'on'],
				['command' => 'echo pre2',  'when' => 'pre',  'enabled' => ''],	// disabled
				['command' => 'echo pre3',  'when' => 'pre',  'enabled' => 'on'],
				['command' => 'echo post2', 'when' => 'post', 'enabled' => 'on'],
			],
		];
	}

	public function testSelectsEnabledPreHooksInListOrder(): void
	{
		$hooks = pfb_get_hooks(self::sampleConfig(), 'pre');
		// pre2 is disabled and must be skipped; pre1 then pre3 in list order.
		$this->assertCount(2, $hooks);
		$this->assertSame('echo pre1', $hooks[0]['command']);
		$this->assertSame('echo pre3', $hooks[1]['command']);
	}

	public function testSelectsEnabledPostHooksInListOrder(): void
	{
		$hooks = pfb_get_hooks(self::sampleConfig(), 'post');
		$this->assertCount(2, $hooks);
		$this->assertSame('echo post1', $hooks[0]['command']);
		$this->assertSame('echo post2', $hooks[1]['command']);
	}

	public function testDisabledHookIsSkipped(): void
	{
		// Before: enabled => the hook is returned.
		$cfg = ['hooks' => [['command' => 'c', 'when' => 'pre', 'enabled' => 'on']]];
		$this->assertCount(1, pfb_get_hooks($cfg, 'pre'));

		// After: disable it (any non-'on' value) => skipped.
		$cfg['hooks'][0]['enabled'] = '';
		$this->assertSame([], pfb_get_hooks($cfg, 'pre'));
	}

	public function testWhenMismatchIsSkipped(): void
	{
		$cfg = ['hooks' => [['command' => 'c', 'when' => 'post', 'enabled' => 'on']]];
		$this->assertSame([], pfb_get_hooks($cfg, 'pre'));
		$this->assertCount(1, pfb_get_hooks($cfg, 'post'));
	}

	public function testBlankOrMissingCommandIsSkipped(): void
	{
		$cfg = ['hooks' => [
			['command' => '   ', 'when' => 'pre', 'enabled' => 'on'],	// whitespace only
			['when' => 'pre', 'enabled' => 'on'],				// no command key
		]];
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
	}

	public function testNonArrayHookEntryIsSkipped(): void
	{
		$cfg = ['hooks' => [
			'garbage',	// non-array entry must not fatal
			['command' => 'good', 'when' => 'pre', 'enabled' => 'on'],
		]];
		$hooks = pfb_get_hooks($cfg, 'pre');
		$this->assertCount(1, $hooks);
		$this->assertSame('good', $hooks[0]['command']);
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
