<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_unbound_py_ccache_flush_cmds() — issue #153.
 *
 * Builds the unbound-control C-cache flush command list for the allow->block delta
 * (a #51 alert Lock / custom-list edit). Extracted from pfb_unbound_py_ccache_flush()
 * so the validation + de-dup branches are covered off-appliance (the exec() side of the
 * wrapper is the live-VM smoke's job, ADR-04).
 *
 * Scenario: a newly-blocked name is flushed from the resolver cache via exec().
 *   Background: each name is interpolated into a `<chroot> flush <name> 2>&1` command.
 *   Rule (the #153 fix): a name reaches the command ONLY if pfb_filter() accepts it as a
 *     domain (PFB_FILTER_DOMAIN). escapeshellarg() is the second layer; validation is the
 *     first — a non-domain / shell-metachar entry is DROPPED, never built into a command.
 */
#[CoversFunction('pfb_unbound_py_ccache_flush_cmds')]
final class CcacheFlushCmdsTest extends TestCase
{
	/** The chroot_cmd is opaque to the builder — a fixed sentinel keeps expectations exact. */
	private const CC = 'CHROOT';

	private function cmds(array $names): array
	{
		return pfb_unbound_py_ccache_flush_cmds($names, self::CC);
	}

	private function flush(string $variant): string
	{
		// Mirror the production framing so the test pins the exact emitted command,
		// including the escapeshellarg() second layer.
		return self::CC . ' flush ' . escapeshellarg($variant) . ' 2>&1';
	}

	public function testValidDomainBuildsTheNameAndWwwPair(): void
	{
		// When a valid domain is passed
		$out = $this->cmds(['example.com']);

		// Then exactly its name + 'www.' sibling are flushed, each escapeshellarg'd.
		$this->assertSame(
			[$this->flush('example.com'), $this->flush('www.example.com')],
			$out
		);
	}

	public function testValidDomainKeepsCase(): void
	{
		// pfb_filter(PFB_FILTER_DOMAIN) preserves case (htmlspecialchars is a no-op on
		// the valid domain charset) — the flush target must match what was resolved.
		$out = $this->cmds(['Example.COM']);
		$this->assertSame(
			[$this->flush('Example.COM'), $this->flush('www.Example.COM')],
			$out
		);
	}

	/** @return array<string, array{0: string}> label => malicious/invalid name */
	public static function rejectedProvider(): array
	{
		return [
			'shell semicolon'   => ['evil.com; reboot'],
			'command sub'       => ['$(reboot).com'],
			'backtick'          => ['`id`.com'],
			'pipe'              => ['a.com | nc x 1'],
			'space'             => ['ex ample.com'],
			'no dot (hostname)' => ['localhost'],
			'double dot'        => ['bad..com'],
			'plus char'         => ['ex+ample.com'],
			'newline'           => ["a.com\nrm -rf /"],
		];
	}

	/**
	 * The core #153 assertion: a name pfb_filter() rejects yields NO command at all.
	 *
	 * Before the fix the loop only trim()'d + escapeshellarg()'d, so EVERY one of these
	 * still produced a (shell-safe but pointless) flush command. The validation is what
	 * drops them — proven by the contrast with the valid-domain cases above.
	 */
	#[DataProvider('rejectedProvider')]
	public function testInvalidNameProducesNoCommand(string $name): void
	{
		$this->assertSame([], $this->cmds([$name]));
	}

	public function testInvalidIsDroppedButValidInTheSameListSurvives(): void
	{
		// Given a mix of one valid domain and several rejected names
		$out = $this->cmds(['good.com', 'bad.com; rm -rf /', 'localhost', '']);

		// Then ONLY the valid domain's pair is built — the bad entries are dropped, not
		// merely neutralised, and they do not suppress the good one.
		$this->assertSame(
			[$this->flush('good.com'), $this->flush('www.good.com')],
			$out
		);
	}

	public function testWwwSiblingIsDeDuplicatedAcrossNames(): void
	{
		// Given a name and its explicit 'www.' form, the shared 'www.example.com' variant
		// must be emitted once (coalesced single control session).
		$out = $this->cmds(['example.com', 'www.example.com']);

		$this->assertSame(
			[
				$this->flush('example.com'),
				$this->flush('www.example.com'),
				$this->flush('www.www.example.com'),
			],
			$out
		);
	}

	public function testExactDuplicateNameCollapses(): void
	{
		// The same name twice must not double the commands.
		$this->assertSame(
			[$this->flush('example.com'), $this->flush('www.example.com')],
			$this->cmds(['example.com', 'example.com'])
		);
	}

	/** @return array<string, array{0: mixed}> label => empty/degenerate input */
	public static function emptyProvider(): array
	{
		return [
			'empty array'    => [[]],
			'all rejected'   => [['localhost', 'no-dot']],
			'whitespace only' => [['   ']],
		];
	}

	#[DataProvider('emptyProvider')]
	public function testNoBuildableNamesYieldsEmptyList(array $names): void
	{
		$this->assertSame([], $this->cmds($names));
	}

	public function testNonArrayIsSafe(): void
	{
		// The wrapper passes through whatever it received; the builder must not warn.
		$this->assertSame([], pfb_unbound_py_ccache_flush_cmds('not-an-array', self::CC));
	}
}
