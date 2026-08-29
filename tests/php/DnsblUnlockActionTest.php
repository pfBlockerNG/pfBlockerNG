<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_unlock_action() — ADR-06 (#51) four-way dispatch of a per-alert DNSBL
 * Lock/Unlock action (the dnsbl_remove POST value) to its temporary-unlock STORE
 * mode + status message. Extracted from the pfblockerng_alerts.php handler so EVERY
 * branch is covered here (the smoke matrix only observes the resolver-visible
 * unlock/lock paths). unlock/relock ADD ('unlock' mode), lock/reunlock REMOVE ('lock'
 * mode); an UNKNOWN/empty action is a no-op (empty mode + empty message).
 */
#[CoversFunction('pfb_dnsbl_unlock_action')]
final class DnsblUnlockActionTest extends TestCase
{
	/** @return array<string, array{0: string, 1: string, 2: string}> action => [mode, msg-substring] */
	public static function provider(): array
	{
		return [
			// ADD branches.
			'unlock adds'   => ['unlock',   'unlock', 'temporarily Unlocked'],
			'relock adds'   => ['relock',   'unlock', 'temporarily Re-Locked'],
			// REMOVE branches.
			'lock removes'  => ['lock',     'lock',   'Locked into DNSBL'],
			'reunlock removes' => ['reunlock', 'lock', 'has been Unlocked'],
			// No-op branches — a crafted/empty action must NOT mutate the store.
			'unknown -> no-op' => ['bogus', '', ''],
			'empty -> no-op'   => ['',      '', ''],
		];
	}

	#[DataProvider('provider')]
	public function testMode(string $action, string $mode, string $msgPart): void
	{
		$out = pfb_dnsbl_unlock_action($action);
		$this->assertSame($mode, $out['mode'], "mode for action '{$action}'");
	}

	#[DataProvider('provider')]
	public function testMessage(string $action, string $mode, string $msgPart): void
	{
		$out = pfb_dnsbl_unlock_action($action);
		if ($msgPart === '') {
			$this->assertSame('', $out['msg'], "unknown action must have an empty message");
		} else {
			$this->assertStringContainsString($msgPart, $out['msg']);
			// The message is a sprintf template carrying exactly one %s for the domain.
			$this->assertSame('The Domain [ x.example.com ] ' . $this->tail($action), sprintf($out['msg'], 'x.example.com'));
		}
	}

	/** Expected post-domain text per action (verifies the %s lands in the right spot). */
	private function tail(string $action): string
	{
		return [
			'unlock'   => 'has been temporarily Unlocked from DNSBL!',
			'relock'   => 'has been temporarily Re-Locked into DNSBL!',
			'lock'     => 'has been Locked into DNSBL!',
			'reunlock' => 'has been Unlocked from DNSBL!',
		][$action];
	}

	public function testUnknownActionIsNoOpShape(): void
	{
		// Both keys present and empty so the handler's `mode !== ''` gate + sprintf('')
		// path are well-defined for any unexpected POST value.
		$out = pfb_dnsbl_unlock_action('definitely-not-an-action');
		$this->assertSame(['mode' => '', 'msg' => ''], $out);
		$this->assertSame('', sprintf($out['msg'], 'x.example.com'));
	}
}
