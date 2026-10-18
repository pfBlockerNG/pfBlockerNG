<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the Reports tab's DNS Reply Log Options (types and records to suppress) and Disabled DNS Reply Stats were
 * shown only with DNSBL on, so a user whose DNS Reply log is filled by pfB-DNS alone (DNSBL off, reply logging on) could
 * not filter the log or hide its stats without turning DNSBL on.
 *
 * pfb_dns_reply_log_active() is the one gate for both controls: DNSBL on keeps showing them as before, whatever the stored
 * preference; with DNSBL off they show only while pfB-DNS is on AND the stored reply-logging preference is on, i.e. while
 * the proxy really logs replies. A default-on preference without pfB-DNS logs nothing, so it must not show them.
 */
#[CoversFunction('pfb_dns_reply_log_active')]
final class DnsReplyReportControlsTest extends TestCase
{
	private mixed $savedPfb;
	private bool $hadPfb;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	/** @return array<string,array{bool,bool,bool,bool}> DNSBL on, pfB-DNS on, reply logging on => controls shown */
	public static function states(): array
	{
		return [
			'DNSBL on, pfB-DNS off, logging off: as before'  => [TRUE, FALSE, FALSE, TRUE],
			'DNSBL on, pfB-DNS off, logging on: as before'   => [TRUE, FALSE, TRUE, TRUE],
			'DNSBL on, pfB-DNS on, logging on: as before'    => [TRUE, TRUE, TRUE, TRUE],
			'DNSBL off, pfB-DNS on, logging on: new'         => [FALSE, TRUE, TRUE, TRUE],
			'DNSBL off, pfB-DNS on, logging off: stored Off' => [FALSE, TRUE, FALSE, FALSE],
			'DNSBL off, pfB-DNS off, logging on: logs nothing' => [FALSE, FALSE, TRUE, FALSE],
			'DNSBL off, pfB-DNS off, logging off'            => [FALSE, FALSE, FALSE, FALSE],
		];
	}

	#[DataProvider('states')]
	public function testTheReplyControlsFollowDnsblOrPfbDnsLoggingReplies(bool $dnsbl, bool $pfbDns, bool $logging, bool $shown): void
	{
		$GLOBALS['pfb'] = [
			'dnsbl'           => $dnsbl ? PfbToggle::On : PfbToggle::Off,
			'pfb_dns'         => $pfbDns ? PfbToggle::On : PfbToggle::Off,
			'dnsbl_py_reply'  => $logging ? PfbToggle::On : PfbToggle::Off,
		];

		$this->assertSame($shown, pfb_dns_reply_log_active());
	}
}
