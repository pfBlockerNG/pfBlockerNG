<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/** The pre-script help note warns about DNSBLIP counts on DNSBL only (the pre-script itself runs in Core since #3977). */
#[CoversFunction('pfb_category_script_pre_settings')]
final class DnsblListScriptWiringTest extends TestCase
{
	public function testHelpNoteRemainsDnsblOnly(): void
	{
		$options = ['' => 'None', 'pre.sh' => 'pre.sh'];
		$dnsbl   = pfb_category_script_pre_settings('dnsbl', $options);
		$ip      = pfb_category_script_pre_settings('ip', $options);

		$this->assertSame(2, $dnsbl['size']);
		$this->assertSame(2, $ip['size']);
		$this->assertStringContainsString('DNSBLIP', $dnsbl['help']);
		$this->assertStringContainsString('silently shrink', $dnsbl['help']);
		$this->assertStringNotContainsString('DNSBLIP', $ip['help']);
		$this->assertStringNotContainsString('silently shrink', $ip['help']);
	}
}
