<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** pfb_editor_toggle_help() names the fields the toggle actually covers. */
final class EditorToggleHelpTest extends TestCase
{
	public function testHelpNamesPreviouslyOmittedFieldsAndStatesTheRule(): void
	{
		$help = pfb_editor_toggle_help();
		foreach ([
			'every list and script textarea',
			'DNSBL Whitelist',
			'no-AAAA',
			'Group Policy Bypass IPs',
			'TLD Exclusion',
			'TLD Blacklist',
			'Block Private-Address Exceptions',
		] as $needle) {
			$this->assertStringContainsString($needle, $help);
		}
		$this->assertStringContainsString('class="infoblock"', $help);
		$inline = preg_split('/<div class="infoblock">/', $help, 2)[0];
		$this->assertStringNotContainsString('DNSBL Whitelist', $inline);
	}
}
