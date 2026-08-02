<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsblListEditorWiringTest extends TestCase
{
	private const FIELDS = [
		'pfb_gp_bypass_list',
		'pfb_noaaaa_list',
		'whitelist',
		'tld_wildcard_exclusion',
		'tld_wildcard_blacklist',
	];

	public function testDisabledEditorEmitsNoPlainListMount(): void
	{
		$this->assertSame('', pfb_dnsbl_editor_render(FALSE)['lists']);
	}

	public function testEnabledEditorMountsEveryDnsblPlainListField(): void
	{
		$init = pfb_dnsbl_editor_render(TRUE)['lists'];

		$this->assertStringContainsString('window.pfbCM', $init);
		$this->assertSame(1, substr_count($init, 'pfbCM.mountLists('));
		foreach (self::FIELDS as $field) {
			$this->assertStringContainsString($field, $init);
		}
	}
}
