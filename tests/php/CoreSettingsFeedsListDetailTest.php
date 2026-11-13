<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_determine_list_detail')]
final class CoreSettingsFeedsListDetailTest extends TestCase
{
	public function testSparseCoreGroupsResolveTheirFolderWithoutWarningsAndPresentKeysKeepTheirValues(): void
	{
		$priorConfig = $GLOBALS['config'] ?? [];
		$priorPfb = $GLOBALS['pfb'];
		$priorDetail = $GLOBALS['pfbarr'] ?? [];
		$warnings = [];
		$GLOBALS['pfb']['reuse'] = '';
		$GLOBALS['config'] = [];
		$path = 'installedpackages/pfblockernglistsv4/config/0';
		config_set_path($path, ['aliasname' => 'Core', 'action' => 'Deny_Both']);
		set_error_handler(static function (int $errno, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			$plain = pfb_determine_list_detail('Deny_Both', '', 'pfblockernglistsv4', 0);
			$noConfig = pfb_determine_list_detail('Deny_Both');
			config_set_path("{$path}/autoaddrnot_out", 'on');
			config_set_path("{$path}/autoproto_out", 'tcp');
			config_set_path("{$path}/agateway_in", 'WAN');
			$invert = pfb_determine_list_detail('Deny_Both', '', 'pfblockernglistsv4', 0);
			$this->assertSame([], $warnings, 'sparse groups and the no-config caller emit no warnings: ' . json_encode($warnings));
			$this->assertSame($GLOBALS['pfb']['denydir'], $plain['folder']);
			$this->assertSame($plain['folder'], $noConfig['folder']);
			$this->assertSame('', $plain['aproto_out']);
			$this->assertSame('', $plain['agateway_in']);
			$this->assertSame($GLOBALS['pfb']['nativedir'], $invert['folder']);
			$this->assertSame('tcp', $invert['aproto_out']);
			$this->assertSame('WAN', $invert['agateway_in']);
		} finally {
			restore_error_handler();
			$GLOBALS['config'] = $priorConfig;
			$GLOBALS['pfb'] = $priorPfb;
			$GLOBALS['pfbarr'] = $priorDetail;
		}
	}
}
