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
		unset($GLOBALS['pfb']['reuse'], $GLOBALS['pfb']['reuse_dnsbl']);	// the adapter process never sets them: only the update pass does
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
			$dnsbl = pfb_determine_list_detail('unbound');
			$GLOBALS['pfb']['reuse'] = 'on';
			$GLOBALS['pfb']['reuse_dnsbl'] = 'off';
			$reuseIp = pfb_determine_list_detail('Deny_Both');
			$reuseDnsbl = pfb_determine_list_detail('unbound');
			$this->assertSame([], $warnings, 'sparse groups and the no-config caller emit no warnings: ' . json_encode($warnings));
			$this->assertSame($GLOBALS['pfb']['denydir'], $plain['folder']);
			$this->assertSame($plain['folder'], $noConfig['folder']);
			$this->assertSame('', $plain['aproto_out']);
			$this->assertSame('', $plain['agateway_in']);
			$this->assertSame($GLOBALS['pfb']['nativedir'], $invert['folder']);
			$this->assertSame('tcp', $invert['aproto_out']);
			$this->assertSame('WAN', $invert['agateway_in']);
			$this->assertSame([$GLOBALS['pfb']['dnsdir'], '', ''], [$dnsbl['folder'], $dnsbl['reuse'], $plain['reuse']], 'an unset reuse flag reads as off');
			$this->assertSame(['on', 'off'], [$reuseIp['reuse'], $reuseDnsbl['reuse']], 'a flag the update pass set keeps its value');
		} finally {
			restore_error_handler();
			$GLOBALS['config'] = $priorConfig;
			$GLOBALS['pfb'] = $priorPfb;
			$GLOBALS['pfbarr'] = $priorDetail;
		}
	}
}
