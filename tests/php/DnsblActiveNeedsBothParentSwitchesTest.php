<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3770 -- DNSBL is on, as far as every consumer of pfb_dnsbl_active() is concerned, only while pfBlockerNG AND pfB-DNS AND
 * DNSBL are on: pfB-DNS is a parent switch of DNSBL exactly as the pfBlockerNG enable is. A missing key reads as off.
 */
#[CoversFunction('pfb_dnsbl_active')]
final class DnsblActiveNeedsBothParentSwitchesTest extends TestCase
{
	private mixed $savedPfb = NULL;
	private bool $hadPfb = FALSE;

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

	/** @return array<string,array{?PfbToggle,?PfbToggle,?PfbToggle,bool}> pfBlockerNG enable, pfB-DNS enable, DNSBL enable (NULL = key missing), active */
	public static function switchStates(): array
	{
		$on = PfbToggle::On;
		$off = PfbToggle::Off;
		return [
			'all on' => [$on, $on, $on, TRUE],
			'pfBlockerNG off' => [$off, $on, $on, FALSE],
			'pfB-DNS off' => [$on, $off, $on, FALSE],
			'DNSBL off' => [$on, $on, $off, FALSE],
			'pfBlockerNG and pfB-DNS off' => [$off, $off, $on, FALSE],
			'pfB-DNS key missing' => [$on, NULL, $on, FALSE],
			'pfBlockerNG key missing' => [NULL, $on, $on, FALSE],
			'DNSBL key missing' => [$on, $on, NULL, FALSE],
		];
	}

	#[DataProvider('switchStates')]
	public function testDnsblIsActiveOnlyWhileEveryOneOfThePackagePfbDnsAndDnsblIsOn(?PfbToggle $enable, ?PfbToggle $pfbDns, ?PfbToggle $dnsbl, bool $active): void
	{
		$GLOBALS['pfb'] = array_filter(
			['enable' => $enable, 'pfb_dns' => $pfbDns, 'dnsbl' => $dnsbl],
			static fn (?PfbToggle $toggle): bool => $toggle !== NULL
		);

		$this->assertSame($active, pfb_dnsbl_active());
	}
}
