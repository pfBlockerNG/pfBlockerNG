<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_proxy_tls_flags')]
final class DnsProxyRuntimeNameRequirementTest extends TestCase
{
	private array $saved;

	protected function setUp(): void
	{
		$this->saved = [array_key_exists('config', $GLOBALS), $GLOBALS['config'] ?? NULL];
		$GLOBALS['config'] = [];
		PfbConfig::write('dns/pfb_dns', 'on');
		PfbConfig::write('dns/pfb_dns_interface', 'lo0');
		foreach (['dot', 'doh', 'doq'] as $kind) {
			PfbConfig::write(pfb_dns_config_key("pfb_dns_{$kind}_interface"), 'lo0');
			PfbConfig::write(pfb_dns_config_key("pfb_dns_{$kind}_port"), $kind === 'doh' ? '4443' : '853');
			PfbConfig::write(pfb_dns_config_key("pfb_dns_{$kind}"), '');
		}
	}

	protected function tearDown(): void
	{
		if ($this->saved[0]) {
			$GLOBALS['config'] = $this->saved[1];
		} else {
			unset($GLOBALS['config']);
		}
	}

	/** @return array<string,array{string,string}> */
	public static function unnamedServices(): array
	{
		$cases = [];
		foreach (['dot', 'doh', 'doq'] as $kind) {
			foreach (['' => 'empty', '*.example.net' => 'wildcard', '192.0.2.53' => 'IP', 'resolver.arpa' => 'reserved'] as $name => $label) {
				$cases["{$kind}: {$label}"] = [$kind, (string) $name];
			}
		}
		return $cases;
	}

	#[DataProvider('unnamedServices')]
	public function testStoredUnnamedEncryptedServiceIsNotStarted(string $kind, string $name): void
	{
		PfbConfig::write(pfb_dns_config_key("pfb_dns_{$kind}"), 'on');
		PfbConfig::write('dns/pfb_dns_name', $name);
		$warnings = [];
		$this->assertSame('', pfb_dns_proxy_tls_flags($warnings), "{$kind} must not be served without a valid DNS Name, even with DDR off");
		$this->assertCount(1, $warnings);
		$this->assertStringContainsString('DNS Name', $warnings[0]);

		PfbConfig::write('dns/pfb_dns_name', 'dns.example.net');
		$warnings = [];
		$this->assertNotSame('', pfb_dns_proxy_tls_flags($warnings), 'a valid Name restores the enabled encrypted listener');
		$this->assertSame([], $warnings);
	}

	public function testPlainOnlyNeedsNoNameAndProducesNoEncryptedListenerWarning(): void
	{
		$warnings = [];
		$this->assertSame('', pfb_dns_proxy_tls_flags($warnings));
		$this->assertSame([], $warnings);
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'));
	}
}
