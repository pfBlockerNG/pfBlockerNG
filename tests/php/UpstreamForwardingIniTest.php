<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3879: the DNSBL module detects upstream blocks only while pfb_unbound.ini says `forwarding = on`. pfSense stores
 * the Resolver's "DNS Query Forwarding" checkbox as bool true (services_unbound.php), which config.xml keeps as an empty
 * element and every later read returns as ''. The ini must say on for both stored shapes and off when the key is absent.
 */
#[CoversFunction('pfb_unbound_python_ini')]
final class UpstreamForwardingIniTest extends TestCase
{
	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $root;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->root = sys_get_temp_dir() . '/pfb_upstream_ini_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root, 0700));
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->root;
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->root);
	}

	/** @return array<string, array{0: bool|string|null, 1: string}> */
	public static function storedForwarding(): array
	{
		return [
			'empty element, as config.xml reads it back' => ['', 'on'],
			'bool true, as the Resolver page saves it' => [TRUE, 'on'],
			'absent: the Resolver resolves itself' => [NULL, 'off'],
		];
	}

	#[DataProvider('storedForwarding')]
	public function testTheIniForwardingFollowsTheResolverCheckbox(bool|string|null $stored, string $expected): void
	{
		if ($stored !== NULL) {
			config_set_path('unbound/forwarding', $stored);
		}
		pfb_global();
		pfb_dnsbl_ini_inputs();

		$ini = pfb_unbound_python_ini('enabled');

		$this->assertMatchesRegularExpression('/^forwarding\t= (on|off)$/m', $ini, 'the ini carries the forwarding key');
		$this->assertStringContainsString("\nforwarding\t= {$expected}\n", $ini, "stored forwarding " . var_export($stored, TRUE) . " must write forwarding = {$expected}");
	}
}
