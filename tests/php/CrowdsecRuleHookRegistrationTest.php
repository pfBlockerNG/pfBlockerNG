<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4072 -- pfSense calls the CrowdSec rule hook only for a package whose installedpackages/package/<n> entry names it in
 * filter_rule_function. pfSense's install_package_xml() sets that from <filter_rules_needed> in memory only, then runs the
 * package's install command, whose pfb_global() re-reads config.xml and drops it (seen on pfSense CE 2.8.1: empty after
 * `pkg add`). So pfBlockerNG registers it itself, on every update pass (the install's resync included), as it does its
 * <logging> block.
 *
 * Intent pinned here:
 *   - the pass registers pfblockerng.xml's own filter_rules_needed on pfBlockerNG's entry, and writes config.xml once;
 *   - an entry that already names it is left alone (no write), and no other package's entry is touched;
 *   - the pass calls it before its install/boot early return, so an install and an upgrade register it too.
 */
#[CoversFunction('pfb_crowdsec_register_rule_hook')]
final class CrowdsecRuleHookRegistrationTest extends TestCase
{
	private const OTHER = ['name' => 'squid', 'configurationfile' => 'squid.xml', 'filter_rule_function' => 'squid_generate_rules'];
	private const PFB = ['name' => 'pfBlockerNG-devel', 'configurationfile' => 'pfblockerng.xml', 'version' => '3.4'];

	private mixed $savedConfig;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		unset($GLOBALS['pfb_test_write_config_calls']);
	}

	private static function xmlHook(): string
	{
		$xml = simplexml_load_file(__DIR__ . '/../../src/usr/local/pkg/pfblockerng.xml');
		self::assertNotFalse($xml);
		return (string) $xml->filter_rules_needed;
	}

	public function testAnEntryPfSenseLeftWithoutTheHookGetsThePackageXmlsHookWrittenOnce(): void
	{
		config_set_path('installedpackages/package', [self::OTHER, self::PFB]);
		$this->assertSame('', config_get_path('installedpackages/package/1/filter_rule_function', ''), 'before: not registered');

		pfb_crowdsec_register_rule_hook();

		$this->assertSame('pfb_crowdsec_rules', self::xmlHook());
		$this->assertSame(self::PFB + ['filter_rule_function' => self::xmlHook()], config_get_path('installedpackages/package/1'));
		$this->assertSame(self::OTHER, config_get_path('installedpackages/package/0'), 'another package\'s entry is untouched');
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls'], 'and config.xml is written once');
	}

	public function testAStaleHookNameIsReplaced(): void
	{
		config_set_path('installedpackages/package', [self::PFB + ['filter_rule_function' => 'pfblockerng_rules']]);
		pfb_crowdsec_register_rule_hook();
		$this->assertSame('pfb_crowdsec_rules', config_get_path('installedpackages/package/0/filter_rule_function'));
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testARegisteredHookIsLeftAloneWithoutAWrite(): void
	{
		$registered = [self::OTHER, self::PFB + ['filter_rule_function' => 'pfb_crowdsec_rules']];
		config_set_path('installedpackages/package', $registered);
		pfb_crowdsec_register_rule_hook();
		$this->assertSame($registered, config_get_path('installedpackages/package'));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testWithoutPfBlockerNGsEntryNothingIsWritten(): void
	{
		config_set_path('installedpackages/package', [self::OTHER]);
		pfb_crowdsec_register_rule_hook();
		$this->assertSame([self::OTHER], config_get_path('installedpackages/package'));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testItAnswersWhetherItWroteTheRegistration(): void
	{
		config_set_path('installedpackages/package', [self::PFB]);
		$this->assertTrue(pfb_crowdsec_register_rule_hook(), 'written');
		$this->assertFalse(pfb_crowdsec_register_rule_hook(), 'already there');
		config_set_path('installedpackages/package', [self::OTHER]);
		$this->assertFalse(pfb_crowdsec_register_rule_hook(), 'no pfBlockerNG entry');
	}

	public function testAFreshRegistrationReloadsTheFilterWhileTheBouncerShouldRunIncludingOnAnInstall(): void
	{
		$apply = file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertIsString($apply);
		$pass = substr($apply, (int) strpos($apply, 'function sync_package_pfblockerng('));
		$this->assertSame(1, preg_match('~\$pfb_crowdsec_hook_new = pfb_crowdsec_register_rule_hook\(\) && pfb_crowdsec_should_run\(\);~', $pass),
			'a running bouncer has no rules until the filter reloads with the hook registered');
		$this->assertSame(1, preg_match("~if \\(\\\$pfb_crowdsec_hook_new\\) \\{\\s*\\\$pfb\\['filter_configure'\\] = TRUE;~", $pass),
			'the pass\'s own reload');
		$boot = (int) strpos($pass, "if (is_platform_booting() || \$g['pfblockerng_install'])");
		$branch = substr($pass, $boot, (int) strpos($pass, 'return TRUE;', $boot) - $boot);
		$this->assertSame(1, preg_match('~if \(\$pfb_crowdsec_hook_new && !is_platform_booting\(\)\) \{\s*filter_configure\(\);~', $branch),
			'an install or upgrade returns before that reload, so it asks for one itself (a boot loads the filter anyway)');
	}

	public function testTheUpdatePassRegistersItBeforeItsInstallAndBootEarlyReturn(): void
	{
		$apply = file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertIsString($apply);
		$pass = substr($apply, (int) strpos($apply, 'function sync_package_pfblockerng('));
		$call = strpos($pass, 'pfb_crowdsec_register_rule_hook();');
		$boot = strpos($pass, "if (is_platform_booting() || \$g['pfblockerng_install'])");
		$this->assertNotFalse($call, 'the pass registers the hook');
		$this->assertNotFalse($boot);
		$this->assertLessThan($boot, $call, 'before the install and boot early return');
		$this->assertSame(1, substr_count($apply, 'pfb_crowdsec_register_rule_hook('), 'once per pass');
	}
}
