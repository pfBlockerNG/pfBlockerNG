<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4072 -- pfSense calls the CrowdSec rule hook only for a package whose installedpackages/package/<n> entry names it in
 * filter_rule_function. pfSense's install_package_xml() sets that from <filter_rules_needed> in memory only, then runs the
 * package's install command, whose pfb_global() re-reads config.xml and drops it (seen on pfSense CE 2.8.1: empty after
 * `pkg add`). So pfBlockerNG registers it itself, from each trigger that applies the bouncer (CrowdsecTriggersTest; issue #4139:
 * never from the update pass).
 *
 * Intent pinned here:
 *   - it registers pfblockerng.xml's own filter_rules_needed on pfBlockerNG's entry, and writes config.xml once;
 *   - an entry that already names it is left alone (no write), and no other package's entry is touched.
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
}
