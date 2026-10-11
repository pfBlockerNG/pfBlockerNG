<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3413 -- one global Suppression CIDR Limit (IP tab) for every IP list and for DNSBLIP.
 *
 * Effective limit per list row, resolved by pfb_list_cidr_floors() and applied by the shared IP
 * parser while IP-tab Suppression is on:
 *   - IPv4: the list's own `suppression_cidr` when numeric, else the global IPv4 limit;
 *   - IPv6: the global IPv6 limit (the former per-list IPv6 field is gone and never read);
 *   - a GeoIP row ignores the GLOBAL limits but keeps an explicit per-list IPv4 value;
 *   - an absent or non-numeric value is Disabled.
 * DNSBLIP is a synthesized list with no per-list value, so it takes the global limits.
 *
 * The live download loop is a monolith unsafe off-appliance (#993), so the loop's own resolver call
 * and parse-config literal are eval-extracted from pfblockerng_apply.inc and every parse below runs
 * through them into the shared line parser (pfb_ip_parse_line_replay). A change to how the loop hands
 * the resolved limits or Suppression to the parser therefore fails these tests.
 */
#[CoversFunction('pfb_list_cidr_floors')]
#[CoversFunction('pfb_global')]
final class SuppressionCidrLimitTest extends TestCase
{
	private const IP = 'installedpackages/pfblockerngipsettings/config/0';

	/** DNSBLIP is synthesized with no list row, so it carries no limit of its own. */
	private const DNSBLIP = ['aliasname' => 'DNSBLIP'];

	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_ip_download_loop_oracle_parse_config')) {
			return;
		}
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match('/\[\$pfbcidr, \$pfbcidr_v6\] = pfb_list_cidr_floors\(.*?\);/s', $src, $resolver)) {
			throw new RuntimeException('test bootstrap: the download loop resolver call not found');
		}
		if (!preg_match('/pfb_ip_parse_line_replay\(\$line, (\[.*?\]), \$ip_lineno/s', $src, $config)) {
			throw new RuntimeException('test bootstrap: the download loop parse config not found');
		}
		eval(
			'function pfb_ip_download_loop_oracle_parse_config(array $list, array $row, string $pftype, $custom, array $pfb): array {'
			. ' ' . $resolver[0]
			. ' return ' . $config[1] . '; }'
		);
	}

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $g) {
			$this->saved[$g] = [array_key_exists($g, $GLOBALS), $GLOBALS[$g] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$g] = $value;
			} else {
				unset($GLOBALS[$g]);
			}
		}
	}

	/** Parse $feed as one row of $list through the download loop's resolver and parse config, returning the accumulated list data. */
	private function collected(array $list, string $format, string $global_v4, string $global_v6, string $feed, PfbToggle $suppression = PfbToggle::On): string
	{
		$regex = pfb_ip_regex_config();
		$pfb = [
			'supp' => $suppression, 'supp_cidr' => $global_v4, 'supp_cidr_v6' => $global_v6,
			'range' => $regex['range'], 'ipv4' => $regex['ipv4'], 'ipv6' => $regex['ipv6'],
		];
		$list += ['vtype' => str_contains($feed, ':') ? '_v6' : '_v4'];
		$config = pfb_ip_download_loop_oracle_parse_config($list, ['format' => $format], 'auto', FALSE, $pfb);

		$ip_data = '';
		$lineno = 0;
		$suppressed = FALSE;
		$failed = 0;
		foreach (explode("\n", $feed) as $line) {
			$state = pfb_ip_parse_line_replay($line, $config, $lineno, $ip_data, $suppressed, $failed);
			$lineno = $state['line_number'];
			$suppressed = $state['ip_suppressed'];
			$failed = $state['parse_fail'];
		}
		return $ip_data;
	}

	/**
	 * Scenario: the global limit clamps a DNSBL feed's wide range (the issue's acceptance case).
	 *   Given IP Suppression is on and the global IPv4 limit is 8,
	 *   When a DNSBL feed yielded `1.2.3.0/1` and DNSBLIP_v4 is processed,
	 *   Then DNSBLIP carries the clamped single host `1.2.3.0/32`, not the half-of-IPv4 range.
	 */
	public function testGlobalLimitClampsAWideDnsblFeedRange(): void
	{
		$dnsblip = self::DNSBLIP;

		$this->assertSame("1.2.3.0/1\n", $this->collected($dnsblip, 'auto', 'Disabled', 'Disabled', "1.2.3.0/1\n"),
			'before: no global limit, the wide range is collected as written');
		$this->assertSame("1.2.3.0/32\n", $this->collected($dnsblip, 'auto', '8', 'Disabled', "1.2.3.0/1\n"));
	}

	public function testGlobalIpv6LimitClampsADnsblIpv6Range(): void
	{
		$dnsblip = self::DNSBLIP;

		$this->assertSame("2606:4700:4700::/32\n", $this->collected($dnsblip, 'auto', 'Disabled', 'Disabled', "2606:4700:4700::/32\n"),
			'before: no global limit, the wide range is collected as written');
		$this->assertSame("2606:4700:4700::\n", $this->collected($dnsblip, 'auto', 'Disabled', '48', "2606:4700:4700::/32\n"));
		$this->assertSame("2606:4700:4700::/48\n", $this->collected($dnsblip, 'auto', 'Disabled', '48', "2606:4700:4700::/48\n"),
			'a range exactly at the limit is kept');
	}

	public function testRangeAtOrAboveTheLimitIsKept(): void
	{
		$dnsblip = self::DNSBLIP;
		$this->assertSame("1.2.3.0/8\n", $this->collected($dnsblip, 'auto', '8', '32', "1.2.3.0/8\n"));
		$this->assertSame("1.2.3.0/16\n", $this->collected($dnsblip, 'auto', '8', '32', "1.2.3.0/16\n"));
	}

	/** Without Suppression nothing clamps: the limit is a sub-clause of IP-tab Suppression. */
	public function testGlobalLimitIsInertWhileIpSuppressionIsOff(): void
	{
		$dnsblip = self::DNSBLIP;
		$this->assertSame("1.2.3.0/32\n", $this->collected($dnsblip, 'auto', '8', '32', "1.2.3.0/1\n", PfbToggle::On),
			'before: the limit is live under Suppression');
		$this->assertSame("1.2.3.0/1\n", $this->collected($dnsblip, 'auto', '8', '32', "1.2.3.0/1\n", PfbToggle::Off));

		$v6 = self::DNSBLIP;
		$this->assertSame("2606:4700:4700::\n", $this->collected($v6, 'auto', '8', '48', "2606:4700:4700::/32\n", PfbToggle::On));
		$this->assertSame("2606:4700:4700::/32\n", $this->collected($v6, 'auto', '8', '48', "2606:4700:4700::/32\n", PfbToggle::Off));
	}

	/** An IP list with no limit of its own follows the global one. */
	public function testIpListWithoutItsOwnLimitFollowsTheGlobalLimit(): void
	{
		$this->assertSame("1.2.3.0/32\n", $this->collected([], 'auto', '8', 'Disabled', "1.2.3.0/6\n"));
		$this->assertSame("1.2.3.0/12\n", $this->collected([], 'auto', '8', 'Disabled', "1.2.3.0/12\n"));
		$this->assertSame("1.2.3.0/6\n", $this->collected([], 'auto', 'Disabled', 'Disabled', "1.2.3.0/6\n"));
	}

	/**
	 * Scenario: a list's own IPv4 limit wins over the global one, in both directions.
	 *   Given the global limit is 8,
	 *   When a list has its own limit of 16, Then a /12 is clamped (the own limit applies, not the global),
	 *   When a list has its own limit of 4, Then a /6 is kept (a looser own limit beats a stricter global).
	 */
	public function testPerListIpv4LimitOverridesTheGlobalOne(): void
	{
		$this->assertSame("1.2.3.0/12\n", $this->collected([], 'auto', '8', '32', "1.2.3.0/12\n"), 'before: the global limit alone keeps a /12');
		$this->assertSame("1.2.3.0/32\n", $this->collected(['suppression_cidr' => '16'], 'auto', '8', '32', "1.2.3.0/12\n"));

		$this->assertSame("1.2.3.0/32\n", $this->collected([], 'auto', '8', '32', "1.2.3.0/6\n"), 'before: the global limit alone clamps a /6');
		$this->assertSame("1.2.3.0/6\n", $this->collected(['suppression_cidr' => '4'], 'auto', '8', '32', "1.2.3.0/6\n"));
	}

	/**
	 * Scenario: GeoIP rows ignore the global limits but honour an explicit per-list IPv4 limit.
	 *   Given global limits 8 and 48, When a GeoIP row has no per-list limit, Then nothing is clamped (v4 and v6),
	 *   When the list has its own IPv4 limit, Then that clamp applies to the GeoIP row.
	 */
	public function testGeoipRowIgnoresTheGlobalLimitsButHonoursAnExplicitPerListIpv4Limit(): void
	{
		$this->assertSame("1.2.3.0/32\n", $this->collected([], 'auto', '8', '48', "1.2.3.0/1\n"), 'control: a non-GeoIP row IS clamped by the global limit');
		$this->assertSame("1.2.3.0/1\n", $this->collected([], 'geoip', '8', '48', "1.2.3.0/1\n"));
		$this->assertSame("1.2.3.0/1\n", $this->collected(['suppression_cidr' => 'Disabled'], 'geoip', '8', '48', "1.2.3.0/1\n"));

		$this->assertSame("2606:4700:4700::\n", $this->collected([], 'auto', '8', '48', "2606:4700:4700::/32\n"), 'control: a non-GeoIP IPv6 row IS clamped');
		$this->assertSame("2606:4700:4700::/32\n", $this->collected([], 'geoip', '8', '48', "2606:4700:4700::/32\n"));

		$this->assertSame("1.2.3.0/32\n", $this->collected(['suppression_cidr' => '16'], 'geoip', '8', '48', "1.2.3.0/12\n"));
	}

	/** A key that was never stored reads Disabled: today's behaviour for every upgrader. */
	public function testAbsentGlobalKeysLeaveBothFamiliesUnclamped(): void
	{
		$this->assertNull(config_get_path(self::IP . '/suppression_cidr'), 'before: key absent');
		$v4 = PfbConfig::read('ip/suppression_cidr');
		$v6 = PfbConfig::read('ip/suppression_cidr_v6');
		$this->assertSame(['Disabled', 'Disabled'], [$v4, $v6]);

		$this->assertSame("1.2.3.0/1\n", $this->collected(self::DNSBLIP, 'auto', $v4, $v6, "1.2.3.0/1\n"));
		$this->assertSame("2606:4700:4700::/32\n", $this->collected(self::DNSBLIP, 'auto', $v4, $v6, "2606:4700:4700::/32\n"));
	}

	/** Each family reads only its own global value. */
	public function testEachFamilyReadsOnlyItsOwnGlobalLimit(): void
	{
		$this->assertSame("2606:4700:4700::/32\n", $this->collected([], 'auto', '8', 'Disabled', "2606:4700:4700::/32\n"));
		$this->assertSame("1.2.3.0/1\n", $this->collected([], 'auto', 'Disabled', '48', "1.2.3.0/1\n"));
	}

	/** @return iterable<string,array{0:array<string,mixed>,1:string,2:string,3:string,4:array{0:string,1:string}}> list, format, global v4, global v6, expected */
	public static function precedenceMatrix(): iterable
	{
		foreach (['auto', 'whois'] as $format) {
			yield "{$format}: global only"              => [[], $format, '8', '32', ['8', '32']];
			yield "{$format}: own v4 beats global v4"   => [['suppression_cidr' => '16'], $format, '8', '32', ['16', '32']];
			yield "{$format}: own v4 Disabled -> global" => [['suppression_cidr' => 'Disabled'], $format, '8', '32', ['8', '32']];
			yield "{$format}: own v4 empty -> global"   => [['suppression_cidr' => ''], $format, '8', '32', ['8', '32']];
			yield "{$format}: own v4 junk -> global"    => [['suppression_cidr' => 'abc'], $format, '8', '32', ['8', '32']];
			yield "{$format}: own v4, global Disabled"  => [['suppression_cidr' => '16'], $format, 'Disabled', 'Disabled', ['16', 'Disabled']];
			yield "{$format}: nothing set"              => [[], $format, 'Disabled', 'Disabled', ['Disabled', 'Disabled']];
			yield "{$format}: junk global is Disabled"  => [[], $format, 'abc', '', ['Disabled', 'Disabled']];
			yield "{$format}: only global v6"           => [[], $format, 'Disabled', '48', ['Disabled', '48']];
			yield "{$format}: a stale own v6 is never read" => [['suppression_cidr_v6' => '48'], $format, '8', '32', ['8', '32']];
			yield "{$format}: a stale own v6 with no global" => [['suppression_cidr_v6' => '48'], $format, 'Disabled', 'Disabled', ['Disabled', 'Disabled']];
		}
		yield 'geoip: global ignored'                    => [[], 'geoip', '8', '32', ['Disabled', 'Disabled']];
		yield 'geoip: own v4 applies, global v6 ignored' => [['suppression_cidr' => '16'], 'geoip', '8', '32', ['16', 'Disabled']];
		yield 'geoip: own v4 Disabled stays Disabled'    => [['suppression_cidr' => 'Disabled'], 'geoip', '8', '32', ['Disabled', 'Disabled']];
		yield 'geoip: a stale own v6 is never read'      => [['suppression_cidr_v6' => '48'], 'geoip', '8', '32', ['Disabled', 'Disabled']];
	}

	/**
	 * @param array<string,mixed>      $list
	 * @param array{0:string,1:string} $expected
	 */
	#[DataProvider('precedenceMatrix')]
	public function testEffectiveLimitPerRow(array $list, string $format, string $global_v4, string $global_v6, array $expected): void
	{
		$this->assertSame($expected, pfb_list_cidr_floors($list, $format, $global_v4, $global_v6));
	}

	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		foreach (['pfb_min', 'pfb_hour', 'pfb_dailystart', 'skipfeed'] as $key) {
			config_set_path("{$gen}/{$key}", '0');
		}
		foreach (['suppression' => 'on', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
			'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path(self::IP . "/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '',
			'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '',
			'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => ''] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}
		PfbConfig::write('dnsbl/dnsbl_interface', 'lo0');
	}

	/** pfb_global() publishes the stored limits for the download loop; absent keys publish Disabled. */
	public function testPfbGlobalPublishesTheStoredGlobalLimits(): void
	{
		$this->seedGlobalPrereqs();

		pfb_global();
		$this->assertSame(['Disabled', 'Disabled'], [$GLOBALS['pfb']['supp_cidr'] ?? NULL, $GLOBALS['pfb']['supp_cidr_v6'] ?? NULL],
			'before: nothing stored, both limits are Disabled');

		config_set_path(self::IP . '/suppression_cidr', '8');
		config_set_path(self::IP . '/suppression_cidr_v6', '32');
		pfb_global();
		$this->assertSame(['8', '32'], [$GLOBALS['pfb']['supp_cidr'] ?? NULL, $GLOBALS['pfb']['supp_cidr_v6'] ?? NULL]);
	}

	/**
	 * Scenario: the download loop hands each family its own resolved limit, and Suppression, to the parser.
	 *   Given the loop's resolver call and parse config, global limits IPv4 8 and IPv6 48,
	 *   When a feed yields a wide and a narrow range per family,
	 *   Then, with Suppression On, only the wide ranges are clamped (v4 to a host, v6 to a bare host) -- so
	 *        neither limit reached the other family's parser slot --
	 *   and with Suppression Off nothing is clamped.
	 */
	public function testDownloadLoopHandsEachFamilyItsOwnLimitAndSuppressionToTheParser(): void
	{
		$v4 = "1.2.3.0/1\n1.2.3.0/12\n";
		$v6 = "2606:4700:4700::/32\n2606:4700:4700::/56\n";

		$this->assertSame("1.2.3.0/1\n1.2.3.0/12\n", $this->collected(self::DNSBLIP, 'auto', '8', '48', $v4, PfbToggle::Off),
			'before: Suppression Off, nothing is clamped');
		$this->assertSame("1.2.3.0/32\n1.2.3.0/12\n", $this->collected(self::DNSBLIP, 'auto', '8', '48', $v4));

		$this->assertSame("2606:4700:4700::/32\n2606:4700:4700::/56\n", $this->collected(self::DNSBLIP, 'auto', '8', '48', $v6, PfbToggle::Off),
			'before: Suppression Off, nothing is clamped');
		$this->assertSame("2606:4700:4700::\n2606:4700:4700::/56\n", $this->collected(self::DNSBLIP, 'auto', '8', '48', $v6));
	}
}
