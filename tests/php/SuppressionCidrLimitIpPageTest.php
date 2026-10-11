<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3413 -- the IP tab's global Suppression CIDR Limit: IPv4 Disabled or 1-17, IPv6 Disabled or 1-64.
 *
 * pfblockerng_ip.php is a top-level, session-gated script that cannot be require()d off-appliance (#993),
 * so this class eval-extracts the page's OWN executable regions and runs them as pure functions of their
 * input (pattern: IpArrayFieldIngressGuardTest): the option arrays, the select whitelist that coerces an
 * out-of-range POST to Disabled, the config-section assignment the save persists, and the read that fills
 * the form. The rendered selects and the save round trip are covered live by the Tier A / Tier B suites
 * under tests/smoke/ui.
 */
final class SuppressionCidrLimitIpPageTest extends TestCase
{
	private const IP_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';
	private const IP = 'installedpackages/pfblockerngipsettings/config/0';

	private static function source(): string
	{
		$source = php_strip_whitespace(self::IP_PHP);
		if ($source === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_ip.php');
		}
		return $source;
	}

	/** @return array<int|string,int|string> the options array the page declares for $field */
	private static function declaredOptions(string $field): array
	{
		self::assertSame(1, preg_match('/\$options_' . $field . '\s*=\s*([^;]+);/', self::source(), $m),
			"the page must declare \$options_{$field}");
		$options = eval("return {$m[1]};");
		self::assertIsArray($options);
		return $options;
	}

	/** The page's Select-field whitelist loop, run over $post with the page's own CIDR option arrays. */
	private static function whitelisted(array $post): array
	{
		if (!function_exists('pfb_ip_oracle_select_whitelist')) {
			if (!preg_match('/(\$select_options = array\(.*?)(?=if \(!is_ipaddrv4)/s', self::source(), $m)) {
				throw new RuntimeException('test bootstrap: ip.php select whitelist region not found');
			}
			eval(
				'function pfb_ip_oracle_select_whitelist(array $post, array $options_suppression_cidr, array $options_suppression_cidr_v6): array {'
				. ' $_POST = $post;'
				. " \$options_asn_reporting = ['disabled' => 'x']; \$options_maxmind_locale = ['en' => 'x'];"
				. " \$options_inbound_deny_action = ['block' => 'x']; \$options_outbound_deny_action = ['reject' => 'x'];"
				. " \$options_pass_order = ['order_0' => 'x']; \$options_autorule_suffix = ['autorule' => 'x'];"
				. $m[1]
				. ' return $_POST; }'
			);
		}
		return pfb_ip_oracle_select_whitelist(
			$post + ['asn_reporting' => 'disabled', 'maxmind_locale' => 'en', 'inbound_deny_action' => 'block',
				'outbound_deny_action' => 'reject', 'pass_order' => 'order_0', 'autorule_suffix' => 'autorule',
				'suppression_cidr' => 'Disabled', 'suppression_cidr_v6' => 'Disabled'],
			self::declaredOptions('suppression_cidr'),
			self::declaredOptions('suppression_cidr_v6')
		);
	}

	/** The page's save assignments into the IP config section, run over a (whitelisted) $post. */
	private static function savedSection(array $post): array
	{
		if (!function_exists('pfb_ip_oracle_save_region')) {
			if (!preg_match('/(\$pfb\[\'iconfig\'\]\[\'enable_dup\'\].*?\$pfb\[\'iconfig\'\]\[\'v6suppression\'\][^;]*;)/s', self::source(), $m)) {
				throw new RuntimeException('test bootstrap: ip.php save region not found');
			}
			eval(
				'function pfb_ip_oracle_save_region(array $post): array {'
				. ' $_POST = $post; $pfb = array("iconfig" => array());'
				. ' $pfb_maxmind_key_post = ""; $pfb_asn_token_post = ""; $pfb_fw_self_post = "";'
				. $m[1]
				. ' return $pfb["iconfig"]; }'
			);
		}
		return pfb_ip_oracle_save_region($post + [
			'ip_placeholder' => '127.1.7.7', 'maxmind_locale' => 'en', 'maxmind_account' => '', 'asn_reporting' => 'disabled',
			'inbound_interface' => ['wan'], 'inbound_deny_action' => 'block', 'outbound_interface' => ['lan'],
			'outbound_deny_action' => 'reject', 'pass_order' => 'order_0', 'autorule_suffix' => 'autorule',
			'v4suppression' => '', 'v6suppression' => '',
		]);
	}

	/** The options -- the whitelist's domain -- are Disabled plus exactly the per-list ranges (v4 1-17, v6 1-64). */
	public function testOptionsAreDisabledPlusTheSamePerListRanges(): void
	{
		$this->assertSame(['Disabled' => 'Disabled'] + array_combine(range(1, 17), range(1, 17)), self::declaredOptions('suppression_cidr'));
		$this->assertSame(['Disabled' => 'Disabled'] + array_combine(range(1, 64), range(1, 64)), self::declaredOptions('suppression_cidr_v6'));
	}

	/** @return iterable<string,array{0:string,1:string,2:string}> field, posted value, stored value */
	public static function postedValues(): iterable
	{
		foreach ([
			'suppression_cidr'    => ['1', '8', '17', 'Disabled'],
			'suppression_cidr_v6' => ['1', '32', '64', 'Disabled'],
		] as $field => $valid) {
			foreach ($valid as $value) {
				yield "{$field} {$value} is kept" => [$field, $value, $value];
			}
		}
		foreach ([
			'suppression_cidr'    => ['18', '0', '-1', '08', '1e1', ' 8', '8 ', '8.0', 'abc', 'disabled', '8;rm', '65'],
			'suppression_cidr_v6' => ['65', '0', '-1', '032', '1e1', ' 32', '32 ', '32.0', 'abc', 'disabled', '32;rm'],
		] as $field => $junk) {
			foreach ($junk as $value) {
				yield "{$field} '{$value}' becomes Disabled" => [$field, $value, 'Disabled'];
			}
		}
	}

	/** A value outside the option range never reaches the save: the whitelist turns it into Disabled first. */
	#[DataProvider('postedValues')]
	public function testPostedValueIsKeptOnlyWhenItIsAnOption(string $field, string $posted, string $stored): void
	{
		$post = self::whitelisted([$field => $posted]);
		$this->assertSame($stored, $post[$field]);
		$this->assertSame($stored, self::savedSection($post)[$field], 'the save persists the whitelisted value');
	}

	/** An array-valued POST (suppression_cidr[]=8) is coerced to Disabled, never persisted as an array. */
	public function testArrayPostIsCoercedToDisabled(): void
	{
		$post = self::whitelisted(['suppression_cidr' => ['8'], 'suppression_cidr_v6' => ['32']]);
		$this->assertSame(['Disabled', 'Disabled'], [$post['suppression_cidr'], $post['suppression_cidr_v6']]);
	}

	/** Each family persists its own field: v4 never lands in the IPv6 key and the reverse. */
	public function testEachFamilyIsStoredUnderItsOwnKey(): void
	{
		$saved = self::savedSection(self::whitelisted(['suppression_cidr' => '8', 'suppression_cidr_v6' => '48']));
		$this->assertSame(['8', '48'], [$saved['suppression_cidr'], $saved['suppression_cidr_v6']]);
	}

	/** An empty POST (select absent) is stored as Disabled, the registry default. */
	public function testAnEmptyPostIsStoredAsDisabled(): void
	{
		$saved = self::savedSection(['suppression_cidr' => '', 'suppression_cidr_v6' => '']);
		$this->assertSame(['Disabled', 'Disabled'], [$saved['suppression_cidr'], $saved['suppression_cidr_v6']]);
	}

	/** The form is filled from the registered keys: stored values show, absent keys show Disabled. */
	public function testFormIsFilledFromTheRegisteredKeys(): void
	{
		$matched = preg_match_all(
			'/\$pconfig\[\'(suppression_cidr(?:_v6)?)\'\]\s*=\s*PfbConfig::read\(\'ip\/(suppression_cidr(?:_v6)?)\'\);/', self::source(), $m, PREG_SET_ORDER
		);
		$this->assertSame(2, $matched, 'the page must read both limits through the gateway');
		$statements = array_column($m, 0);
		foreach ($m as [, $field, $key]) {
			$this->assertSame($field, $key, 'each form field reads its own registered key');
		}

		$GLOBALS['config'] = [];
		$pconfig = [];
		eval(implode("\n", $statements));
		$this->assertSame(['Disabled', 'Disabled'], [$pconfig['suppression_cidr'], $pconfig['suppression_cidr_v6']], 'before: nothing stored');

		config_set_path(self::IP . '/suppression_cidr', '8');
		config_set_path(self::IP . '/suppression_cidr_v6', '32');
		eval(implode("\n", $statements));
		$this->assertSame(['8', '32'], [$pconfig['suppression_cidr'], $pconfig['suppression_cidr_v6']]);
	}
}
