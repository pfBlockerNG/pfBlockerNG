<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 6 — www/ group A gateway routing tests.
 *
 * Covers the three settings pages routed in Phase 6:
 *   - pfblockerng_general.php  (section: installedpackages/pfblockerng/config/0)
 *   - pfblockerng_ip.php       (section: installedpackages/pfblockerngipsettings/config/0)
 *   - pfblockerng_dnsbl.php    (section: installedpackages/pfblockerngdnsblsettings/config/0)
 *
 * Test groups:
 *
 * A — LOAD DEFAULT PARITY
 *   For every field whose page-local `isset() ? ... : 'on'` default was removed and
 *   replaced by PfbConfig::read(), assert that PfbConfig::read($key) on an absent
 *   section returns the SAME value the page used to produce.  Fields not changed
 *   (registry default differs from the page default, or field is not in the registry)
 *   are asserted to confirm the registry default does NOT match the page default —
 *   proving those were correctly left on their section-array access.
 *
 * B — SAVE ROUND-TRIP IDENTITY
 *   For every section routed through PfbConfig::writeSection(), assert that writing
 *   an array and reading it back via PfbConfig::readSection() returns byte-identical
 *   values.  Models the exact pattern the page save handler uses: build the section
 *   array in $pfb['xconfig'], call writeSection, then confirm readSection returns it.
 *
 * Scenario (group A):
 *   Background: config.xml is empty — no pfblockerng* sections.
 *     Given PfbConfig::read($key) with no seed.
 *     When the key is absent.
 *     Then the gateway default equals the prior page default (parity).
 *
 * Scenario (group B):
 *   Background: a representative save-handler array is built.
 *     Given a section array mirroring what a page save handler would produce.
 *     When PfbConfig::writeSection(section, array) is called.
 *     Then PfbConfig::readSection(section) returns the same array byte-for-byte.
 */
final class WwwGroupAGatewayTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — Load default parity: General page fields
	// -----------------------------------------------------------------------

	/**
	 * pfb_keep: page used `isset($pfb['gconfig']['pfb_keep']) ? ... : 'on'` — default 'on'.
	 * Registry default = 'on' (PfbToggle::On). Page default REMOVED; gateway owns it.
	 *
	 * Parity: absent key → PfbConfig::read('gen/pfb_keep')->value === 'on' (was: 'on').
	 * Present empty is explicit Off; legacy 'off' remains read-compatible and is never written.
	 */
	public function testGeneralPfbKeepAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_keep';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'pfb_keep must be absent for this test');

		// When: gateway read (replaces the removed isset() ? ... : 'on').
		$result = PfbConfig::read('gen/pfb_keep');

		// Then: PfbToggle::On, value 'on' — matches prior page default 'on'.
		// PfbToggle owns the default-on adapter contract.
		$this->assertSame(PfbToggle::On, $result, 'pfb_keep absent -> PfbToggle::On');
		$this->assertSame('on', $result->value, 'pfb_keep absent -> value "on" (parity with prior isset default)');
	}

	/**
	 * pfb_feed_internal_filter: page used `isset(...) ? ... : 'on'` — default 'on'.
	 * Registry default = 'on'. Page default REMOVED; gateway owns it.
	 *
	 * Parity: absent key → PfbConfig::read('gen/pfb_feed_internal_filter') === 'on'.
	 */
	public function testGeneralPfbFeedInternalFilterAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_feed_internal_filter';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'pfb_feed_internal_filter must be absent');

		// When: gateway read (replaces the removed isset() ? ... : 'on').
		$result = PfbConfig::read('gen/pfb_feed_internal_filter');

		// Then: On — matches prior page default ('on'); the enum since issue #1887.
		$this->assertSame(PfbToggle::On, $result, 'pfb_feed_internal_filter absent -> On (parity with prior isset default)');
	}

	/**
	 * issue #1907: pfb_cache, pfb_py_reply, pfb_hsts -- the #1907-class page/registry
	 * divergence this closes. Their page-local `isset(...) ? ... : 'on'` defaults were
	 * REMOVED and replaced by PfbConfig::read(); the registry default flipped from ''
	 * to 'on' to match, closing the mismatch this test used to document (previously
	 * the page and registry defaults disagreed, so the page-local default was
	 * deliberately kept -- issue #1921 S3 resolves that by adopting the toggle
	 * adapter and matching default, same as pfb_idn_block_malicious already had).
	 *
	 * Parity: absent key -> PfbConfig::read($key) === On (matches the prior page default).
	 */
	public function testDnsblPfbCachePfbPyReplyPfbHstsAbsentDefaultMatchesPriorPageDefault(): void
	{
		// pfb_cache: registry default now 'on' (matches the removed page default).
		$this->assertNull(config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_cache'),
			'pfb_cache absent -> On (parity with prior isset default)');

		// pfb_py_reply: registry default now 'on' (matches the removed page default).
		$this->assertNull(config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_py_reply'),
			'pfb_py_reply absent -> On (parity with prior isset default)');

		// pfb_hsts: registry default now 'on' (matches the removed page default).
		$this->assertNull(config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_hsts'),
			'pfb_hsts absent -> On (parity with prior isset default)');
	}

	// -----------------------------------------------------------------------
	// A — Load default parity: DNSBL page fields
	// -----------------------------------------------------------------------

	/**
	 * pfb_idn_block_malicious: page used `isset(...) ? ... : 'on'` — default 'on'.
	 * Registry default = 'on'. Page default REMOVED; gateway owns it.
	 *
	 * Parity: absent key → PfbConfig::read('dnsbl/pfb_idn_block_malicious') === 'on'.
	 */
	public function testDnsblPfbIdnBlockMaliciousAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'pfb_idn_block_malicious must be absent');

		// When: gateway read (replaces the removed isset() ? ... : 'on').
		$result = PfbConfig::read('dnsbl/pfb_idn_block_malicious');

		// Then: 'on' — matches prior page default.
		$this->assertSame(PfbToggle::On, $result, 'pfb_idn_block_malicious absent -> On (parity with prior isset default)');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: General section
	// -----------------------------------------------------------------------

	/**
	 * General section write → read round-trips byte-identically via gateway.
	 *
	 * Scenario:
	 *   Given a representative General settings array (mirrors what the save handler builds).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array.
	 */
	public function testGeneralSectionWriteReadRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';

		$data = [
			'enable_cb'                  => 'on',
			'pfb_keep'                   => 'on',
			'pfb_feed_internal_filter'   => 'on',
			'pfb_feed_internal_allowlist' => base64_encode("10.0.0.0/8\n"),
			'pfb_interval'               => '1',
			'pfb_min'                    => '0',
			'pfb_hour'                   => '0',
			'pfb_dailystart'             => '0',
			'skipfeed'                   => '0',
			'pfb_agg_types'              => '',
			'log_max_log'                => '20000',
			'log_max_errlog'             => '20000',
			'log_max_extraslog'          => '20000',
			'log_max_ip_blocklog'        => '20000',
			'log_max_ip_permitlog'       => '20000',
			'log_max_ip_matchlog'        => '20000',
			'log_max_dnslog'             => '20000',
			'log_max_dnsbl_parse_err'    => '20000',
			'log_max_dnsreplylog'        => '20000',
			'log_max_unilog'             => '20000',
			'log_max_days_log'           => '0',
			'log_max_days_errlog'        => '0',
			'log_max_days_extraslog'     => '0',
			'log_max_days_ip_blocklog'   => '0',
			'log_max_days_ip_permitlog'  => '0',
			'log_max_days_ip_matchlog'   => '0',
			'log_max_days_dnslog'        => '0',
			'log_max_days_dnsbl_parse_err' => '0',
			'log_max_days_dnsreplylog'   => '0',
			'log_max_days_unilog'        => '0',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'section absent -> empty array before write');

		// When: write (models the page save handler).
		PfbConfig::writeSection($section, $data);

		// Then: read back is byte-identical.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'General section round-trips identically through gateway');
	}

	/**
	 * ADR-60 Phase 8: log_max_days_<type> (age-based log retention) toggled from its
	 * default '0' (disabled) to a set value round-trips correctly through the gateway —
	 * the Log Settings page's new field, replacing the retired log_rotate_/
	 * log_reset_keep_ controls.
	 *
	 * Asserts the before-state ('0') and the after-state ('30') are distinct — proving
	 * the write actually changed the stored value, not just replayed the default.
	 */
	public function testGeneralLogMaxDaysIpBlocklogRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';

		// Given: write the default '0' first (mirrors an unconfigured/new install).
		PfbConfig::writeSection($section, ['log_max_days_ip_blocklog' => '0']);
		$this->assertSame('0', PfbConfig::readSection($section)['log_max_days_ip_blocklog'], 'log_max_days_ip_blocklog starts as "0"');

		// When: write '30' (operator opts into a 30-day retention window and saves).
		PfbConfig::writeSection($section, ['log_max_days_ip_blocklog' => '30']);

		// Then: reads back as '30'.
		$this->assertSame('30', PfbConfig::readSection($section)['log_max_days_ip_blocklog'], 'log_max_days_ip_blocklog "30" round-trips identically');
	}

	/**
	 * General section: pfb_keep = '' (disabled) is preserved byte-for-byte.
	 * Asserts the before-state ('on') and the after-state ('off') are distinct —
	 * proving the write changed the value rather than being an always-equal no-op.
	 *
	 * Issue #930: writeSection() applies the toggle adapter to every registered
	 * field of the target section, preserving the canonical empty Off token.
	 */
	public function testGeneralSectionPfbKeepEmptyPreservesExplicitOff(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';

		// Given: write 'on' first.
		PfbConfig::writeSection($section, ['pfb_keep' => 'on']);
		$this->assertSame('on', PfbConfig::readSection($section)['pfb_keep'], 'pfb_keep starts as "on"');

		// When: write '' — the owner-ruled Off token.
		PfbConfig::writeSection($section, ['pfb_keep' => '']);

		// Then: reads back as the owner-ruled empty Off token.
		$this->assertSame('', PfbConfig::readSection($section)['pfb_keep'], "pfb_keep '' remains empty");
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: IP section
	// -----------------------------------------------------------------------

	/**
	 * IP section write → read round-trips byte-identically via gateway.
	 *
	 * Scenario:
	 *   Given a representative IP settings array (mirrors what the save handler builds).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array.
	 */
	public function testIpSectionWriteReadRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngipsettings/config/0';

		$data = [
			'enable_dup'           => '',
			'enable_agg'           => '',
			'suppression'          => 'on',
			'enable_log'           => '',
			'ip_placeholder'       => '127.1.7.7',
			'maxmind_locale'       => 'en',
			'asn_reporting'        => 'disabled',
			'asn_token'            => '',
			'database_cc'          => '',
			'maxmind_account'      => '',
			'maxmind_key'          => '',
			'inbound_interface'    => '',
			'inbound_deny_action'  => 'block',
			'outbound_interface'   => '',
			'outbound_deny_action' => 'reject',
			'enable_float'         => '',
			'pass_order'           => 'order_0',
			'autorule_suffix'      => 'autorule',
			'killstates'           => '',
			'v4suppression'        => base64_encode('192.168.1.1/32'),
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'IP section absent -> empty array before write');

		// When: write (models the page save handler).
		PfbConfig::writeSection($section, $data);

		// Then: read back is byte-identical.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'IP section round-trips identically through gateway');
	}

	/**
	 * IP section: suppression toggled from 'on' -> '' round-trips correctly. issue
	 * #1907 adopted the toggle adapter (default on); present empty is the owner-ruled Off
	 * state while an absent key resolves to the registered default.
	 */
	public function testIpSectionSuppressionOffRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerngipsettings/config/0';

		// Given: write 'on' first.
		PfbConfig::writeSection($section, ['suppression' => 'on']);
		$this->assertSame('on', PfbConfig::readSection($section)['suppression'], 'suppression starts as "on"');

		// When: write the owner-ruled empty Off token.
		PfbConfig::writeSection($section, ['suppression' => '']);

		// Then: reads back as empty -- the disabled state survives.
		$this->assertSame('', PfbConfig::readSection($section)['suppression'], "suppression empty round-trips");
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: DNSBL section
	// -----------------------------------------------------------------------

	/**
	 * DNSBL section write → read round-trips byte-identically via gateway.
	 *
	 * Scenario:
	 *   Given a representative DNSBL settings array (mirrors what the save handler builds).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array.
	 *
	 * Issue #930: pfb_idn is adapter-bearing (PfbIdnMode); its fixture value uses
	 * the canonical empty Off token so this stays a true byte-identical
	 * round-trip assertion.
	 */
	public function testDnsblSectionWriteReadRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';

		$data = [
			'pfb_dnsbl'                  => 'on',
			'tld_wildcard'               => '',
			'pfb_control'                => '',
			'pfb_control_legacy'         => '',
			'pfb_dnsvip_auto'            => '',
			'pfb_dnsvip4'                => '',
			'pfb_dnsvip6'                => '',
			'pfb_dnsport'                => '8081',
			'pfb_dnsport_ssl'            => '8443',
			'dnsbl_interface'            => 'lo0',
			'pfb_dnsbl_rule'             => '',
			'dnsbl_allow_int'            => '',
			'global_log'                 => '',
			'dnsbl_webpage'              => 'dnsbl_default.php',
			'pfb_cache'                  => 'on',
			'pfb_cache_flush'            => 'on',
			'pfb_py_reply'               => 'on',
			'pfb_hsts'                   => 'on',
			'pfb_idn'                    => 'off',
			'pfb_idn_block_malicious'    => 'on',
			'pfb_idn_escalate_suspicious' => '',
			'pfb_regex'                  => '',
			'pfb_regex_cap'              => '',
			'pfb_cname'                  => '',
			'pfb_dnsbl_lenient'          => 'off',
			'pfb_noaaaa'                 => '',
			'pfb_gp'                     => '',
			'tld_allow'                  => '',
			'tld_allow_sort'             => '',
			'pfb_py_nolog'               => '',
			'pfb_regex_list'             => '',
			'pfb_noaaaa_list'            => '',
			'pfb_gp_bypass_list'         => '',
			'whitelist'                  => '',
			'tld_wildcard_exclusion'     => '',
			'tld_wildcard_blacklist'     => '',
			'action'                     => 'Disabled',
			'aliaslog'                   => 'enabled',
			'top1m_enable'               => '',
			'top1m_source'               => 'tranco',
			'top1m_count'                => '1000',
			'pfb_py_cache_max'           => '10000',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'DNSBL section absent -> empty array before write');

		// When: write (models the page save handler).
		PfbConfig::writeSection($section, $data);

		// Then: read back is byte-identical. Toggle Off values are stored as empty.
		$expected = $data;
		$expected['pfb_dnsvip_auto'] = '';
		$expected['pfb_regex_cap']   = '';
		$expected['pfb_idn_escalate_suspicious'] = '';
		$expected['pfb_idn'] = '';
		$expected['pfb_dnsbl_lenient'] = '';
		$result = PfbConfig::readSection($section);
		$this->assertSame($expected, $result, 'DNSBL section round-trips with only the #1887 toggle canonicalisation');
	}

	/**
	 * DNSBL pfb_idn_block_malicious toggled from 'on' → '' round-trips correctly.
	 * Asserts the before-state ('on') and the after-state ('') are distinct.
	 */
	public function testDnsblPfbIdnBlockMaliciousOffRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';

		// Given: write 'on' first.
		PfbConfig::writeSection($section, ['pfb_idn_block_malicious' => 'on']);
		$this->assertSame('on', PfbConfig::readSection($section)['pfb_idn_block_malicious'], 'pfb_idn_block_malicious starts as "on"');

		// When: write the owner-ruled empty Off token.
		PfbConfig::writeSection($section, ['pfb_idn_block_malicious' => '']);

		// Then: reads back as empty — the disabled state survives.
		$this->assertSame('', PfbConfig::readSection($section)['pfb_idn_block_malicious'], "pfb_idn_block_malicious empty round-trips");
	}

	/**
	 * pfb_feed_internal_filter toggled from 'on' → empty round-trips correctly.
	 * Asserts the before-state ('on') and the after-state (empty) are distinct.
	 */
	public function testGeneralPfbFeedInternalFilterOffRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerng/config/0';

		// Given: write 'on' first (mirrors a new install state).
		PfbConfig::writeSection($section, ['pfb_feed_internal_filter' => 'on']);
		$this->assertSame('on', PfbConfig::readSection($section)['pfb_feed_internal_filter'], 'pfb_feed_internal_filter starts as "on"');

		// When: write empty (user unchecked the box and saved).
		PfbConfig::writeSection($section, ['pfb_feed_internal_filter' => '']);

		// Then: reads back as empty.
		$this->assertSame('', PfbConfig::readSection($section)['pfb_feed_internal_filter'], 'pfb_feed_internal_filter empty round-trips identically');
	}
}
