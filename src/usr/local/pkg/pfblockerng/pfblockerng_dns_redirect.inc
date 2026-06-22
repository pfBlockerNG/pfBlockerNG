<?php

declare(strict_types=1);

// [ ADR-36 ] Optional NAT DNS-redirection rule set (DNS hijack).
//
// Pure builder helpers — no shell/exec, no write_config calls.
// write_config() is always the CALLER'S responsibility.
//
// The sections handled here (nat/rule, filter/rule) are pfSense-core foreign
// sections (ADR-29 exclusion list) — direct config_get_path/config_set_path
// is correct; the RequireConfigGateway sniff does NOT flag pfSense-core paths.
//
// The three registered config keys (dnsbl_redir, dnsbl_redir_int,
// dnsbl_redir_exclude) live in installedpackages/pfblockerngdnsblsettings/
// config/0 and are read exclusively via PfbConfig::read() (ADR-29).

// ---------------------------------------------------------------------------
// Description / marker constants
// ---------------------------------------------------------------------------

/**
 * NAT rdr rule descr prefix for inet (IPv4) DNS-redirect rules.
 * Pattern: pfB_DNS_Redirect_<iface>_v4
 * Must start with 'pfB_' so pfb_fwobj_is_owned() recognises it.
 * Must NOT contain 'pfB DNSBL' (space) — pfb_create_dnsbl() would
 * incorrectly bucket the rule as a DNSBL rule and attempt to remove it.
 */
define('PFB_DNS_REDIR_DESCR_V4_PFX', 'pfB_DNS_Redirect_');

/**
 * Suffix for inet (IPv4) DNS-redirect descr markers.
 * Full descr: PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V4_SFX
 */
define('PFB_DNS_REDIR_DESCR_V4_SFX', '_v4');

/**
 * Suffix for inet6 (IPv6) DNS-redirect descr markers.
 * Full descr: PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V6_SFX
 */
define('PFB_DNS_REDIR_DESCR_V6_SFX', '_v6');

// ---------------------------------------------------------------------------
// pfb_build_dns_redirect_rules — per-interface, per-family rule-set builder
// ---------------------------------------------------------------------------

/**
 * Build the NAT rdr rule + associated filter PASS rule for one interface/family.
 *
 * Ground-truth rule shape (from maintainer's working config.xml — ADR-36 §2.2):
 *
 *   <rule>                                        <!-- nat/rule -->
 *     <!-- source: negated exception alias; <any> when alias is empty -->
 *     <source><address>EXCEPTION_ALIAS</address><not></not></source>
 *     <!-- destination: negated (self) = firewall-self-exempt; port 53 -->
 *     <destination><network>(self)</network><not></not><port>53</port></destination>
 *     <ipprotocol>inet</ipprotocol>
 *     <protocol>tcp/udp</protocol>
 *     <target>127.0.0.1</target>                  <!-- inet; inet6 => ::1 -->
 *     <local-port>53</local-port>
 *     <interface>lan</interface>
 *     <descr><![CDATA[pfB_DNS_Redirect_lan_v4]]></descr>
 *     <associated-rule-id>nat_...</associated-rule-id>
 *     <natreflection>disable</natreflection>
 *   </rule>
 *
 * Invariants (all asserted by PHPUnit golden tests in DnsRedirectBuilderTest.php):
 *   • destination is always negated (self) + port 53 — firewall-self-exempt is
 *     structurally present in every generated rule.
 *   • source is negated-alias when $exception is non-empty; <any> when empty.
 *   • target is '127.0.0.1' for inet; '::1' for inet6.
 *   • natreflection is 'disable' on every rule.
 *   • protocol is 'tcp/udp' on every rule.
 *   • local-port is '53' on every rule.
 *   • descr carries the pfBlockerNG marker (pfB_DNS_Redirect_<iface>_v4/v6) in
 *     BOTH the NAT entry [0] and the associated filter PASS entry [1].
 *
 * @param  string $iface       pfSense interface name (e.g. 'lan', 'opt1').
 * @param  string $ipprotocol  IP family: 'inet' (IPv4) or 'inet6' (IPv6).
 * @param  string $exception   Exception alias/IP string. Empty string = no exception.
 *
 * @return array{0: array<string,mixed>, 1: array<string,mixed>}
 *   [0] => NAT rdr rule config array (for nat/rule).
 *   [1] => Associated filter PASS rule config array (for filter/rule).
 *
 * @throws \InvalidArgumentException if $ipprotocol is not 'inet' or 'inet6'.
 */
function pfb_build_dns_redirect_rules(string $iface, string $ipprotocol, string $exception): array
{
	if ($ipprotocol !== 'inet' && $ipprotocol !== 'inet6') {
		throw new \InvalidArgumentException(
			"pfb_build_dns_redirect_rules: ipprotocol must be 'inet' or 'inet6', got '{$ipprotocol}'"
		);
	}

	$is_v4  = ($ipprotocol === 'inet');
	$target = $is_v4 ? '127.0.0.1' : '::1';
	$suffix = $is_v4 ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
	$descr  = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;

	// -----------------------------------------------------------------------
	// Source element:
	//   When $exception is set: <source><address>$exception</address><not/></source>
	//   When $exception is empty: <source><any/></source>
	// -----------------------------------------------------------------------
	if ($exception !== '') {
		$source = [
			'address' => $exception,
			'not'     => '',
		];
	} else {
		$source = [
			'any' => '',
		];
	}

	// -----------------------------------------------------------------------
	// Destination element (always negated (self) + port 53):
	//   <destination><network>(self)</network><not/><port>53</port></destination>
	// -----------------------------------------------------------------------
	$destination = [
		'network' => '(self)',
		'not'     => '',
		'port'    => '53',
	];

	// -----------------------------------------------------------------------
	// NAT rdr rule [0]
	// -----------------------------------------------------------------------
	$nat_rule = [
		'source'          => $source,
		'destination'     => $destination,
		'ipprotocol'      => $ipprotocol,
		'protocol'        => 'tcp/udp',
		'target'          => $target,
		'local-port'      => '53',
		'interface'       => $iface,
		'descr'           => $descr,
		'natreflection'   => 'disable',
	];

	// -----------------------------------------------------------------------
	// Associated filter PASS rule [1]
	// The associated-rule-id wiring is pfSense's responsibility at apply time;
	// the builder populates the fields that pfSense writes when creating an
	// associated filter rule for a NAT rdr entry.
	// -----------------------------------------------------------------------
	$filter_rule = [
		'source'      => $source,
		'destination' => [
			'address' => $target,
			'port'    => '53',
		],
		'ipprotocol'  => $ipprotocol,
		'protocol'    => 'tcp/udp',
		'interface'   => $iface,
		'descr'       => $descr,
		'type'        => 'pass',
	];

	return [$nat_rule, $filter_rule];
}
