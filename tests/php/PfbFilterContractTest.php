<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter() — PFBL-01 validation-contract pins for the constants used at the
 * feed/manifest, SafeSearch and VIP boundaries:
 *
 *   - PFB_FILTER_DOMAIN : SafeSearch CNAME targets, alert/unlock domains,
 *                         suppression (whitelist) lines.
 *   - PFB_FILTER_WORD   : feed headers (the per-feed file/manifest labels) and
 *                         pfSense friendly interface names ('lo0'/'lan'/'optN').
 *   - PFB_FILTER_IP(V4) : address-valued settings (e.g. the external DNS server).
 *
 * Branch coverage per the repo rules — every constant is pinned from BOTH sides:
 * representative valid values pass through UNCHANGED (the filter must never
 * mangle good data), and each documented invalid input class returns the default
 * ('' here). PfbFilterTest covers the basics; this file adds the boundary-shaped
 * inputs the PFBL-01 call sites must rely on being rejected: '..' sequences and
 * separator characters, command-line metacharacters, embedded whitespace/quotes,
 * and overlong values.
 */
#[CoversFunction('pfb_filter')]
final class PfbFilterContractTest extends TestCase
{
	// --- PFB_FILTER_DOMAIN ------------------------------------------------------

	/** @return array<string, array{0: string}> label => valid domain returned unchanged */
	public static function domainAcceptedProvider(): array
	{
		// Longest legal shape: 63+63+63+61 char labels + 3 dots = 253 chars
		// (< the 255 limit), every label at or under the 63-char label cap.
		$longest = sprintf(
			'%s.%s.%s.%s',
			str_repeat('a', 63),
			str_repeat('b', 63),
			str_repeat('c', 63),
			str_repeat('d', 61)
		);

		return [
			'plain domain'            => ['example.com'],
			'deep subdomain'          => ['a.b.c.d.example.com'],
			'digits and dash'         => ['feed-01.example-cdn.net'],
			'underscore label'        => ['_dmarc.example.com'],
			'leading-dot wildcard'    => ['.example.com'],   // suppression wildcard form
			'63-char label boundary'  => [str_repeat('a', 63) . '.com'],
			'253-char total boundary' => [$longest],
		];
	}

	#[DataProvider('domainAcceptedProvider')]
	public function testDomainFilterReturnsValidValueUnchanged(string $domain): void
	{
		$this->assertSame($domain, pfb_filter($domain, PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => value the DOMAIN filter must reject */
	public static function domainRejectedProvider(): array
	{
		return [
			'parent-dir sequence'        => ['../../etc/passwd'],
			'dot-dot inside a name'      => ['example..com'],
			'embedded slash'             => ['example.com/etc'],
			'backslash'                  => ['example\\.com'],
			'semicolon suffix'           => ['example.com;ls'],
			'dollar-paren'               => ['$(hostname).com'],
			'backtick'                   => ['`hostname`.com'],
			'pipe'                       => ['a.com|b.com'],
			'ampersand'                  => ['a.com&b.com'],
			'redirection'                => ['a.com>out.com'],
			'embedded space'             => ['exam ple.com'],
			'single quote'               => ["exam'ple.com"],
			'double quote'               => ['exam"ple.com'],
			'embedded newline'           => ["example.com\nmore.com"],
			'embedded tab'               => ["example\t.com"],
			'embedded NUL'               => ["example.com\0"],
			'at-sign'                    => ['user@example.com'],
			'colon (host:port)'          => ['example.com:8080'],
			'64-char label (overlong)'   => [str_repeat('a', 64) . '.com'],
			// 63+63+63+63 char labels + 3 dots = 255 chars: every label is legal,
			// the total length is what trips the < 255 limit.
			'255-char total (overlong)'  => [str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 63)],
		];
	}

	#[DataProvider('domainRejectedProvider')]
	public function testDomainFilterRejectsToDefault(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	// --- PFB_FILTER_WORD (feed headers + friendly interface names) ---------------

	/** @return array<string, array{0: string}> label => valid \w-only value returned unchanged */
	public static function wordAcceptedProvider(): array
	{
		return [
			// Feed-header shapes (the '{header}{vtype}' file/manifest labels).
			'plain header'         => ['EasyList'],
			'header with vtype'    => ['Abuse_ch_v4'],
			'custom-list header'   => ['MyAlias_custom'],
			'dnsblip header'       => ['DNSBLIP_v6'],
			// Friendly interface names as stored in dnsbl_interface
			// (pfb_build_if_list: wan/lan/optN/lo0/enc0/openvpn/l2tp).
			'localhost interface'  => ['lo0'],
			'lan interface'        => ['lan'],
			'optN interface'       => ['opt12'],
			'ipsec interface'      => ['enc0'],
			'openvpn interface'    => ['openvpn'],
		];
	}

	#[DataProvider('wordAcceptedProvider')]
	public function testWordFilterReturnsValidValueUnchanged(string $word): void
	{
		$this->assertSame($word, pfb_filter($word, PFB_FILTER_WORD, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => value the WORD filter must reject */
	public static function wordRejectedProvider(): array
	{
		return [
			'parent-dir sequence'  => ['..'],
			'relative path'        => ['../feed'],
			'embedded slash'       => ['feeds/evil'],
			'backslash'            => ['feed\\name'],
			'dot (file suffix)'    => ['feed.txt'],
			'dotted device name'   => ['igb1.100'],   // dnsbl_interface stores friendly names; dotted VLAN device names are out of contract
			'dash'                 => ['feed-name'],
			'embedded space'       => ['feed name'],
			'semicolon'            => ['feed;name'],
			'dollar-paren'         => ['$(feed)'],
			'backtick'             => ['`feed`'],
			'pipe'                 => ['feed|name'],
			'single quote'         => ["feed'name"],
			'double quote'         => ['feed"name'],
			'embedded newline'     => ["feed\nname"],
			'embedded NUL'         => ["feed\0name"],
		];
	}

	#[DataProvider('wordRejectedProvider')]
	public function testWordFilterRejectsToDefault(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_WORD, 'PFBL-01 contract'));
	}

	// --- PFB_FILTER_IP / PFB_FILTER_IPV4 -----------------------------------------

	public function testIpFilterReturnsValidAddressUnchanged(): void
	{
		$this->assertSame('192.0.2.53', pfb_filter('192.0.2.53', PFB_FILTER_IP, 'PFBL-01 contract'));
		$this->assertSame('2001:db8::53', pfb_filter('2001:db8::53', PFB_FILTER_IP, 'PFBL-01 contract'));
		$this->assertSame('198.51.100.4', pfb_filter('198.51.100.4', PFB_FILTER_IPV4, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => value the IP filters must reject */
	public static function ipRejectedProvider(): array
	{
		return [
			'semicolon suffix'   => ['192.0.2.1;ls'],
			'trailing token'     => ['192.0.2.1 extra'],
			'backtick suffix'    => ['192.0.2.1`x`'],
			'quoted'             => ["'192.0.2.1'"],
			'cidr (not a host)'  => ['192.0.2.0/24'],
		];
	}

	#[DataProvider('ipRejectedProvider')]
	public function testIpFilterRejectsToDefault(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_IP, 'PFBL-01 contract'));
		$this->assertSame('', pfb_filter($input, PFB_FILTER_IPV4, 'PFBL-01 contract'));
	}

	// --- Rejection shape ----------------------------------------------------------

	public function testRejectionReturnsCallerSuppliedDefault(): void
	{
		// Callers that abort on rejection key off the default return: it must be the
		// caller-supplied default verbatim, for each constant used at these boundaries.
		$this->assertSame('DEF', pfb_filter('../../etc/passwd', PFB_FILTER_DOMAIN, 'ref', 'DEF'));
		$this->assertSame('DEF', pfb_filter('../feed', PFB_FILTER_WORD, 'ref', 'DEF'));
		$this->assertSame('DEF', pfb_filter('192.0.2.1;ls', PFB_FILTER_IP, 'ref', 'DEF'));
	}

	public function testRejectionDefaultIsFalsyByDefault(): void
	{
		// The in-tree skip/abort idiom is `if (empty(pfb_filter(...)))` — the no-default
		// rejection value must stay falsy or every guard at these boundaries breaks.
		$rejected = pfb_filter('feed;name', PFB_FILTER_WORD, 'PFBL-01 contract');
		$this->assertEmpty($rejected);
	}
}
