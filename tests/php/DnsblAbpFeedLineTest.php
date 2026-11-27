<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272 (owner decisions, second round): in an Adblock feed, a line that is not an Adblock
 * rule is kept only as
 *  - a hostname, optionally with ':<port>' and/or a trailing '/' (Allow Ports-compatible);
 *  - a hosts line ('<ip> <hostname> [aliases...] [# comment]');
 *  - an AdGuard DNS hostname mask (https://adguard-dns.io/kb/general/dns-filtering-syntax/).
 * Every other line is dropped. A kept hostname must be a real one: every label letters, digits and
 * inner hyphens, and an ICANN TLD from the shipped dnsbl_psl. That keeps ABP URL fragments such as
 * '_chartbeat.js', '-murmann.ru' (RU AdBlock) and '_werbung.pl' (EasyList Germany) out.
 *
 * pfBlockerNG blocks a host, or a host and its subdomains, so a mask maps to the closest rule that
 * never blocks more than AdGuard would:
 *  - '|host^', '|host|' and '://host^' anchor both ends of the hostname: the host alone, a domain row;
 *  - 'host^' and 'host|' anchor only the end, which AdGuard matches on any hostname ending in 'host':
 *    '||host^' (the host and its subdomains) is the label-boundary subset;
 *  - '.host^' (subdomains only) and '*' masks have no pfBlockerNG form and are dropped;
 *  - '$important' rides along on '||host^'; an exact mask keeps no modifier ('|host^$important' is the
 *    host alone). '$badfilter' is dropped: as '||host^$badfilter' it would prune every feed's '||host^'
 *    in reconcile(), while AdGuard's 'host^$badfilter' disables only the 'host^' rule. Any other
 *    modifier scopes the rule ($client, $ctag, $dnstype, $denyallow), rewrites instead of blocking
 *    ($dnsrewrite) or is unknown, which AdGuard says makes it ignore the whole rule: dropped too.
 */
final class DnsblAbpFeedLineTest extends TestCase
{
	/** @return array<string, array{string, ?array{0: string, 1: string}}> line => [row kind, payload] or NULL */
	public static function lineProvider(): array
	{
		return [
			// hostnames
			'bare domain'                   => ['kerfskelts.cfd', ['d', 'kerfskelts.cfd']],
			'bare subdomain'                => ['adsy.mail.bg', ['d', 'adsy.mail.bg']],
			'upper case'                    => ['Ads.Example.COM', ['d', 'ads.example.com']],
			'inner hyphen'                  => ['dom-2-onlain.ru', ['d', 'dom-2-onlain.ru']],
			'digits'                        => ['b2.grabo.bg', ['d', 'b2.grabo.bg']],
			'IDN'                           => ['bücher.de', ['d', 'xn--bcher-kva.de']],
			'punycode'                      => ['xn--bcher-kva.de', ['d', 'xn--bcher-kva.de']],
			'trailing slash'                => ['example.com/', ['d', 'example.com']],
			'port'                          => ['example.com:8080', ['d', 'example.com']],
			'port and slash'                => ['example.com:443/', ['d', 'example.com']],
			'trailing comment'              => ['example.com # ad server', ['d', 'example.com']],
			'port zero'                     => ['example.com:0', NULL],
			'port too large'                => ['example.com:65536', NULL],
			'empty port'                    => ['example.com:', NULL],
			'double slash'                  => ['example.com//', NULL],
			'path'                          => ['example.com/ads', NULL],
			'glued comment'                 => ['example.com#ad', NULL],
			'trailing dot'                  => ['example.com.', ['d', 'example.com']],
			'longest hostname'              => [str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 57) . '.com',
			                                    ['d', str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 57) . '.com']],
			'hostname too long'             => [str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 58) . '.com', NULL],
			'TLD only under a wildcard rule' => ['ads.com.np', ['d', 'ads.com.np']],
			'NUL byte'                      => ["1.2.3.4\0 ads.example.com", NULL],
			// hosts lines
			'hosts, 0.0.0.0'                => ['0.0.0.0 ads.example.com', ['d', 'ads.example.com']],
			'hosts, 127.0.0.1'              => ['127.0.0.1 tracker.example.org', ['d', 'tracker.example.org']],
			'hosts, tab'                    => ["0.0.0.0\ttracker.example.org", ['d', 'tracker.example.org']],
			'hosts, IPv6 sink'              => [':: tracker.example.org', ['d', 'tracker.example.org']],
			'hosts, aliases'                => ['0.0.0.0 a.example.com b.example.com', ['d', 'a.example.com']],
			'hosts, aliases and comment'    => ['0.0.0.0 a.example.com b.example.com # tracking', ['d', 'a.example.com']],
			'hosts, bad alias'              => ['0.0.0.0 a.example.com _b.example.com', NULL],
			'hosts, IP target'              => ['0.0.0.0 1.2.3.4', NULL],
			'hosts, no IP'                  => ['ads tracker.example.org', NULL],
			'hosts, bad label'              => ['0.0.0.0 _ads.example.com', NULL],
			'hosts, port'                   => ['0.0.0.0 ads.example.com:80', NULL],
			// AdGuard DNS hostname masks
			'mask, both anchors'            => ['|ads.example.com^', ['d', 'ads.example.com']],
			'mask, both pipes'              => ['|ads.example.com|', ['d', 'ads.example.com']],
			'mask, scheme anchor'           => ['://ads.example.com^', ['d', 'ads.example.com']],
			'mask, end anchor'              => ['ads.example.com^', ['a', '||ads.example.com^']],
			'mask, end pipe'                => ['ads.example.com|', ['a', '||ads.example.com^']],
			'mask, upper case'              => ['Ads.Example.COM^', ['a', '||ads.example.com^']],
			'mask, important'               => ['ads.example.com^$important', ['a', '||ads.example.com^$important']],
			'mask, both anchors, important' => ['|ads.example.com^$important', ['d', 'ads.example.com']],
			'mask, start anchor only'       => ['|ads.example', NULL],
			'mask, subdomains only'         => ['.example.com^', NULL],
			'mask, wildcard label'          => ['*.example.com^', NULL],
			'mask, inner wildcard'          => ['ad*.example.com^', NULL],
			'mask, badfilter'               => ['ads.example.com^$badfilter', NULL],
			'mask, TLD under wildcard rule' => ['tracker.gov.mm^', ['a', '||tracker.gov.mm^']],
			'mask, client'                  => ['ads.example.com^$client=192.168.1.5', NULL],
			'mask, ctag'                    => ['ads.example.com^$ctag=device_tv', NULL],
			'mask, dnstype'                 => ['ads.example.com^$dnstype=AAAA', NULL],
			'mask, denyallow'               => ['example.com^$denyallow=cdn.example.com', NULL],
			'mask, dnsrewrite'              => ['ads.example.com^$dnsrewrite=1.2.3.4', NULL],
			'mask, important and dnstype'   => ['ads.example.com^$important,dnstype=A', NULL],
			'mask, anchored badfilter'      => ['|ads.example.com^$badfilter', NULL],
			'mask, URL modifier'            => ['example.com^$third-party', NULL],
			'mask, bad label'               => ['_ads.example.com^', NULL],
			'mask, unknown TLD'             => ['ads.example.notatld^', NULL],
			// everything else
			'filename fragment'             => ['_chartbeat.js', NULL],
			'image fragment'                => ['_120.240.gif', NULL],
			'Java-style class name'         => ['com.nxtras.banner.ImageRotator', NULL],
			'path rule'                     => ['.imgur.com/lumbar.gif', NULL],
			'leading dot'                   => ['.imgur.com', NULL],
			'options'                       => ['example.com$third-party', NULL],
			'HTML filter'                   => ['example.com$$script[data-src]', NULL],
			'unknown TLD'                   => ['ads.example.notatld', NULL],
			'single label'                  => ['localhost', NULL],
			'bare IP'                       => ['1.2.3.4', NULL],
			'leading hyphen'                => ['-murmann.ru', NULL],
			'leading hyphen, longer'        => ['-dom-2-onlain.ru', NULL],
			'leading underscore'            => ['_2krota.ru', NULL],
			'underscore label'              => ['_camelot.multilocal.ru', NULL],
			'underscore, .org'              => ['_spy2wc.org', NULL],
			'underscore, .pl'               => ['_werbung.pl', NULL],
			'trailing hyphen label'         => ['ads-.example.com', NULL],
			'empty'                         => ['', NULL],
		];
	}

	/** @param ?array{0: string, 1: string} $row */
	#[DataProvider('lineProvider')]
	public function testAnAdblockFeedKeepsOnlyHostnamesHostsLinesAndHostnameMasks(string $line, ?array $row): void
	{
		$kept = pfb_dnsbl_abp_feed_line($line);
		$this->assertSame($row, $kept === NULL ? NULL : [$kept[0]->value, $kept[1]], "[{$line}]");
	}
}
