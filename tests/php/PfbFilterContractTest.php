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
			// 254 chars is DELIBERATELY accepted (issue #724): the `< 255` bound
			// admits the longest legal name in trailing-root-dot presentation
			// (253 chars + '.'), and a 254-char name without the dot exceeds the
			// DNS wire cap so it can never be queried — inert either way. The
			// length check is a sanity cap; the charset regex and '..' exclusion
			// are the PFBL-01 security layer. Do not tighten to `<= 253`.
			'254-char max FQDN + root dot' => [$longest . '.'],
			'254-char total (lenient cap)' => [str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', 62)],
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

	// --- Unicode-aware control-character gate (issue #714 audit item c3) ----------
	//
	// pfb_filter()'s control-character check used bare `preg_match("/[\p{C}]+/", $x)`.
	// Without the `/u` modifier, \p{C} classifies each raw BYTE as a Latin-1 codepoint:
	// a valid multibyte UTF-8 character whose continuation byte falls in 0x80-0x9F was
	// falsely flagged as a control character, while a genuinely invalid-UTF-8 subject
	// was silently accepted. With `/u`, preg_match() returns FALSE (not 0) on invalid
	// UTF-8, so the fixed call sites reject on `!== 0` to fail closed rather than open.

	/** @return array<string, array{0: string}> label => valid multibyte UTF-8 the gate must accept */
	public static function multibyteAcceptedProvider(): array
	{
		return [
			// Byte-mode \p{C} misreads a continuation byte (0x82/0x97) as a Latin-1
			// C1 control codepoint (0x80-0x9F) -- falsely rejected pre-fix; a real
			// Unicode-aware match correctly sees a printable character.
			'euro sign'     => ["\xE2\x82\xAC"],              // €
			'kanji nihon'   => ["\xE6\x97\xA5\xE6\x9C\xAC"],  // 日本
			// Contrast case: byte-mode happens to accept this one already (its
			// continuation byte 0xA9 sits outside 0x80-0x9F) -- pins the
			// already-working accept side, proving the fix doesn't just get lucky.
			'e-acute'       => ["\xC3\xA9"],                  // é
		];
	}

	#[DataProvider('multibyteAcceptedProvider')]
	public function testScalarFilterAcceptsValidMultibyteUtf8(string $input): void
	{
		// Given valid multibyte UTF-8 text, When it passes the control-char gate,
		// Then PFB_FILTER_HTML returns it unchanged (htmlspecialchars() is a no-op
		// on these codepoints -- none are HTML-special).
		$this->assertSame($input, pfb_filter($input, PFB_FILTER_HTML, 'PFBL-01 contract', 'DEF'));
	}

	public function testScalarFilterStillRejectsRealControlCharacters(): void
	{
		// A genuine control character must keep being rejected with /u applied --
		// green both before and after the fix (the gate must not loosen).
		$this->assertSame('DEF', pfb_filter("\x07", PFB_FILTER_HTML, 'ref', 'DEF'));
		$this->assertSame('DEF', pfb_filter("abc\x07def", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterRejectsZeroWidthSpaceAsFormatControl(): void
	{
		// U+200B (ZERO WIDTH SPACE, Unicode category Cf) is a genuine \p{C} member --
		// a homoglyph/zero-width hardening pin, distinct from the false-positive fix.
		$this->assertSame('DEF', pfb_filter("\xE2\x80\x8B", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterRejectsInvalidUtf8FailClosed(): void
	{
		// With /u, preg_match() returns FALSE (not 0) on a malformed-UTF-8 subject.
		// pfb_filter() is a PFBL-01 input-sanitisation gate, so a subject the regex
		// cannot even parse must be rejected (fail-closed), never silently accepted.
		$this->assertSame('DEF', pfb_filter("\xC3\x28", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	// --- Array-input branch: the same gate, applied per element --------------------

	/**
	 * Runs $exercise() with $pfb['errlog'] pointed at a fresh temp file and returns
	 * its contents. PFB_FILTER_FILE_MIME_COMPARE forces $return_type to FALSE (see
	 * pfb_filter()'s $return_type override for that constant), and its file_exists()
	 * miss also returns FALSE -- so the return value alone can't tell an early
	 * control-char reject apart from one that reached the MIME switch. The log line
	 * ("Control characters found" vs "Invalid Mime-type (file missing)") can.
	 */
	private function errLogAfter(callable $exercise): string
	{
		$had  = array_key_exists('errlog', $GLOBALS['pfb'] ?? []);
		$prev = $GLOBALS['pfb']['errlog'] ?? null;
		$path = sys_get_temp_dir() . '/pfb_filter_contract_errlog_' . uniqid('', true);
		$GLOBALS['pfb']['errlog'] = $path;
		try {
			$exercise();
			return file_exists($path) ? (string) file_get_contents($path) : '';
		} finally {
			if ($had) {
				$GLOBALS['pfb']['errlog'] = $prev;
			} else {
				unset($GLOBALS['pfb']['errlog']);
			}
			@unlink($path);
		}
	}

	public function testArrayInputAcceptsValidMultibyteUtf8Element(): void
	{
		// Given an array element containing valid multibyte UTF-8 (the euro sign),
		// When it passes the same per-element control-char loop as the scalar branch,
		// Then it must NOT be rejected there -- the run reaches the MIME switch,
		// whose own file_exists() miss on the (nonexistent) path logs a DIFFERENT
		// message. Pre-fix, byte-mode \p{C} falsely matches and only the
		// "Control characters found" line appears.
		$log = $this->errLogAfter(function (): void {
			pfb_filter(["/nonexistent/\xE2\x82\xAC-file", 'text/plain'], PFB_FILTER_FILE_MIME_COMPARE, 'PFBL-01 contract array');
		});
		$this->assertStringNotContainsString(
			'Control characters found',
			$log,
			"expected no control-char rejection for a valid UTF-8 array element, but errlog was:\n{$log}"
		);
		$this->assertStringContainsString(
			'Invalid Mime-type (file missing)',
			$log,
			"expected the run to reach the MIME file_exists() check, but errlog was:\n{$log}"
		);
	}

	public function testArrayInputRejectsControlCharacterElement(): void
	{
		// A real control character in an array element must still be rejected at
		// the per-element loop -- green before and after (no loosening).
		$log = $this->errLogAfter(function (): void {
			pfb_filter(["/nonexistent/abc\x07def-file", 'text/plain'], PFB_FILTER_FILE_MIME_COMPARE, 'PFBL-01 contract array');
		});
		$this->assertStringContainsString(
			'Control characters found',
			$log,
			"expected a control-char rejection for an array element containing \\x07, but errlog was:\n{$log}"
		);
	}

	public function testArrayInputRejectsInvalidUtf8ElementFailClosed(): void
	{
		// An invalid-UTF-8 array element must be rejected fail-closed post-fix
		// (preg_match() returns FALSE on it, treated as a match by `!== 0`) -- the
		// array-branch counterpart of the scalar fail-closed case above.
		$log = $this->errLogAfter(function (): void {
			pfb_filter(["/nonexistent/\xC3\x28-file", 'text/plain'], PFB_FILTER_FILE_MIME_COMPARE, 'PFBL-01 contract array');
		});
		$this->assertStringContainsString(
			'Control characters found',
			$log,
			"expected a control-char rejection for an array element with invalid UTF-8, but errlog was:\n{$log}"
		);
	}
}
