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

	// --- PFB_FILTER_DOMAIN / PFB_FILTER_TLD: Unicode/IDN acceptance (issue #1723) --
	//
	// Non-ASCII input is converted to its punycode candidate for validation
	// (dots/length/labels/charset), but on success the ORIGINAL Unicode input is
	// returned (htmlspecialchars'd) -- matching the read path
	// (pfb_text_area_decode()'s IDN branch), which also IDNA-converts at read
	// time, and preserving the pass/fail-gate contract callers rely on.

	/** @return array<string, array{0: string}> label => Unicode domain returned unchanged */
	public static function domainUnicodeAcceptedProvider(): array
	{
		return [
			'IDN domain (latin)'        => ['bücher.de'],
			'IDN domain (CJK)'          => ['日本語.example'],
			'IDN leading-dot wildcard'  => ['.bücher.de'],
			// Persian "nameh-i": ZWNJ in a valid joining context (CONTEXTJ-valid).
			'CONTEXTJ-valid ZWNJ (Persian)' => ["\u{0646}\u{0627}\u{0645}\u{0647}\u{200C}\u{0627}\u{06CC}.example"],
			'CONTEXTJ-valid ZWNJ leading-dot wildcard' => [".\u{0646}\u{0627}\u{0645}\u{0647}\u{200C}\u{0627}\u{06CC}.example"],
			// Mid-label U+200B (ZWSP) is silently MAPPED AWAY by UTS46 --
			// probed: idn_to_ascii("exam\u{200B}ple.com") === 'example.com' --
			// so the row is accepted and blocks the mapped target; an invisible
			// copy-paste artifact cannot make a row silently miss. Only a ZWSP
			// standing as an entire label is rejected (hostile provider below).
			'ZWSP inside a label (mapped away)' => ["exam\xE2\x80\x8Bple.com"],
		];
	}

	#[DataProvider('domainUnicodeAcceptedProvider')]
	public function testDomainFilterAcceptsUnicodeIdnUnchanged(string $domain): void
	{
		$this->assertSame($domain, pfb_filter($domain, PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	public function testTldFilterAcceptsUnicodeIdnUnchanged(): void
	{
		$this->assertSame('рф', pfb_filter('рф', PFB_FILTER_TLD, 'PFBL-01 contract'));
	}

	public function testTldFilterAcceptsContextjValidPersianZwnj(): void
	{
		$this->assertSame("\u{0646}\u{0627}\u{0645}\u{0647}\u{200C}\u{0627}\u{06CC}", pfb_filter("\u{0646}\u{0627}\u{0645}\u{0647}\u{200C}\u{0627}\u{06CC}", PFB_FILTER_TLD, 'PFBL-01 contract'));
	}

	// --- PFB_FILTER_{TLD,DOMAIN,HOSTNAME}: emoji label acceptance (issue #1779) --
	// Pin both the Unicode representation and its accepted A-label equivalent;
	// successful filtering preserves whichever representation the caller supplied.

	/** @return array<string, array{0: string, 1: int}> label => input and filter type */
	public static function emojiLabelAcceptedProvider(): array
	{
		return [
			'TLD Unicode emoji'          => ['😀', PFB_FILTER_TLD],
			'TLD equivalent A-label'     => ['xn--e28h', PFB_FILTER_TLD],
			'DOMAIN Unicode emoji'       => ['😀.example', PFB_FILTER_DOMAIN],
			'DOMAIN equivalent A-label'  => ['xn--e28h.example', PFB_FILTER_DOMAIN],
			'HOSTNAME Unicode emoji'     => ['😀.example', PFB_FILTER_HOSTNAME],
			'HOSTNAME equivalent A-label' => ['xn--e28h.example', PFB_FILTER_HOSTNAME],
		];
	}

	#[DataProvider('emojiLabelAcceptedProvider')]
	public function testEmojiLabelsAcceptedAndPreserved(string $input, int $filterType): void
	{
		$this->assertSame($input, pfb_filter($input, $filterType, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => CONTEXTJ-forbidden TLD */
	public static function tldContextjRejectedProvider(): array
	{
		return [
			'leading ZWJ' => ["\u{200D}рф"],
		];
	}

	#[DataProvider('tldContextjRejectedProvider')]
	public function testTldFilterRejectsContextjForbiddenJoiners(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_TLD, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => hostile/boundary value the DOMAIN filter must still reject */
	public static function domainUnicodeHostileProvider(): array
	{
		return [
			// No dot -- same rule as the ASCII case (pin: rejected before and
			// after via the "Exclude no dots" check on the converted candidate).
			'IDN no dot'                  => ['bücher'],
			// Embedded space, pure ASCII -- unaffected by the IDN branch (pin).
			'space (ascii, unaffected)'   => ['exa mple.com'],
			// Double dot inside an IDN label -- idn_to_ascii() itself refuses
			// the malformed input (probed: returns FALSE), so it never reaches
			// the label check; still rejected either way.
			'IDN double dot'              => ["b\xC3\xBCcher..de"],
			// Punycode form of a 60-char single label exceeds the 63-char
			// label cap once 'xn--...-' is added -- probed: idn_to_ascii()
			// itself returns FALSE for the whole domain (UTS46 refuses an
			// over-length label before we ever run pfb_validate_domain_labels()).
			'IDN label overlong in punycode' => [str_repeat('ü', 60) . '.de'],
			// U+200B (ZERO WIDTH SPACE) leading a label -- probed: idn_to_ascii()
			// returns FALSE (UTS46 rejects it), so the candidate stays FALSE and
			// the domain is rejected before the charset/label checks run.
			'zero-width leading label'    => ["\xE2\x80\x8B.com"],
			// A leading ZWJ is forbidden by IDNA2008 CONTEXTJ; nontransitional
			// conversion must reject it instead of deleting it.
			'leading ZWJ'                 => ["\u{200D}example.com"],
			// U+202E (RIGHT-TO-LEFT OVERRIDE) inside a label -- probed:
			// idn_to_ascii() returns FALSE (UTS46 disallows bidi control
			// characters), so the candidate stays FALSE and the domain is
			// rejected before the charset/label checks run. Contrast with the
			// free-text PFB_FILTER_HTML gate above, which accepts it.
			'bidi override inside a label' => ["exam\xE2\x80\xAEple.com"],
		];
	}

	#[DataProvider('domainUnicodeHostileProvider')]
	public function testDomainFilterRejectsUnicodeHostileInput(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	public function testDomainFilterAsciiPathUnaffectedByIdnBranch(): void
	{
		// Unchanged ASCII accept/reject pins -- must stay green throughout the
		// IDN-acceptance change (no regression on the plain-ASCII path).
		$this->assertSame('example.com', pfb_filter('example.com', PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
		$this->assertSame('', pfb_filter('exam!ple.com', PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	public function testDomainFilterRejectsIdnDoubleLeadingDot(): void
	{
		// PR #1729 review: the IDN leading-dot branch used ltrim($input, '.'),
		// which strips ALL leading dots -- "..bücher.de" was wrongly ACCEPTED
		// (ltrim leaves "bücher.de", a legal single label) while its ASCII
		// sibling "..example.com" is correctly rejected (double-dot survives
		// unmodified on the ASCII path). Strip exactly ONE leading dot so both
		// paths reject a double leading dot identically.
		$this->assertSame('DEF', pfb_filter("..b\xC3\xBCcher.de", PFB_FILTER_DOMAIN, 'ref', 'DEF'));
		// Single leading dot must still be accepted unchanged (regression guard).
		$this->assertSame(".b\xC3\xBCcher.de", pfb_filter(".b\xC3\xBCcher.de", PFB_FILTER_DOMAIN, 'PFBL-01 contract'));
	}

	// --- PFB_FILTER_HOSTNAME: Unicode/IDN acceptance (issue #1731) ----------------
	//
	// dnsbl.php's TLD Exclusion rows are hostname-typed (PFB_FILTER_HOSTNAME) but
	// used to reject any non-ASCII input outright (bare is_hostname(), no IDN
	// branch) while the adjacent TLD Blacklist (PFB_FILTER_TLD, issue #1723)
	// already accepted punycode-convertible Unicode. Same fix, same shape: a
	// non-ASCII input is converted to its punycode candidate before
	// is_hostname() runs; on success the ORIGINAL Unicode input is returned
	// (htmlspecialchars'd) -- the read path IDN-converts separately.

	/** @return array<string, array{0: string}> label => Unicode hostname returned unchanged */
	public static function hostnameUnicodeAcceptedProvider(): array
	{
		return [
			'IDN hostname (latin)'   => ['bücher.example'],
			'IDN mixed-label'        => ['münchen.test-host'],
			// Already-punycode ASCII input: no non-ASCII byte, so the IDN branch
			// never triggers -- pins the pre-existing (unchanged) accept path.
			'already-punycode ASCII' => ['xn--bcher-kva.example'],
			// Plain ASCII hostname -- before-state pin, must stay green both
			// sides of the fix (no regression on the plain-ASCII path).
			'plain ASCII hostname'   => ['example-host'],
		];
	}

	#[DataProvider('hostnameUnicodeAcceptedProvider')]
	public function testHostnameFilterAcceptsUnicodeIdnUnchanged(string $hostname): void
	{
		$this->assertSame($hostname, pfb_filter($hostname, PFB_FILTER_HOSTNAME, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => value the HOSTNAME filter must reject */
	public static function hostnameRejectedProvider(): array
	{
		return [
			// Lone combining mark -- not a legal standalone label; idn_to_ascii()
			// refuses it (UTS46), so the candidate stays FALSE.
			'lone combining mark'         => ["\xCC\x81"],
			// Punycode form of an overlong label exceeds the 63-char label cap
			// once 'xn--...-' is added -- idn_to_ascii() itself returns FALSE.
			'IDN label overlong in punycode' => [str_repeat('ü', 60)],
			// Plain ASCII reject -- before-state pin (unaffected by the IDN branch).
			'embedded space (ascii)'      => ['exam ple'],
			// Unicode-whitespace/control: still caught by pfb_filter()'s universal
			// \p{Cc}+BOM gate before the switch is even reached -- pin.
			'embedded NUL'                => ["example\0host"],
			// PR #1781 adversarial review: a delimiter character survives
			// idn_to_ascii() -- it has no STD3-ASCII-rules check, so the
			// punycode candidate can carry a literal ',', ' ' or '|' straight
			// through (probed: idn_to_ascii("a,bä.example") ===
			// "xn--a,b-sla.example", non-FALSE, non-empty). is_hostname() is
			// the SOLE remaining guard that rejects it. These pin the
			// delimiter class specifically -- not merely "invalid hostname"
			// in general -- because these three characters are the ones a
			// converted-but-accepted candidate would inject into the
			// comma-joined $details line (pfblockerng.inc:~15389) and the
			// ipcache SQLite table, shifting every downstream field. The
			// inputs are non-admin: DHCP client-hostname / a PTR record.
			'comma survives IDN conversion (log/DB delimiter safety)' => ['a,bä.example'],
			'space survives IDN conversion (log/DB delimiter safety)' => ['a bä.example'],
			'pipe survives IDN conversion (log/DB delimiter safety)'  => ['a|bä.example'],
		];
	}

	#[DataProvider('hostnameRejectedProvider')]
	public function testHostnameFilterRejectsToDefault(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_HOSTNAME, 'PFBL-01 contract'));
	}

	public function testHostnameFilterAcceptsEmptyStringUnchanged(): void
	{
		// pfb_filter() short-circuits on empty() before the switch is ever
		// reached for non-ON_OFF/NUM types -- unchanged before/after (pin).
		$this->assertSame('', pfb_filter('', PFB_FILTER_HOSTNAME, 'PFBL-01 contract', ''));
	}

	// --- PFB_FILTER_HOSTNAME: IDNA2008 CONTEXTJ joiner placements (issue #1807) --
	//
	// The entry gate deliberately admits Cf format characters (issue #1723) on the
	// premise that "domain-shaped fields still exclude them via their type-specific
	// validation below". For the HOSTNAME branch that premise does not hold:
	// idn_to_ascii() under default (transitional) UTS46 processing silently DELETES
	// ZWJ/ZWNJ instead of checking them, so a CONTEXTJ-forbidden placement IDNA2008
	// rejects is accepted and the joiner-bearing ORIGINAL input is returned and
	// persisted. The filter must run nontransitional processing with CONTEXTJ
	// checks (probed: IDNA_CHECK_CONTEXTJ alone is a no-op -- transitional mapping
	// removes the joiners before the check ever sees them) and reject on failure.

	/** @return array<string, array{0: string}> label => CONTEXTJ-forbidden joiner placement */
	public static function hostnameContextjRejectedProvider(): array
	{
		return [
			// A leading joiner has no preceding character to join -- forbidden in
			// every IDNA2008 CONTEXTJ rule; no conformant resolver produces it.
			'leading ZWJ'  => ["\u{200D}example.com"],
			'leading ZWNJ' => ["\u{200C}example.com"],
			// ZWNJ between two non-joining Latin letters: fails the CONTEXTJ
			// regional rule (needs a virama before it, or joining-type context).
			'ZWNJ between non-joining latin letters' => ["a\u{200C}b\u{00E4}.example"],
		];
	}

	#[DataProvider('hostnameContextjRejectedProvider')]
	public function testHostnameFilterRejectsContextjForbiddenJoiners(string $input): void
	{
		$this->assertSame('', pfb_filter($input, PFB_FILTER_HOSTNAME, 'PFBL-01 contract'));
	}

	/** @return array<string, array{0: string}> label => CONTEXTJ-valid or deviation input kept */
	public static function hostnameContextjAcceptedProvider(): array
	{
		return [
			// Persian "nameh-i": ZWNJ in a valid joining context (CONTEXTJ-valid) --
			// rejecting joiners wholesale would break real IDN hostnames, so this
			// pins that the CONTEXTJ check is placement-aware, not a blanket strip.
			'CONTEXTJ-valid ZWNJ (Persian)' => ["\u{0646}\u{0627}\u{0645}\u{0647}\u{200C}\u{0627}\u{06CC}.example"],
			// Eszett is a UTS46 deviation character: transitional maps it to 'ss',
			// nontransitional keeps it. ACCEPTANCE must be stable across the flag
			// change (the filter returns the ORIGINAL input either way).
			'eszett deviation character' => ["stra\u{00DF}e.example"],
		];
	}

	#[DataProvider('hostnameContextjAcceptedProvider')]
	public function testHostnameFilterKeepsContextjValidJoiners(string $hostname): void
	{
		$this->assertSame($hostname, pfb_filter($hostname, PFB_FILTER_HOSTNAME, 'PFBL-01 contract'));
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

	public function testScalarFilterAcceptsZeroWidthFormatCharacter(): void
	{
		// issue #1723: the control-character gate narrowed from \p{C} (Cc+Cf+Co+
		// Cs+Cn) to \p{Cc}+BOM only. U+200B (ZERO WIDTH SPACE) is Cf, not Cc, so
		// it no longer makes a whole free-text field a reject. Mixed-script/
		// homoglyph domains are ACCEPTED by design (admins block typosquat
		// domains in their own lists).
		//
		// PR #1729 review: in domain-shaped input, ZWSP as an entire label
		// ("​.com") IS rejected -- idn_to_ascii() itself refuses it, UTS46
		// disallows it (see 'zero-width leading label' below). In
		// domain-shaped input, CONTEXTJ-valid ZWNJ/ZWJ placements (e.g. Persian)
		// remain accepted, while IDNA2008-forbidden placements are rejected by
		// nontransitional CHECK_CONTEXTJ validation. Free-text keeps all of them.
		$this->assertSame("\xE2\x80\x8B", pfb_filter("\xE2\x80\x8B", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterAcceptsZeroWidthJoinerInsideText(): void
	{
		// U+200D (ZERO WIDTH JOINER) is Cf -- must survive embedded in text too.
		$this->assertSame("a\xE2\x80\x8Db", pfb_filter("a\xE2\x80\x8Db", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterAcceptsBidiOverrideMark(): void
	{
		// U+202E (RIGHT-TO-LEFT OVERRIDE) is Cf -- free-text fields must accept
		// Unicode; bidi-spoofing defense is out of scope for this gate.
		$this->assertSame("a\xE2\x80\xAEb", pfb_filter("a\xE2\x80\xAEb", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterStillRejectsByteOrderMark(): void
	{
		// U+FEFF (BOM) is not \p{Cc} but is explicitly named in the narrowed
		// class (\x{FEFF}) -- must keep being rejected.
		$this->assertSame('DEF', pfb_filter("a\xEF\xBB\xBFb", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	public function testScalarFilterRejectsInvalidUtf8FailClosed(): void
	{
		// With /u, preg_match() returns FALSE (not 0) on a malformed-UTF-8 subject.
		// pfb_filter() is a PFBL-01 input-sanitisation gate, so a subject the regex
		// cannot even parse must be rejected (fail-closed), never silently accepted.
		$this->assertSame('DEF', pfb_filter("\xC3\x28", PFB_FILTER_HTML, 'ref', 'DEF'));
	}

	// --- PFB_FILTER_ON_OFF / PFB_FILTER_NUM: NULL input (issue #1768) -------------
	//
	// Both constants are deliberately exempt from the early
	// empty($input)||is_null($input) return (NULL=='' / a legitimate stored
	// default must still validate), so a caller passing NULL (e.g. an absent
	// POST/config field) previously flowed unguarded into preg_match()/
	// htmlspecialchars() -- PHP 8.1+ deprecates passing NULL to a non-nullable
	// string parameter. pfb_filter() now coerces a non-array $input to a
	// string immediately after that early-return guard, preserving the
	// NULL==''/NUM-no-match-default return shape byte-identically.

	public function testOnOffFilterAcceptsNullWithNoDiagnostics(): void
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		}, E_WARNING | E_DEPRECATED);
		try {
			$result = pfb_filter(NULL, PFB_FILTER_ON_OFF, 'PFBL-01 contract');
		} finally {
			restore_error_handler();
		}
		$this->assertSame(
			[],
			$diagnostics,
			"pfb_filter(NULL, PFB_FILTER_ON_OFF) must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		// NULL == '' -- same accepted-empty shape as an explicit '' input.
		$this->assertSame('', $result);
	}

	public function testNumFilterAcceptsNullWithNoDiagnostics(): void
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		}, E_WARNING | E_DEPRECATED);
		try {
			$result = pfb_filter(NULL, PFB_FILTER_NUM, 'PFBL-01 contract');
		} finally {
			restore_error_handler();
		}
		$this->assertSame(
			[],
			$diagnostics,
			"pfb_filter(NULL, PFB_FILTER_NUM) must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		// No digits matched -> caller-supplied default ('').
		$this->assertSame('', $result);
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
