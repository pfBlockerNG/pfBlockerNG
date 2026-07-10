<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter() — the input sanitiser used throughout the UI/config paths.
 * Only the pure validation types are exercised here; URL/MIME types need
 * host resolution or /usr/bin/file and belong to the live-VM smoke (ADR-04).
 */
#[CoversFunction('pfb_filter')]
final class PfbFilterTest extends TestCase
{
	public static function domainProvider(): array
	{
		return [
			'plain domain'        => ['example.com', 'example.com'],
			'subdomain'           => ['a.b.example.com', 'a.b.example.com'],
			'mixed case kept'     => ['Example.Com', 'Example.Com'],
			'underscore/dash ok'  => ['my_host-1.example.com', 'my_host-1.example.com'],
			'no dot rejected'     => ['localhost', ''],
			'double dot rejected' => ['bad..com', ''],
			'bad char rejected'   => ['ex+ample.com', ''],
			'space rejected'      => ['ex ample.com', ''],
		];
	}

	#[DataProvider('domainProvider')]
	public function testDomainFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_DOMAIN));
	}

	public function testDomainLabelTooLongRejected(): void
	{
		$label = str_repeat('a', 64);
		$this->assertSame('', pfb_filter("{$label}.com", PFB_FILTER_DOMAIN));
	}

	public static function ipProvider(): array
	{
		return [
			'ipv4'            => ['192.0.2.10', '192.0.2.10'],
			'ipv6'            => ['2001:db8::1', '2001:db8::1'],
			'ipv6 loopback'   => ['::1', '::1'],
			'not an ip'       => ['999.1.1.1', ''],
			'word'            => ['nope', ''],
		];
	}

	#[DataProvider('ipProvider')]
	public function testIpFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_IP));
	}

	public function testIpv4FilterRejectsV6(): void
	{
		$this->assertSame('192.0.2.1', pfb_filter('192.0.2.1', PFB_FILTER_IPV4));
		$this->assertSame('', pfb_filter('2001:db8::1', PFB_FILTER_IPV4));
	}

	public static function wordProvider(): array
	{
		return [
			'alnum + underscore' => ['abc_123', 'abc_123'],
			'space rejected'     => ['a b', ''],
			'dot rejected'       => ['a.b', ''],
			'dash rejected'      => ['a-b', ''],
		];
	}

	#[DataProvider('wordProvider')]
	public function testWordFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_WORD));
	}

	public static function hexColorProvider(): array
	{
		return [
			'six hex'      => ['#a1b2c3', '#a1b2c3'],
			'three hex'    => ['#abc', '#abc'],
			'uppercase'    => ['#ABCDEF', '#ABCDEF'],
			'literal none' => ['none', 'none'],
			'missing hash' => ['a1b2c3', ''],
			'bad hex'      => ['#xyzxyz', ''],
			'wrong length' => ['#a1b2', ''],
		];
	}

	#[DataProvider('hexColorProvider')]
	public function testHexColorFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_HEX_COLOR));
	}

	public static function onOffProvider(): array
	{
		return [
			'on'              => ['on', 'on'],
			'empty'           => ['', ''],
			'off -> default'  => ['off', ''],
			'junk -> default' => ['enabled', ''],
		];
	}

	#[DataProvider('onOffProvider')]
	public function testOnOffFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_ON_OFF));
	}

	public static function numProvider(): array
	{
		return [
			'digits'              => ['12345', '12345'],
			'alpha -> default'    => ['12a', ''],
			'negative -> default' => ['-5', ''],
			// '0' is a legitimately validated digit string (matches
			// /^[0-9]+$/) and must round-trip unchanged, not collapse to
			// the default -- a hook_timeout of '0' (pfblockerng_hooks.php)
			// must not be rejected as invalid just because PHP's loose
			// '0' == FALSE coercion used to treat it as a filter failure.
			'zero validates'      => ['0', '0'],
		];
	}

	#[DataProvider('numProvider')]
	public function testNumFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_NUM));
	}

	/**
	 * issue #1070: a crafted array POST ('field[]=x') routed through pfb_filter
	 * must return the default, not TypeError in the scalar string ops
	 * (htmlspecialchars/preg_match) -- every scalar-expecting filter type.
	 *
	 * @return array<string, array{int, mixed}>
	 */
	public static function scalarTypeProvider(): array
	{
		return [
			'ON_OFF' => [PFB_FILTER_ON_OFF, ''],
			'WORD'   => [PFB_FILTER_WORD, ''],
			'NUM'    => [PFB_FILTER_NUM, ''],
			'DOMAIN' => [PFB_FILTER_DOMAIN, ''],
			// Non-empty default proves the rejected array returns the CALLER'S default,
			// not a hardcoded '' -- a bare '' row alone cannot distinguish the two.
			'WORD non-empty default' => [PFB_FILTER_WORD, 'PFB_ARRAY_REJECT_SENTINEL'],
		];
	}

	#[DataProvider('scalarTypeProvider')]
	public function testArrayInputReturnsDefaultInsteadOfThrowing(int $type, string $default): void
	{
		$this->assertSame($default, pfb_filter(['x'], $type, 'test', $default));
	}

	public static function tokenProvider(): array
	{
		return [
			// A realistic base64url/JWT-shaped credential (dots, dash, tilde, plus, slash,
			// equals -- the exact punctuation PFB_FILTER_WORD would reject).
			'realistic token'  => ['cf-abc123._~+/=-XYZ', 'cf-abc123._~+/=-XYZ'],
			'too short'        => ['short12', ''],
			'space rejected'   => ['has a space', ''],
			'colon rejected'   => ['bad:token', ''],
			'quote rejected'   => ["bad'token", ''],
			'too long'         => [str_repeat('a', 513), ''],
			'exactly max ok'   => [str_repeat('a', 512), str_repeat('a', 512)],
			'exactly min ok'   => ['a1234567', 'a1234567'],
			// #892 review: PCRE's '$' matches before a trailing '\n' by default, so a
			// token smuggling a trailing newline would otherwise pass the character-class
			// check unmodified -- the 'D' flag (or '\z') pins '$' to the true end of the
			// string, matching the same discipline PFB_FILTER_URL etc. don't need here
			// (a token is the one filter mode taking a raw untrusted secret).
			'trailing newline rejected' => ["a1234567\n", ''],
		];
	}

	#[DataProvider('tokenProvider')]
	public function testTokenFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_TOKEN));
	}

	/**
	 * ADR-59 P5 (security): a token rejected by PFB_FILTER_TOKEN must NEVER be logged --
	 * not even at debug level -- when the caller identifies itself via the 'top1m_token'
	 * reference. This is the load-bearing proof for the pfb_filter() exceptions list
	 * (pfblockerng.inc ~1655) this phase added 'top1m_token' to, alongside the
	 * pre-existing 'DNSBL_Download' exception. A DIFFERENT reference (the normal case
	 * for every other pfb_filter() caller) still logs the reject -- proving the
	 * suppression is genuinely conditional on the reference, not a side effect of
	 * PFB_FILTER_TOKEN itself.
	 */
	public function testTokenFilterRejectionNeverLogsForTop1mTokenReferenceButOtherReferencesStillDo(): void
	{
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_filter_token_errlog_');
		$this->assertNotFalse($errlog, 'could not create temp errlog');
		$saved = array_key_exists('errlog', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['errlog'] : false;
		$GLOBALS['pfb']['errlog'] = $errlog;

		try {
			$secret = 'REJECTED-SECRET-should-never-be-logged!!!';

			// Given/When: reference 'top1m_token' -- the ADR-59 P5 exception.
			$this->assertSame('', pfb_filter($secret, PFB_FILTER_TOKEN, 'top1m_token'));
			// Then: the rejected value never reaches the error log.
			$this->assertStringNotContainsString(
				$secret,
				(string) file_get_contents($errlog),
				'a token rejected via the top1m_token reference must never be logged'
			);

			// Given/When: a DIFFERENT (ordinary) reference for the same rejected input.
			$this->assertSame('', pfb_filter($secret, PFB_FILTER_TOKEN, 'some_other_caller'));
			// Then: the suppression is genuinely reference-scoped -- an ordinary caller
			// still gets its reject logged (the pre-existing, unchanged behaviour).
			$this->assertStringContainsString(
				$secret,
				(string) file_get_contents($errlog),
				'a non-top1m_token reference must still log its rejected input as before'
			);
		} finally {
			if ($saved === false) {
				unset($GLOBALS['pfb']['errlog']);
			} else {
				$GLOBALS['pfb']['errlog'] = $saved;
			}
			unlink($errlog);
		}
	}

	/**
	 * issue #924 (security): a MaxMind license key rejected by PFB_FILTER_WORD must NEVER be
	 * logged -- the same reference-scoped suppression proven above for top1m_token, extended
	 * to the 'maxmind_key' reference (added to the pfb_filter() exceptions list at
	 * pfblockerng.inc ~1658). Every maxmind_key call site passes this reference -- the UI
	 * validate/store (pfblockerng_ip.php) AND the pfb_global() consumer read
	 * (pfblockerng.inc ~2361) -- so a rejected stored key never reaches the log on any path.
	 * A DIFFERENT reference still logs the reject, proving the suppression is reference-scoped
	 * and not a side effect of PFB_FILTER_WORD itself.
	 */
	public function testWordFilterRejectionNeverLogsForMaxmindKeyReferenceButOtherReferencesStillDo(): void
	{
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_filter_maxmind_errlog_');
		$this->assertNotFalse($errlog, 'could not create temp errlog');
		$saved = array_key_exists('errlog', $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb']['errlog'] : false;
		$GLOBALS['pfb']['errlog'] = $errlog;

		try {
			// A key with non-word chars ('-'/'!') that PFB_FILTER_WORD rejects.
			$secret = 'REJECTED-MAXMIND-KEY-should-never-be-logged!!!';

			// Given/When: reference 'maxmind_key' -- the issue #924 exception.
			$this->assertSame('', pfb_filter($secret, PFB_FILTER_WORD, 'maxmind_key'));
			// Then: the rejected key never reaches the error log.
			$this->assertStringNotContainsString(
				$secret,
				(string) file_get_contents($errlog),
				'a key rejected via the maxmind_key reference must never be logged'
			);

			// Given/When: a DIFFERENT (ordinary) reference for the same rejected input.
			$this->assertSame('', pfb_filter($secret, PFB_FILTER_WORD, 'some_other_caller'));
			// Then: the suppression is reference-scoped -- an ordinary caller still logs.
			$this->assertStringContainsString(
				$secret,
				(string) file_get_contents($errlog),
				'a non-maxmind_key reference must still log its rejected input as before'
			);
		} finally {
			if ($saved === false) {
				unset($GLOBALS['pfb']['errlog']);
			} else {
				$GLOBALS['pfb']['errlog'] = $saved;
			}
			unlink($errlog);
		}
	}

	public function testControlCharactersRejected(): void
	{
		// A control char anywhere makes the whole input fail, returning default.
		$this->assertSame('', pfb_filter("abc\x01def", PFB_FILTER_WORD));
	}

	public function testCustomDefaultReturnedOnFailure(): void
	{
		$this->assertSame('FALLBACK', pfb_filter('not a domain', PFB_FILTER_DOMAIN, 'ref', 'FALLBACK'));
	}

	public function testEmptyInputReturnsDefault(): void
	{
		$this->assertSame('DEF', pfb_filter('', PFB_FILTER_DOMAIN, 'ref', 'DEF'));
	}
}
