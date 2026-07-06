<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_redact_url() — issue #890: a download URL logged verbatim can carry a
 * credential (query-string token, or 'user:pass@' userinfo), and pfBlockerNG's
 * logs ship inside pfSense support bundles. This pins that neither ever survives
 * into the string handed to a logger, while the scheme/host/port/path a
 * maintainer needs to diagnose a failed download are kept intact.
 */
#[CoversFunction('pfb_redact_url')]
final class RedactUrlTest extends TestCase
{
	public function testQueryStringIsRedacted(): void
	{
		$redacted = pfb_redact_url('https://h/p?token=SECRET');
		$this->assertStringNotContainsString('SECRET', $redacted);
		$this->assertSame('https://h/p?[redacted]', $redacted);
	}

	public function testUserinfoIsRedacted(): void
	{
		$redacted = pfb_redact_url('https://user:pass@h/p');
		$this->assertStringNotContainsString('pass', $redacted);
		$this->assertSame('https://h/p', $redacted);
	}

	public function testUserinfoAndQueryStringAreBothRedacted(): void
	{
		$redacted = pfb_redact_url('https://user:pass@h/p?token=SECRET');
		$this->assertStringNotContainsString('pass', $redacted);
		$this->assertStringNotContainsString('SECRET', $redacted);
		$this->assertSame('https://h/p?[redacted]', $redacted);
	}

	public function testMalformedUrlNeverLeaksTheSecret(): void
	{
		// parse_url() can't make sense of this as a URL (no host) -- the regex
		// fallback engages. Over-redacting is acceptable; leaking is not.
		$redacted = pfb_redact_url('not a url ?token=SECRET');
		$this->assertStringNotContainsString('SECRET', $redacted);
	}

	public function testPlainUrlWithNoQueryOrUserinfoRoundTripsUnchanged(): void
	{
		$this->assertSame('https://h/p', pfb_redact_url('https://h/p'));
	}

	#[DataProvider('rsyncShorthandProvider')]
	public function testBareRsyncShorthandUserinfoIsRedacted(string $url, string $expected): void
	{
		// pfBlockerNG's own '[user@]host::module' rsync source form has no scheme
		// and no '//', so parse_url() reports no host for it either -- same
		// fallback path, same guarantee: no userinfo survives.
		$this->assertSame($expected, pfb_redact_url($url));
	}

	public static function rsyncShorthandProvider(): array
	{
		return [
			'user@ only'       => ['user@host::module', 'host::module'],
			'user:pass@ form'  => ['user:pass@host::module/path?x=1', 'host::module/path?[redacted]'],
			'no userinfo'      => ['host::module', 'host::module'],
		];
	}
}
