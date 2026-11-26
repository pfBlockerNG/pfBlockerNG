<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272: with Download Schemes unchecked (strict), a DNSBL host token is kept only as
 * `(<scheme>://)?<domain>/?`. A path, query, fragment, ';' parameters, a port or userinfo is a
 * skipped, logged and counted line, with or without a scheme. Lenient mode keeps cutting the
 * host out, and IP literals and CIDRs keep their own rules in both modes.
 */
#[CoversFunction('pfb_dnsbl_extract_host')]
final class DnsblStrictHostGrammarTest extends TestCase
{
	private string $parseErr = '';

	protected function setUp(): void
	{
		$this->parseErr = tempnam(sys_get_temp_dir(), 'pfbstrictgrammar');
		@unlink($this->parseErr);
	}

	protected function tearDown(): void
	{
		if ($this->parseErr !== '' && is_file($this->parseErr)) {
			unlink($this->parseErr);
		}
	}

	private function extract(string $line, bool $strict, int &$skipped): string|false
	{
		$skipped = 0;
		return pfb_dnsbl_extract_host($line, $strict, 'hdr', $line, 7, $this->parseErr, $skipped);
	}

	/** @return array<string, array{string, string}> line => the host lenient mode keeps */
	public static function strictRejectedProvider(): array
	{
		return [
			'EasyPrivacy path rule'      => ['.imgur.com/lumbar.gif', '.imgur.com'],
			'scheme-less path'           => ['d.com/a/b', 'd.com'],
			'scheme-less double slash'   => ['d.com//', 'd.com'],
			'scheme-less query'          => ['d.com?q=1', 'd.com'],
			'scheme-less fragment'       => ['d.com#frag', 'd.com'],
			'scheme-less parameters'     => ['d.com;jsessionid=x', 'd.com'],
			'scheme-less port'           => ['d.com:8080', 'd.com'],
			'scheme port'                => ['http://d.com:8080', 'd.com'],
			'scheme port and root path'  => ['http://d.com:8080/', 'd.com'],
			'scheme userinfo'            => ['http://user@d.com', 'd.com'],
			'scheme userinfo root path'  => ['http://user:pw@d.com/', 'd.com'],
			'nothing before the path'    => ['/24', ''],
			'nothing before the query'   => ['?foo', ''],
		];
	}

	#[DataProvider('strictRejectedProvider')]
	public function testStrictModeSkipsLogsAndCountsAnythingAfterTheDomain(string $line, string $lenientHost): void
	{
		$skipped = 0;
		$this->assertFalse($this->extract($line, TRUE, $skipped), "strict must skip [{$line}], not keep part of it");
		$this->assertSame(1, $skipped, "strict must count [{$line}] for the per-feed skip warning");
		$this->assertStringContainsString($line, (string) file_get_contents($this->parseErr), 'the skipped line must be in the parse-error log');
	}

	#[DataProvider('strictRejectedProvider')]
	public function testLenientModeStillKeepsTheHost(string $line, string $lenientHost): void
	{
		$skipped = 0;
		$this->assertSame($lenientHost, $this->extract($line, FALSE, $skipped), "lenient result for [{$line}]");
		$this->assertSame(0, $skipped);
	}

	/** @return array<string, array{string, string}> line => the host strict mode keeps */
	public static function strictAcceptedProvider(): array
	{
		return [
			'bare domain'                => ['my-domain.com', 'my-domain.com'],
			'domain with root path'      => ['my-domain.com/', 'my-domain.com'],
			'scheme domain'              => ['http://d.com', 'd.com'],
			'scheme domain root path'    => ['https://d.com/', 'd.com'],
			'IPv4 authority with a path' => ['http://1.2.3.4:80/x', '1.2.3.4'],
			'IPv4 with a port'           => ['1.2.3.4:80', '1.2.3.4'],
			'bracketed IPv6 with a port' => ['[2604:2dc0::]:53', '2604:2dc0::'],
			'CIDR near-miss with a tail' => ['192.168.1.0/24#x', '192.168.1.0'],
			'CIDR'                       => ['192.168.1.0/24', '192.168.1.0/24'],
		];
	}

	#[DataProvider('strictAcceptedProvider')]
	public function testStrictModeKeepsADomainWithNothingAfterItAndKeepsTheIpRules(string $line, string $host): void
	{
		$skipped = 0;
		$this->assertSame($host, $this->extract($line, TRUE, $skipped), "strict result for [{$line}]");
		$this->assertSame(0, $skipped);
		$this->assertFileDoesNotExist($this->parseErr, "[{$line}] must not be logged as a parse error");
	}
}
