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
			// Quirk worth pinning: '0' validates, but the final
			// `return $result == FALSE ? $default : $result` treats the string
			// '0' as loosely == FALSE, so NUM can never return '0' -> default.
			'zero is loose-false' => ['0', ''],
		];
	}

	#[DataProvider('numProvider')]
	public function testNumFilter(string $input, string $expected): void
	{
		$this->assertSame($expected, pfb_filter($input, PFB_FILTER_NUM));
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
