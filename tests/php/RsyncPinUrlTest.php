<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_rsync_pin_url() — rebuild an rsync feed source so it connects to the vetted
 * IP (the guard's pinned address) instead of the hostname, keeping the module/path
 * intact, for both rsync source forms. An unparseable form returns '' so the caller
 * fails closed (does not connect).
 */
#[CoversFunction('pfb_rsync_pin_url')]
final class RsyncPinUrlTest extends TestCase
{
	public static function pinProvider(): array
	{
		return [
			// host::module form -> IP substituted for the host, module intact.
			'module form'            => ['rsync.example::feed/list.txt', '203.0.113.5', '203.0.113.5::feed/list.txt'],
			'module form bare'       => ['rsync.example::feed', '198.51.100.9', '198.51.100.9::feed'],
			'module form user@'      => ['user@rsync.example::feed/x', '203.0.113.5', 'user@203.0.113.5::feed/x'],
			// rsync://host/path form -> IP substituted for the host, path intact.
			'url form'               => ['rsync://rsync.example/feed/list.txt', '203.0.113.5', 'rsync://203.0.113.5/feed/list.txt'],
			'url form with port'     => ['rsync://rsync.example:8730/feed', '203.0.113.5', 'rsync://203.0.113.5:8730/feed'],
			'url form user@'         => ['rsync://user@rsync.example/feed', '203.0.113.5', 'rsync://user@203.0.113.5/feed'],
			// IPv6 vetted IP is bracketed in the URL form.
			'url form ipv6'          => ['rsync://rsync.example/feed', '2001:db8::1', 'rsync://[2001:db8::1]/feed'],
		];
	}

	#[DataProvider('pinProvider')]
	public function testHostIsReplacedByVettedIp(string $url, string $ip, string $expected): void
	{
		$this->assertSame($expected, pfb_rsync_pin_url($url, $ip));
	}

	public function testUnparseableFormFailsClosed(): void
	{
		// A source that is neither a 'host::module' nor an 'rsync://' URL cannot be
		// host-substituted -> '' so the caller fails closed.
		$this->assertSame('', pfb_rsync_pin_url('https://rsync.example/feed', '203.0.113.5'));
		$this->assertSame('', pfb_rsync_pin_url('rsync.example/feed', '203.0.113.5'));
		$this->assertSame('', pfb_rsync_pin_url('', '203.0.113.5'));
		$this->assertSame('', pfb_rsync_pin_url('rsync.example::feed', ''));
	}
}
