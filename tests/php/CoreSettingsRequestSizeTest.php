<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937 (review on PR #3942): Core's writes carry every projection, the groups' custom lists included, so a request of a few
 * MiB is a real configuration; the adapter takes it, as Core takes a read reply of that size. Past 32 MiB it is still refused.
 */
#[CoversFunction('pfb_core_settings_serve')]
final class CoreSettingsRequestSizeTest extends TestCase
{
	public function testARequestOfSomeMiBIsServed(): void
	{
		$reply = json_decode(pfb_core_settings_serve('{"version":1,"op":"read"}' . str_repeat(' ', 3 << 20)), TRUE);

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertArrayHasKey('feeds/ipv4', $reply['settings'] ?? []);
	}

	public function testARequestOver32MiBIsRefused(): void
	{
		$reply = json_decode(pfb_core_settings_serve('{"version":1,"op":"read"}' . str_repeat(' ', 32 << 20)), TRUE);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
	}
}
