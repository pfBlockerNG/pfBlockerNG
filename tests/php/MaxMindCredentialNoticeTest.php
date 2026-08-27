<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_maxmind_credential_notice() — returns a field-aware notice when one or
 * both MaxMind credentials are absent, or '' when both are present.
 *
 * Regression anchor: the old code hardcoded "requires a License Key" even when
 * the Key was present and only the Account ID was missing — the exact case
 * reported in issue #335.
 */
#[CoversFunction('pfb_maxmind_credential_notice')]
final class MaxMindCredentialNoticeTest extends TestCase
{
	// Both credentials present — no notice expected.
	public function testBothPresentReturnsEmpty(): void
	{
		$this->assertSame('', pfb_maxmind_credential_notice('mykey', 'myaccount'));
	}

	// Account ID missing, Key present — notice must name Account ID and must NOT
	// say "License Key" (regression anchor for issue #335: old code wrongly said
	// "requires a License Key" in this case).
	public function testAccountMissingKeyPresentNamesAccountId(): void
	{
		$notice = pfb_maxmind_credential_notice('mykey', '');
		$this->assertStringContainsString('requires an Account ID!', $notice);
		$this->assertStringNotContainsString('License Key', $notice);
	}

	// License Key missing, Account ID present — notice must name License Key.
	public function testKeyMissingAccountPresentNamesLicenseKey(): void
	{
		$notice = pfb_maxmind_credential_notice('', 'myaccount');
		$this->assertStringContainsString('requires a License Key!', $notice);
		$this->assertStringNotContainsString('Account ID', $notice);
	}

	// Both missing — notice must name both fields.
	public function testBothMissingNamesBothFields(): void
	{
		$notice = pfb_maxmind_credential_notice('', '');
		$this->assertStringContainsString('requires an Account ID and License Key!', $notice);
	}

	// Full expected strings — ensures the suffix is intact for all non-empty branches.
	public function testAccountMissingFullMessage(): void
	{
		$this->assertSame(
			'MaxMind now requires an Account ID! Review the IP tab: MaxMind settings for more information.',
			pfb_maxmind_credential_notice('mykey', '')
		);
	}

	public function testKeyMissingFullMessage(): void
	{
		$this->assertSame(
			'MaxMind now requires a License Key! Review the IP tab: MaxMind settings for more information.',
			pfb_maxmind_credential_notice('', 'myaccount')
		);
	}

	public function testBothMissingFullMessage(): void
	{
		$this->assertSame(
			'MaxMind now requires an Account ID and License Key! Review the IP tab: MaxMind settings for more information.',
			pfb_maxmind_credential_notice('', '')
		);
	}
}
