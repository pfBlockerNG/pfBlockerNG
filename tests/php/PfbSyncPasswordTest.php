<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sync_filter_password() — stores an XMLRPC sync password verbatim.
 *
 * Bug pinned (issue #339): pfblockerng_sync.php ran varsyncpassword through
 * htmlspecialchars() on save, so a password containing & " ' < > was stored
 * HTML-escaped. pfblockerng.inc later read it back verbatim and handed the
 * escaped form to the XMLRPC client, so authentication to the peer failed and
 * repeated attempts tripped sshguard.
 *
 * Fix: the helper is the named, unit-tested storage contract — return the value
 * unchanged. The Sync form's Form_Input escapes the value attribute for display
 * via Form_Element::__toString(), so escaping at the storage boundary is wrong.
 *
 * Contracts pinned:
 *   1. A password containing & is stored verbatim (no &amp; corruption).
 *   2. A password containing " ' < > is stored verbatim.
 *   3. A plain alphanumeric password round-trips unchanged.
 *   4. An empty password returns empty.
 *   5. Before/after contrast: htmlspecialchars() corrupts; the helper does not.
 */
#[CoversFunction('pfb_sync_filter_password')]
final class PfbSyncPasswordTest extends TestCase
{
	/**
	 * A password containing & is stored verbatim — no &amp; introduced.
	 */
	public function testPasswordWithAmpersandStoredVerbatim(): void
	{
		$result = pfb_sync_filter_password('p@ss&word');

		$this->assertSame('p@ss&word', $result,
			'ampersand must be stored verbatim, not HTML-encoded');
		$this->assertStringNotContainsString('&amp;', $result,
			'no &amp; entity may appear in the stored password');
	}

	/**
	 * A password containing " ' < > is stored verbatim — no HTML entities introduced.
	 */
	public function testPasswordWithQuotesAndAnglesStoredVerbatim(): void
	{
		$result = pfb_sync_filter_password('a"b\'c<d>e');

		$this->assertSame('a"b\'c<d>e', $result,
			'quotes and angle brackets must be stored verbatim');
		$this->assertStringContainsString('"', $result, 'raw double-quote must be present');
		$this->assertStringContainsString('<', $result, 'raw less-than must be present');
		$this->assertStringContainsString('>', $result, 'raw greater-than must be present');
		$this->assertStringNotContainsString('&quot;', $result, 'no &quot; entity may appear');
		$this->assertStringNotContainsString('&lt;', $result, 'no &lt; entity may appear');
		$this->assertStringNotContainsString('&gt;', $result, 'no &gt; entity may appear');
		$this->assertStringNotContainsString('&#039;', $result, 'no &#039; entity may appear');
	}

	/**
	 * A plain alphanumeric password is stored unchanged.
	 */
	public function testPlainPasswordUnchanged(): void
	{
		$this->assertSame('S3cr3tPass', pfb_sync_filter_password('S3cr3tPass'));
	}

	/**
	 * An empty password returns empty — no error, no substitution.
	 */
	public function testEmptyPasswordReturnsEmpty(): void
	{
		$this->assertSame('', pfb_sync_filter_password(''));
	}

	/**
	 * Regression contrast: documents the corruption the fix removes.
	 *
	 * Before: htmlspecialchars() encodes & in the password, so 'p@ss&word' becomes
	 * 'p@ss&amp;word' in config.xml and that escaped form is sent to the XMLRPC peer.
	 *
	 * After: pfb_sync_filter_password() stores the literal secret unchanged, so the
	 * peer receives the real password and authentication succeeds.
	 */
	public function testRegressionContrastsOldHtmlspecialcharsCorruption(): void
	{
		$password = 'p@ss&word';

		// Before state: the old htmlspecialchars() call corrupts the password.
		$this->assertNotSame($password, htmlspecialchars($password),
			'htmlspecialchars() must encode & — proving the old code corrupted the password');

		// After state: the helper preserves the literal secret.
		$this->assertSame($password, pfb_sync_filter_password($password),
			'pfb_sync_filter_password() must return the password unchanged');
	}
}
