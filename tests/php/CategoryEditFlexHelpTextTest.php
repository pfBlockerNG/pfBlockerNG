<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2661 -- the Flex feed-state guideline must say what the retry disables.
 *
 * Flex is an operator-chosen per-feed exception: after cURL errors 35, 51 or 60
 * the download retry turns certificate verification off and widens the cipher
 * list to SSLv3. The category-edit Guidelines infoblock is the only user-facing
 * description of that state. The page cannot be required off-appliance, so the
 * executable help string is pinned from comment-free PHP.
 */
final class CategoryEditFlexHelpTextTest extends TestCase
{
	public function testFlexHelpStatesCertificateVerificationIsDisabled(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($source === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_category_edit.php');
		}
		if (preg_match('#<dt>Flex:</dt><dd>.*?</dd>#s', $source, $match) !== 1) {
			self::fail('category-edit Guidelines infoblock is missing a Flex definition');
		}
		$help = $match[0];

		$this->assertStringContainsString(
			'certificate verification disabled',
			$help,
			'Flex help must say certificate verification is turned off for that feed'
		);
		$this->assertStringContainsString(
			'widened cipher list',
			$help,
			'Flex help must say the cipher list is widened on the retry'
		);
		$this->assertStringContainsString(
			'Not Recommended',
			$help,
			'Flex help must keep the Not Recommended framing'
		);
		$this->assertStringContainsString(
			'unauthenticated',
			$help,
			'Flex help must say the feed contents are then unauthenticated'
		);
		$this->assertStringNotContainsString(
			'Downgrade the SSL Connection',
			$help,
			'Flex help must not hide the retry behind unspecific downgrade wording'
		);
	}
}
