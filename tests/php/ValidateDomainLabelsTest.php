<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_domain_labels() — rejects a domain if any dot-separated label
 * exceeds the 63-char DNS label limit. (pfb_filter PFB_FILTER_DOMAIN leans on it.)
 */
#[CoversFunction('pfb_validate_domain_labels')]
final class ValidateDomainLabelsTest extends TestCase
{
	public function testAllShortLabelsPass(): void
	{
		$this->assertTrue(pfb_validate_domain_labels('a.b.example.com'));
	}

	public function testLabelExactly63Passes(): void
	{
		$this->assertTrue(pfb_validate_domain_labels(str_repeat('a', 63) . '.com'));
	}

	public function testLabel64Fails(): void
	{
		$this->assertFalse(pfb_validate_domain_labels(str_repeat('a', 64) . '.com'));
	}

	public function testLastLabelTooLongFails(): void
	{
		$this->assertFalse(pfb_validate_domain_labels('example.' . str_repeat('z', 70)));
	}

	public function testNoDotSingleLabel(): void
	{
		// A single sub-64 label has no over-long label -> TRUE.
		$this->assertTrue(pfb_validate_domain_labels('localhost'));
	}
}
