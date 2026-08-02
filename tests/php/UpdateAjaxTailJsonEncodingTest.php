<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class UpdateAjaxTailJsonEncodingTest extends TestCase
{
	public function testTailReaderReceivesValidatedOffsetAndResponseIsJson(): void
	{
		$received = NULL;
		$result = pfb_update_tail_response(
			['ajax' => 'tail', 'offset' => '17'],
			static function (string $which, int $offset, bool $hasOffset) use (&$received): array {
				$received = [$which, $offset, $hasOffset];
				return ['data' => "line\n"];
			}
		);
		$this->assertSame(['update', 17, TRUE], $received);
		$this->assertSame(['Content-Type: application/json', 'Cache-Control: no-cache, no-store, must-revalidate'], $result['headers']);
		$this->assertSame(['data' => "line\n"], json_decode($result['body'], TRUE));
	}

	public function testInvalidUtf8TailByteIsSubstitutedInValidJson(): void
	{
		$args = NULL;
		$result = pfb_update_tail_response(
			['ajax' => 'tail'],
			static function (string $which, int $offset, bool $hasOffset) use (&$args): array {
				$args = [$which, $offset, $hasOffset];
				return ['data' => "bad \xFF"];
			}
		);
		$this->assertSame(['update', -1, FALSE], $args);
		$this->assertTrue(mb_check_encoding($result['body'], 'UTF-8'));
		$decoded = json_decode($result['body'], TRUE);
		$this->assertIsArray($decoded);
		$this->assertStringContainsString("\u{FFFD}", $decoded['data']);
	}

}
