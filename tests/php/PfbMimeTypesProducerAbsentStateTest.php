<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbMimeTypesProducerHygieneTest.php';

/** Issue #2906: MIME fixture producers must preserve a previously absent key. */
final class PfbMimeTypesProducerAbsentStateTest extends TestCase
{
	public static function producer(): array
	{
		return PfbMimeTypesProducerHygieneTest::producer();
	}

	#[DataProvider('producer')]
	public function testProducerLifecycleRestoresAbsentMimeTypes(string $class, string $method): void
	{
		$hadMimeTypes = array_key_exists('mime_types', $GLOBALS['pfb']);
		$previous = $GLOBALS['pfb']['mime_types'] ?? null;
		unset($GLOBALS['pfb']['mime_types']);

		try {
			$suite = new $class($method);
			$ref = new ReflectionClass($suite);
			$setUp = $ref->getMethod('setUp');
			$tearDown = $ref->getMethod('tearDown');
			$setUpComplete = false;

			try {
				$setUp->invoke($suite);
				$setUpComplete = true;
				$this->assertArrayHasKey(
					'mime_types',
					$GLOBALS['pfb'],
					"{$class} setUp must install its MIME fixture"
				);
			} finally {
				if ($setUpComplete) {
					$tearDown->invoke($suite);
				}
			}

			$this->assertArrayNotHasKey(
				'mime_types',
				$GLOBALS['pfb'],
				"{$class} teardown must preserve a previously absent MIME allow-list"
			);
		} finally {
			if ($hadMimeTypes) {
				$GLOBALS['pfb']['mime_types'] = $previous;
			} else {
				unset($GLOBALS['pfb']['mime_types']);
			}
		}
	}
}
