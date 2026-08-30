<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class RuntimeToggleOwnershipFlowTest extends TestCase
{
	public function testSelectedToggleReaderIsDefinedOnceAndConsumedByEveryFieldLoop(): void
	{
		$reflection = new ReflectionFunction('pfb_determine_list_detail');
		$lines = file($reflection->getFileName());
		if (!is_array($lines)) {
			throw new RuntimeException('test bootstrap: failed to read pfb_determine_list_detail source');
		}
		$source = implode('', array_slice(
			$lines,
			$reflection->getStartLine() - 1,
			$reflection->getEndLine() - $reflection->getStartLine() + 1
		));

		$tokens = array_values(array_filter(
			token_get_all("<?php\n{$source}"),
			static fn (array|string $token): bool => !is_array($token) || !in_array(
				$token[0],
				[T_OPEN_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT],
				TRUE
			)
		));
		$uses = [];
		foreach ($tokens as $index => $token) {
			if (!is_array($token) || $token[0] !== T_VARIABLE || $token[1] !== '$toggle_enabled') {
				continue;
			}
			$next = self::tokenText($tokens[$index + 1] ?? '');
			if ($next === '=') {
				$uses[] = 'assign';
				continue;
			}
			if ($next !== '(') {
				$uses[] = "other:{$next}";
				continue;
			}

			$call = '$toggle_enabled';
			$depth = 0;
			for ($cursor = $index + 1; isset($tokens[$cursor]); $cursor++) {
				$text = self::tokenText($tokens[$cursor]);
				$call .= $text;
				if ($text === '(') {
					$depth++;
				} elseif ($text === ')' && --$depth === 0) {
					break;
				}
			}
			$uses[] = "call:{$call}";
		}

		$this->assertSame([
			'assign',
			"call:\$toggle_enabled('autonot'.\$dir)",
			"call:\$toggle_enabled('autoaddrnot'.\$dir)",
			"call:\$toggle_enabled(\$akey.\$dir)",
		], $uses, 'the ownership-selected reader must not be replaced or bypassed before its three field-loop calls');
	}

	private static function tokenText(array|string $token): string
	{
		return is_array($token) ? $token[1] : $token;
	}
}
