<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Every checkbox this package renders must say what it POSTS (issue #2367).
 *
 * pfSense's Form_Checkbox defaults its value argument to 'yes'
 * (``__construct($name, $title, $description, $checked, $value = 'yes')``), while this
 * package's save paths validate with PFB_FILTER_ON_OFF, which accepts only 'on' and ''.
 * A checkbox built without the argument therefore renders and saves without error, and
 * silently persists the DISABLED token every time — including when it is ticked, leaving no
 * UI path back. The Software page shipped that way for a release.
 *
 * The page-specific round-trip lives in SoftwareCheckPostRoundTripTest; this is the class
 * guard, so the next page to omit the argument fails here rather than after a user cannot
 * re-enable a setting.
 */
final class WwwCheckboxPostedValueTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www';

	/** @return list<string> every shipped PHP file under src/usr/local/www. */
	private function pages(): array
	{
		$found = [];
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::WWW, FilesystemIterator::SKIP_DOTS));
		foreach ($it as $file) {
			if ($file->isFile() && strtolower((string) $file->getExtension()) === 'php') {
				$found[] = (string) $file->getPathname();
			}
		}
		sort($found);

		return $found;
	}

	/**
	 * Split a PHP argument list on its TOP-LEVEL commas.
	 *
	 * A plain explode() would split inside a quoted title ("Enable, then reload") and inside
	 * a nested call, counting arguments that are not there — which for this guard means a
	 * page that omits the posted value reads as if it passed one.
	 *
	 * @return list<string>
	 */
	public static function splitArgs(string $args): array
	{
		$parts = [];
		$current = '';
		$quote = '';
		$depth = 0;
		$length = strlen($args);

		for ($i = 0; $i < $length; $i++) {
			$char = $args[$i];

			if ($quote !== '') {
				// Inside a string literal: a backslash escapes the next character, so an
				// escaped quote does not end it.
				if ($char === '\\' && $i + 1 < $length) {
					$current .= $char . $args[++$i];
					continue;
				}
				if ($char === $quote) {
					$quote = '';
				}
				$current .= $char;
				continue;
			}

			if ($char === "'" || $char === '"') {
				$quote = $char;
			} elseif ($char === '(' || $char === '[') {
				$depth++;
			} elseif ($char === ')' || $char === ']') {
				$depth--;
			} elseif ($char === ',' && $depth === 0) {
				$parts[] = trim($current);
				$current = '';
				continue;
			}

			$current .= $char;
		}

		$parts[] = trim($current);

		return $parts;
	}

	/**
	 * The constructor arguments of every ``new Form_Checkbox(...)`` in a file, comments and
	 * line breaks already stripped so formatting cannot change the answer.
	 *
	 * @return list<list<string>>
	 */
	private function checkboxArgs(string $path): array
	{
		// Tokenised, not pattern-matched: a description like gettext('text (with parens)')
		// nests deeper than any fixed regex, and a call the sweep cannot see is a page it
		// cannot guard -- which is how a real offender would slip through.
		$tokens = token_get_all(php_strip_whitespace($path));
		$count  = count($tokens);
		$calls  = [];

		for ($i = 0; $i < $count; $i++) {
			if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_NEW) {
				continue;
			}
			$j = $i + 1;
			while ($j < $count && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], TRUE)) {
				$j++;
			}
			// A fully-qualified `new \Form_Checkbox(` is the same call; no page declares a
			// namespace today, so this is only here to keep the shape from being a blind spot.
			if ($j < $count && is_array($tokens[$j]) && $tokens[$j][0] === T_NS_SEPARATOR) {
				$j++;
			} elseif ($j < $count && $tokens[$j] === '\\') {
				$j++;
			}
			if ($j >= $count || !is_array($tokens[$j]) || $tokens[$j][0] !== T_STRING || $tokens[$j][1] !== 'Form_Checkbox') {
				continue;
			}
			$k = $j + 1;
			while ($k < $count && is_array($tokens[$k]) && $tokens[$k][0] === T_WHITESPACE) {
				$k++;
			}
			if ($k >= $count || $tokens[$k] !== '(') {
				continue;
			}

			$depth = 0;
			$args  = '';
			for ($n = $k; $n < $count; $n++) {
				$text = is_array($tokens[$n]) ? $tokens[$n][1] : $tokens[$n];
				if ($text === '(' || $text === '[') {
					$depth++;
					if ($depth === 1) {
						continue;
					}
				} elseif ($text === ')' || $text === ']') {
					$depth--;
					if ($depth === 0) {
						break;
					}
				}
				$args .= $text;
			}

			$calls[] = self::splitArgs($args);
		}

		return $calls;
	}

	/**
	 * The splitter is the guard's load-bearing half: miscount the arguments and a page that
	 * omits its posted value reads as compliant. A comma inside a title is the realistic
	 * shape ("Enable, then reload"), and a nested call is the other.
	 */
	public function testArgumentSplitterIgnoresCommasInsideLiteralsAndCalls(): void
	{
		$this->assertSame(
			["'pfb_x'", "'Enable, then reload'", "'Enabled'", '$checked'],
			self::splitArgs("'pfb_x', 'Enable, then reload', 'Enabled', \$checked"),
			'a comma inside a quoted argument must not end that argument'
		);
		$this->assertSame(
			["'pfb_x'", 'gettext(\'A, B\')', "'Enabled'", '$checked', "'on'"],
			self::splitArgs("'pfb_x', gettext('A, B'), 'Enabled', \$checked, 'on'"),
			'a comma inside a nested call must not end that argument'
		);
		// The case above is also satisfied by quote-tracking alone; this one is not, so it
		// is what actually holds the depth tracking honest.
		$this->assertSame(
			["'pfb_x'", 'max($a, $b)', "'Enabled'", '$rows[1, 2]', "'on'"],
			self::splitArgs("'pfb_x', max(\$a, \$b), 'Enabled', \$rows[1, 2], 'on'"),
			'an UNQUOTED comma inside a call or an index must not end that argument'
		);
		$this->assertSame(
			["'pfb_x'", '"a \\", b"', "'Enabled'", '$checked'],
			self::splitArgs("'pfb_x', \"a \\\", b\", 'Enabled', \$checked"),
			'an escaped quote must not end the literal it sits in'
		);
	}

	public function testEveryCheckboxPassesItsPostedValueExplicitly(): void
	{
		$offenders = [];
		$seen      = 0;

		foreach ($this->pages() as $page) {
			foreach ($this->checkboxArgs($page) as $args) {
				$seen++;
				// name, title, description, checked, value: fewer than five arguments means
				// the page inherits pfSense's 'yes'.
				if (count($args) < 5 || $args[4] === '') {
					$offenders[] = basename($page) . ': new Form_Checkbox(' . implode(', ', $args) . ')';
				}
			}
		}

		// A guard that silently sees only SOME of the calls is worse than one that sees none,
		// so the sweep's own count is checked against a second, cruder count of the same
		// construct. An undercount means a page is unguarded without anything saying so.
		$expected = 0;
		foreach ($this->pages() as $page) {
			$stripped  = php_strip_whitespace($page);
			$expected += substr_count($stripped, 'new Form_Checkbox');
			$expected += substr_count($stripped, 'new \\Form_Checkbox');
		}
		$this->assertGreaterThan(20, $expected, 'the sweep found almost no checkboxes; it has stopped matching');
		$this->assertSame($expected, $seen, 'the sweep parsed fewer checkbox calls than the tree contains');
		$this->assertSame(
			[],
			$offenders,
			"these checkboxes inherit pfSense's default posted value 'yes', which no PFB_FILTER_ON_OFF "
			. "save path accepts:\n  " . implode("\n  ", $offenders)
		);
	}
}
