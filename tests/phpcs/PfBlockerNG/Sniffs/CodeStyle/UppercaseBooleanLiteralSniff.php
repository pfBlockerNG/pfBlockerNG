<?php

/*
 * ADR-28 item 5: enforce uppercase PHP TRUE/FALSE boolean value literals.
 *
 * Flags any T_TRUE or T_FALSE token whose text is not exactly uppercase
 * (e.g. "true", "false", "True", "False", "tRuE") and emits an error with
 * an auto-fixable replacement. Type-declaration positions (return types,
 * parameter types, union types such as "string|false") are EXCLUDED — PHPCS's
 * own tokenizer converts T_TRUE/T_FALSE in type contexts back to T_STRING
 * before the sniff runs, so those tokens never reach this sniff. Strings
 * ('true', "false") and identifiers are not affected. NULL/null is out of
 * scope (ADR-28 §2.4).
 *
 * Extends Generic.PHP.UpperCaseConstant (which itself extends
 * Generic.PHP.LowerCaseConstant) so all type-declaration skipping logic is
 * inherited; we narrow the target set to T_TRUE/T_FALSE only and update the
 * error message and error code.
 */

namespace PfBlockerNG\Sniffs\CodeStyle;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Standards\Generic\Sniffs\PHP\UpperCaseConstantSniff;
use PHP_CodeSniffer\Util\Tokens;

class UppercaseBooleanLiteralSniff extends UpperCaseConstantSniff
{
	/**
	 * Returns only the T_TRUE and T_FALSE tokens (not T_NULL).
	 * Scope-modifier and function-keyword tokens are also registered so the
	 * parent's type-declaration skip logic fires correctly.
	 *
	 * @return array<int, int|string>
	 */
	public function register()
	{
		$targets = [
			T_TRUE  => T_TRUE,
			T_FALSE => T_FALSE,
		];

		// Inherit the parent's type-declaration filters (property modifiers,
		// T_FUNCTION / T_CLOSURE / T_FN, T_CONST).
		$targets  += Tokens::$scopeModifiers;
		$targets[] = T_VAR;
		$targets[] = T_STATIC;
		$targets[] = T_READONLY;
		$targets[] = T_FINAL;
		$targets[] = T_ABSTRACT;
		$targets[] = T_FUNCTION;
		$targets[] = T_CLOSURE;
		$targets[] = T_FN;
		$targets[] = T_CONST;

		return $targets;
	}

	/**
	 * Flags a T_TRUE / T_FALSE token that is not exactly uppercase.
	 *
	 * @param int $stackPtr
	 */
	protected function processConstant(File $phpcsFile, $stackPtr)
	{
		$tokens  = $phpcsFile->getTokens();
		$code    = $tokens[$stackPtr]['code'];

		// Only handle TRUE/FALSE — the parent also processes NULL, which is
		// out of scope for ADR-28.
		if ($code !== T_TRUE && $code !== T_FALSE) {
			return;
		}

		$keyword  = $tokens[$stackPtr]['content'];
		$expected = strtoupper($keyword);

		if ($keyword === $expected) {
			return;
		}

		$error = 'Boolean literal must be uppercase (ADR-28); expected "%s" but found "%s"';
		$data  = [$expected, $keyword];

		$fix = $phpcsFile->addFixableError($error, $stackPtr, 'Found', $data);
		if ($fix === TRUE) {
			$phpcsFile->fixer->replaceToken($stackPtr, $expected);
		}
	}
}
