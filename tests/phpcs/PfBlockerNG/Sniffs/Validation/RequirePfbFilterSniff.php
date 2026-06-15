<?php

/*
 * PFBL-01: enforce the input-validation contract mechanically.
 *
 * Flags any SINK -- an exec-family call, a json_encode() (the Python manifest
 * writer), or a dynamic filesystem-path build -- that appears inside a PFBL-01
 * in-scope function WITHOUT a preceding semantic-validation call (pfb_filter() /
 * pfb_sanitise_feed_header() / sanitize_ipaddr()) in the same function scope.
 * This is the "ADR-06/07/10/13 surfaces" gate from PFBL-01 Requirement 4: it does
 * not replace escapeshellarg() -- it enforces that the SEMANTIC layer is also
 * present, the dual-layer rule pfb_unbound_py_ccache_flush_cmds() already follows.
 *
 * Scope is an explicit, auditable allow-list of function names (the Phase 1 audit
 * table), settable from the ruleset so the in-scope set stays visible and grows
 * deliberately -- the ADR's "legacy code is out of scope" carve-out is encoded by
 * NOT listing legacy functions, never by a blanket file scan.
 */

namespace PfBlockerNG\Sniffs\Validation;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class RequirePfbFilterSniff implements Sniff
{
	/**
	 * The PFBL-01 in-scope surface: the functions the Phase 1 audit identified as
	 * accepting caller-supplied input that reaches a path / exec / manifest sink.
	 * Override from the ruleset via <property name="scopeFunctions" type="array">
	 * when a new in-scope function is added.
	 *
	 * @var string[]
	 */
	public $scopeFunctions = [
		'pfb_manage_dnsbl_vip',
		'pfb_ss_resolve_target',
		'pfb_dnsbl_whitelist_lines',
		'pfb_dnsbl_unlock_lines',
		'pfb_sanitise_feed_header',
		'pfb_unbound_python_sources',
		'pfb_unbound_py_ccache_flush_cmds',
		'pfb_run_hooks',
	];

	/**
	 * Calls that satisfy the semantic-validation contract. escapeshellarg() is NOT
	 * here on purpose: it is shell quoting, not semantic validation -- PFBL-01
	 * requires both layers and this sniff enforces the one escapeshellarg() cannot.
	 *
	 * @var string[]
	 */
	public $validatorFunctions = [
		'pfb_filter',
		'pfb_sanitise_feed_header',
		'sanitize_ipaddr',
		'pfb_hook_script_valid',
	];

	/**
	 * Exec-family sinks: a value reaching any of these must have passed a
	 * semantic-validation call first; the sniff flags one that has not.
	 *
	 * @var string[]
	 */
	public $execFunctions = [
		'exec',
		'shell_exec',
		'system',
		'passthru',
		'proc_open',
		'popen',
		'mwexec',
		'mwexec_bg',
	];

	/**
	 * Manifest / serialisation sinks: json_encode() writes the Python build manifest
	 * (pfb_unbound_py_sources.json) consumed by pfb_unbound.py; a value stored here
	 * propagates to query time, so it must be validated first.
	 *
	 * @var string[]
	 */
	public $encodeFunctions = [
		'json_encode',
	];

	/**
	 * @return array<int, int|string>
	 */
	public function register()
	{
		return [T_FUNCTION];
	}

	/**
	 * @param int $stackPtr
	 */
	public function process(File $phpcsFile, $stackPtr)
	{
		$tokens = $phpcsFile->getTokens();

		$name = $phpcsFile->getDeclarationName($stackPtr);
		if ($name === null || !in_array($name, $this->scopeFunctions, true)) {
			return;
		}

		// No body (abstract / interface) -> nothing to guard.
		if (!isset($tokens[$stackPtr]['scope_opener'], $tokens[$stackPtr]['scope_closer'])) {
			return;
		}

		$open  = $tokens[$stackPtr]['scope_opener'];
		$close = $tokens[$stackPtr]['scope_closer'];

		// Earliest semantic-validation call inside the body; null when there is none.
		$firstValidator = $this->firstValidatorCall($phpcsFile, $tokens, $open, $close);

		for ($i = $open + 1; $i < $close; $i++) {
			$sink = $this->matchSink($phpcsFile, $tokens, $i);
			if ($sink === null) {
				continue;
			}

			// Satisfied iff some validator call precedes this sink in the same scope.
			if ($firstValidator !== null && $firstValidator < $i) {
				continue;
			}

			$phpcsFile->addError(
				sprintf(
					'PFBL-01: %s in %s() is not preceded by a semantic-validation call '
					. '(%s) in the same function scope. Validate the input before '
					. 'it reaches a path/exec/manifest sink; escapeshellarg() alone is not enough.',
					$sink,
					$name,
					implode('() / ', $this->validatorFunctions) . '()'
				),
				$i,
				'MissingFilter'
			);
		}
	}

	/**
	 * Index of the first validator call within ($open, $close), or null.
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 * @return int|null
	 */
	private function firstValidatorCall(File $phpcsFile, array $tokens, int $open, int $close)
	{
		for ($i = $open + 1; $i < $close; $i++) {
			if (!$this->isNameToken($tokens[$i]['code'])) {
				continue;
			}
			if (!in_array($this->callName($tokens, $i), $this->validatorFunctions, true)) {
				continue;
			}
			if ($this->isFunctionCall($phpcsFile, $tokens, $i)) {
				return $i;
			}
		}

		return null;
	}

	/**
	 * Classify the token at $i as a PFBL-01 sink, or null when it is not one.
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 * @return string|null  Human-readable sink description for the error message.
	 */
	private function matchSink(File $phpcsFile, array $tokens, int $i)
	{
		$code = $tokens[$i]['code'];

		// Function-call sinks: exec-family + json_encode.
		if ($this->isNameToken($code) && $this->isFunctionCall($phpcsFile, $tokens, $i)) {
			$fn = $this->callName($tokens, $i);
			if (in_array($fn, $this->execFunctions, true)) {
				return "an exec-family call ({$fn}())";
			}
			if (in_array($fn, $this->encodeFunctions, true)) {
				return "a serialisation sink ({$fn}())";
			}
		}

		// Interpolated path: a "..." / heredoc carrying both '/' and an interpolated
		// variable, e.g. "{$pfb['dnsdir']}/{$header}.txt".
		if ($code === T_DOUBLE_QUOTED_STRING || $code === T_HEREDOC) {
			$content = (string) $tokens[$i]['content'];
			if (strpos($content, '/') !== false && strpos($content, '$') !== false) {
				return 'a dynamic filesystem-path build (interpolated string)';
			}
		}

		// Concatenated path: a string literal containing '/' joined by '.' to another
		// term, e.g. $dir . '/' . $name.
		if ($code === T_CONSTANT_ENCAPSED_STRING) {
			$literal = trim((string) $tokens[$i]['content'], "'\"");
			if (strpos($literal, '/') !== false && $this->isConcatenated($phpcsFile, $tokens, $i)) {
				return 'a dynamic filesystem-path build (string concatenation)';
			}
		}

		return null;
	}

	/**
	 * True when $code is a callable-name token: a plain T_STRING or a namespace-
	 * qualified name (T_NAME_QUALIFIED / T_NAME_FULLY_QUALIFIED), so a qualified
	 * call like \exec() or Foo\exec() is considered alongside a bare exec().
	 *
	 * @param int|string $code
	 */
	private function isNameToken($code): bool
	{
		return $code === T_STRING
			|| $code === T_NAME_QUALIFIED
			|| $code === T_NAME_FULLY_QUALIFIED;
	}

	/**
	 * Bare, lowercased function name at $i: strips any namespace prefix and a leading
	 * '\', so \exec and Foo\exec both resolve to exec. Without this a namespace-
	 * qualified sink would slip past the allow-list checks (a PFBL-01 gate bypass).
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 */
	private function callName(array $tokens, int $i): string
	{
		$content = (string) $tokens[$i]['content'];
		$tail = strrchr($content, '\\');
		return strtolower($tail === false ? $content : substr($tail, 1));
	}

	/**
	 * True when the name token at $i is a direct function call (next non-empty token is
	 * '(') and not a method/property access, declaration, namespace segment or
	 * object instantiation.
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 */
	private function isFunctionCall(File $phpcsFile, array $tokens, int $i): bool
	{
		$next = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);
		if ($next === false || $tokens[$next]['code'] !== T_OPEN_PARENTHESIS) {
			return false;
		}

		// PHPCS tokenizes a qualified call (\exec, Foo\exec) as a T_NS_SEPARATOR /
		// T_STRING chain. Walk back over that whole prefix so the call is judged by
		// what precedes the qualified NAME, not by its own namespace separators —
		// otherwise a leading '\' would mask the call (a PFBL-01 gate bypass).
		$prev = $phpcsFile->findPrevious(T_WHITESPACE, $i - 1, null, true);
		while ($prev !== false
			&& ($tokens[$prev]['code'] === T_NS_SEPARATOR || $tokens[$prev]['code'] === T_STRING)) {
			$prev = $phpcsFile->findPrevious(T_WHITESPACE, $prev - 1, null, true);
		}
		if ($prev === false) {
			return true;
		}

		$disqualifiers = [
			T_OBJECT_OPERATOR,
			T_NULLSAFE_OBJECT_OPERATOR,
			T_DOUBLE_COLON,
			T_FUNCTION,
			T_NEW,
		];

		return !in_array($tokens[$prev]['code'], $disqualifiers, true);
	}

	/**
	 * True when the literal at $i is part of a '.' concatenation (either side).
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 */
	private function isConcatenated(File $phpcsFile, array $tokens, int $i): bool
	{
		$prev = $phpcsFile->findPrevious(T_WHITESPACE, $i - 1, null, true);
		$next = $phpcsFile->findNext(T_WHITESPACE, $i + 1, null, true);

		$prevIsConcat = $prev !== false && $tokens[$prev]['code'] === T_STRING_CONCAT;
		$nextIsConcat = $next !== false && $tokens[$next]['code'] === T_STRING_CONCAT;

		return $prevIsConcat || $nextIsConcat;
	}
}
