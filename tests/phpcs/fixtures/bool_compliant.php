<?php

/*
 * ADR-28 UppercaseBooleanLiteral sniff fixture (NOT production code).
 *
 * Contains:
 *   - Uppercase TRUE/FALSE value literals -> sniff MUST stay silent.
 *   - A "string|false" union return type   -> sniff MUST stay silent (type decl).
 *   - A "?true" nullable param type        -> sniff MUST stay silent (type decl).
 *   - A 'true' string literal              -> sniff MUST stay silent (string).
 *   - A null value literal                 -> out of scope, MUST stay silent.
 *
 * Pinned by UppercaseBooleanLiteralSniffTest::testCompliantFileIsClean.
 */

function pfb_bool_value_ok(bool $flag = FALSE): string|false
{
	if ($flag === TRUE) {
		return 'yes';
	}

	$check = ($flag !== FALSE) ? TRUE : FALSE;
	$str   = 'true';  // string literal — not a boolean
	$n     = null;    // null — out of scope for ADR-28

	return FALSE;
}

function pfb_nullable_type_ok(?true $x = NULL): bool
{
	return TRUE;
}
