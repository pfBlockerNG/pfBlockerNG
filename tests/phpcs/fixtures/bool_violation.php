<?php

/*
 * ADR-28 UppercaseBooleanLiteral sniff fixture (NOT production code).
 *
 * Contains lowercase / PascalCase boolean VALUE literals that the sniff MUST
 * flag, plus a "string|false" return type that MUST NOT be flagged (type decl).
 *
 * Flagged lines: 17 (true), 18 (false), 19 (False) — three errors.
 * Clean line:    24 ("string|false" return type) — zero errors.
 *
 * Pinned by UppercaseBooleanLiteralSniffTest::testViolatingFileFindings.
 */

function pfb_bool_violation_target($flag)
{
	$a = true;   // line 17 -- flagged: lowercase true
	$b = false;  // line 18 -- flagged: lowercase false
	$c = False;  // line 19 -- flagged: PascalCase False

	return $a || $b || $c;
}

function pfb_bool_type_ok(): string|false  // line 24 -- NOT flagged: type declaration
{
	return FALSE;  // line 26 -- uppercase, clean
}
