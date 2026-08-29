<?php

// Fixture for NoEmptyOnStringRuleTest: every empty() below sits on a
// statically-string-typed operand and MUST be flagged by
// PfBlockerNG\PHPStan\NoEmptyOnStringRule (issue #1787).

function pfb_fixture_empty_on_string_param(string $value): bool {
	return empty($value); // line 8: plain string
}

function pfb_fixture_empty_on_nullable_string(?string $value): bool {
	return empty($value); // line 12: ?string still lies about '0'
}

function pfb_fixture_empty_on_string_or_false($haystack): bool {
	$pos = strstr((string) $haystack, '/');
	return empty($pos); // line 17: string|false — the false wrapper is stripped
}

/** @param string|int $value */
function pfb_fixture_empty_on_string_int_union($value): bool {
	return empty($value); // line 22: string|int — the string member still lies about '0' (issue #1792 N1)
}

/** @param 'a'|'b'|'' $value */
function pfb_fixture_empty_on_string_literal_union(string $value): bool {
	return empty($value); // line 27: literal-string union is still a string operand
}
