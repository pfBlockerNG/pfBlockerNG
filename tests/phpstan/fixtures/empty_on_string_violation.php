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
