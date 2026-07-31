<?php

/*
 * issue #1895 RequireConfigGateway sniff fixture (NOT production code).
 *
 * Lives under a fixtures/usr/local/www/ path (same as system_write_violation.php)
 * so the "/usr/local/www/" path-substring check applies here too — this is the
 * before/after proof for SystemWriteInWww: same path, but every call below MUST
 * stay silent, so it is the method name / class name / token shape that decides
 * the finding, not merely being under www/.
 *
 * Silent cases:
 *   a) PfbConfig::write() / PfbConfig::writeSection() — the authorization-
 *      checked variants; different method names entirely.
 *   b) SomethingElse::writeSystem() — same method name, wrong class.
 *   c) A comment mentioning "PfbConfig::writeSystem" as plain text — the
 *      T_STRING token check is structural, so prose never triggers it.
 *
 * Pinned by RequireConfigGatewaySniffTest::testSystemWriteCompliantCasesAreClean.
 */

function pfb_www_write_authorized_variant()
{
	// PfbConfig::write() enforces write_priv — must never be flagged.
	PfbConfig::write('gen/pfb_keep', '30');
}

function pfb_www_writesection_authorized_variant()
{
	// PfbConfig::writeSection() enforces write_priv — must never be flagged.
	PfbConfig::writeSection('installedpackages/pfblockerng/config/0', []);
}

function pfb_www_foreign_class_writesystem()
{
	// Same method name, but the class is not PfbConfig — must never be flagged.
	SomethingElse::writeSystem('gen/pfb_keep', '30');
}

function pfb_www_writesystem_mentioned_in_comment()
{
	// Mentioning PfbConfig::writeSystem() in a comment (e.g. explaining why it
	// must not be called here) is not code — must never be flagged.
	// See also: 'PfbConfig::writeSystem' referenced in a string literal below.
	$note = 'do not call PfbConfig::writeSystem() from this page';

	return $note;
}
