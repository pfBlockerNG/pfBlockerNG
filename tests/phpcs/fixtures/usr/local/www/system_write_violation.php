<?php

/*
 * issue #1895 RequireConfigGateway sniff fixture (NOT production code).
 *
 * Lives under a fixtures/usr/local/www/ path so the sniff's "/usr/local/www/"
 * path-substring check applies, exactly as it would to a real pfSense web UI
 * file. Static PfbConfig::writeSystem() / PfbConfig::writeSectionSystem() /
 * (issue #1921) writeSectionRawSystem() calls here MUST each be flagged with
 * the SystemWriteInWww error code — those methods bypass per-field write_priv
 * authorization and are reserved for no-session system contexts
 * (cron/install/migrations/CLI/core hooks), never a web-UI page.
 *
 * Pinned by RequireConfigGatewaySniffTest::testFlagsSystemWriteInWww.
 */

function pfb_www_writesystem_violation()
{
	// Direct writeSystem() call from a www/ page — must be flagged.
	PfbConfig::writeSystem('gen/pfb_keep', '30');
}

function pfb_www_writesectionsystem_violation()
{
	// Direct writeSectionSystem() call from a www/ page — must be flagged.
	PfbConfig::writeSectionSystem('installedpackages/pfblockerng/config/0', []);
}

function pfb_www_writesectionrawsystem_violation()
{
	// issue #1921: direct writeSectionRawSystem() call from a www/ page — must be flagged.
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerng/config/0', []);
}

function pfb_www_writesystem_case_variance()
{
	// Case-insensitive class AND method name (PHP identifiers are
	// case-insensitive) — must still be flagged.
	pfbconfig::WRITESYSTEM('gen/pfb_keep', '30');
}

function pfb_www_writesystem_comment_before_double_colon()
{
	// A comment wedged between the class name and '::' must not evade the
	// sniff -- it must walk past comment tokens, not just whitespace.
	PfbConfig/*x*/::writeSystem('gen/pfb_keep', '30');
}

function pfb_www_writesystem_comment_after_double_colon()
{
	// A comment wedged between '::' and the method name must not evade
	// the sniff either.
	PfbConfig::/*x*/writeSystem('gen/pfb_keep', '30');
}

function pfb_www_writesystem_comment_before_paren()
{
	// The third comment gap: between the method name and '(' — the sniff's
	// forward walk to the opening parenthesis must skip comments too.
	PfbConfig::writeSystem/*x*/('gen/pfb_keep', '30');
}
