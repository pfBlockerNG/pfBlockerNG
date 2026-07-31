<?php

/*
 * issue #1895 RequireConfigGateway sniff fixture (NOT production code).
 *
 * Lives under a fixtures/usr/local/pkg/pfblockerng/ path — no "/usr/local/www/"
 * substring anywhere in the file path. The exact same PfbConfig::writeSystem()
 * / PfbConfig::writeSectionSystem() / writeSectionRawSystem() (issue #1921)
 * call shapes as system_write_violation.php MUST stay silent here: this is the
 * legitimate no-session system-caller use case (cron/install/migrations/CLI/core
 * hooks) these methods exist for.
 *
 * Pinned by RequireConfigGatewaySniffTest::testSystemWriteOutsideWwwIsClean.
 */

function pfb_pkg_writesystem_system_caller()
{
	// System-context caller (e.g. cron/install) — legitimate, must stay silent.
	PfbConfig::writeSystem('gen/pfb_keep', '30');
}

function pfb_pkg_writesectionsystem_system_caller()
{
	// System-context caller (e.g. migration) — legitimate, must stay silent.
	PfbConfig::writeSectionSystem('installedpackages/pfblockerng/config/0', []);
}

function pfb_pkg_writesectionrawsystem_system_caller()
{
	// issue #1921: system-context caller (e.g. migration) — legitimate, must stay silent.
	PfbConfig::writeSectionRawSystem('installedpackages/pfblockerng/config/0', []);
}
