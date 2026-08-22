"""Release/3.3 CA-consent page, cron, and URL integration seam."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
SOFTWARE_PAGE = ROOT / "src/usr/local/www/pfblockerng/pfblockerng_software.php"
SOFTWARE_CORE = ROOT / "src/usr/local/pkg/pfblockerng/pfblockerng_software.inc"
CRON_PAGE = ROOT / "src/usr/local/www/pfblockerng/pfblockerng.php"
URL_FILES = (
    ROOT / "src/usr/local/www/pfblockerng/pfblockerng_general.php",
    ROOT / "src/usr/local/www/pfblockerng/www/dnsbl_default.php",
    ROOT / "src/usr/local/www/wizards/pfblockerng_wizard.xml",
)


def _between(source: str, start: str, end: str) -> str:
    assert start in source, f"anchor not found: {start!r}"
    tail = source.split(start, 1)[1]
    assert end in tail, f"anchor not found: {end!r}"
    return tail.split(end, 1)[0]


def test_save_persists_consent_before_applying_pkg_conf() -> None:
    source = SOFTWARE_PAGE.read_text()
    save = _between(source, "if ($_POST && isset($_POST['save'])) {", '// "Check now"')
    positions = [
        save.index("$pfb_ca_was_consented = pfb_pkg_ca_consent_enabled();"),
        save.index("$pfb_ca_token = pfb_pkgconf_ca_save($_POST);"),
        save.index("write_config('[pfBlockerNG] save Software settings');"),
        save.index("$pfb_ca_ok = pfb_pkgconf_ca_apply($pfb_ca_token, $pfb_ca_was_consented);"),
    ]
    assert positions == sorted(positions)
    assert "pfb_software_check_config_write(" in save
    assert "if ($pfb_ca_ok)" in save
    assert "$input_errors[]" in save
    # issue #2631 review round: the failure notice speaks the installed generation.
    # Login hook: per-verb diagnosis naming /etc/login.conf, boot-only retry (there
    # is no per-check reapply to promise). Old hook: the shipped 3.3.3 sentence,
    # byte-preserved, naming pkg.conf.
    assert "if (pfb_pkgconf_ca_hook_is_login()) {" in save
    assert save.count("could not update /etc/login.conf right now") == 2
    assert "the file may be a symlink, or have a shape pfBlockerNG does not edit" in save
    assert save.count("it will retry at the next boot.") == 2
    assert "pfBlockerNG will retry at the next boot or package check." in save
    assert "PFB_PKG_CONF" in save
    assert "/etc/login.conf' : PFB_PKG_CONF" not in save


def test_ui_is_conditional_and_posts_an_explicit_consent_token() -> None:
    page = SOFTWARE_PAGE.read_text()
    source = SOFTWARE_CORE.read_text()
    assert "pfb_pkgconf_ca_add_form_controls($form, pfb_pkg_ca_consent_enabled());" in page
    for token in (
        "function pfb_pkgconf_ca_add_form_controls(",
        "new Form_Checkbox(\n\t\t'pfb_pkg_ca_consent'",
        "\n\t\t'on'\n\t))->setHelp($help);",
        "new Form_Input('pfb_pkg_ca_consent_shown', 'pfb_pkg_ca_consent_shown', 'hidden', '1')",
        "SSL_CA_CERT_PATH=/etc/ssl/certs",
        "Unchecking this removes only that one line",
        "re-applies the line at boot and before package checks",
    ):
        assert token in source
    # issue #2630: the login-generation hook applies on every edition; the pkg.conf
    # generation stays Plus-only.
    assert "if (pfb_pkg_ca_is_plus() || pfb_pkgconf_ca_hook_is_login()) {" in page
    assert "config_get_path" not in page
    assert "gen/pfb_pkg_ca_consent" not in page


def test_cron_keeps_feed_and_software_checks_without_a_duplicate_ca_writer() -> None:
    source = CRON_PAGE.read_text()
    case = _between(source, "case 'cron':", "\n\t\tcase 'updateip':")
    feed = case.index("pfblockerng_sync_cron();")
    update = case.index("pfb_software_update_check();")
    assert feed < update
    assert case.count("function_exists('pfb_software_update_check')") == 1
    assert case.count("try { pfb_software_update_check(); }") == 1
    assert "pfb_pkgconf_ca_tick" not in case


def test_active_project_links_are_https_and_canonical() -> None:
    insecure = "http://" + "pfblockerng.com"
    retired = "https://" + "pfblockerng.github.io"
    for path in URL_FILES:
        source = path.read_text()
        assert insecure not in source
        assert retired not in source
    assert URL_FILES[0].read_text().count("https://pfblockerng.com") == 2
    assert URL_FILES[1].read_text().count("https://pfblockerng.com") == 1
    assert URL_FILES[2].read_text().count("https://pfblockerng.com") == 2
