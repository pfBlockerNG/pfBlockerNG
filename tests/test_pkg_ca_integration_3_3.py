"""Release/3.3 Software-page save, cron, and URL integration seam."""

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


def test_save_persists_the_software_check_setting_and_redirects() -> None:
    # issue #2694: the CA-consent surface (#2617/#2518) is retired -- #2692 put the
    # #2675 signed-catalogue hook on this line, so nothing consults pkg's CA store for
    # our repository anymore. The save block is a plain write-config-redirect now.
    source = SOFTWARE_PAGE.read_text()
    save = _between(source, "if ($_POST && isset($_POST['save'])) {", '// "Check now"')
    positions = [
        save.index("pfb_software_check_config_write("),
        save.index("write_config('[pfBlockerNG] save Software settings');"),
        save.index("header('Location: /pfblockerng/pfblockerng_software.php');"),
    ]
    assert positions == sorted(positions)
    for retired in (
        "pfb_pkg_ca_consent",
        "pfb_pkgconf_ca_save",
        "pfb_pkgconf_ca_apply",
        "pfb_pkgconf_ca_hook_is_login",
        "$input_errors[]",
        "PFB_PKG_CONF",
    ):
        assert retired not in save


def test_ui_has_no_ca_consent_section() -> None:
    # issue #2694: no edition/hook-generation gate renders a CA-consent control anymore.
    page = SOFTWARE_PAGE.read_text()
    source = SOFTWARE_CORE.read_text()
    for retired in (
        "pfb_pkg_ca_consent",
        "pfb_pkgconf_ca_add_form_controls",
        "pfb_login_ca_add_form_controls",
        "pfb_pkg_ca_is_plus",
        "pfb_pkgconf_ca_hook_is_login",
        "Package manager CA trust",
        "SSL_CA_CERT_PATH",
    ):
        assert retired not in page
        assert retired not in source
    assert "config_get_path" not in page


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
