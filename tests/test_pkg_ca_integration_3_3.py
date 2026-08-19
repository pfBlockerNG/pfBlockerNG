"""Release/3.3 CA-consent page, cron, and URL integration seam."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
SOFTWARE_PAGE = ROOT / "src/usr/local/www/pfblockerng/pfblockerng_software.php"
CRON_PAGE = ROOT / "src/usr/local/www/pfblockerng/pfblockerng.php"
URL_FILES = (
    ROOT / "src/usr/local/www/pfblockerng/pfblockerng_general.php",
    ROOT / "src/usr/local/www/pfblockerng/www/dnsbl_default.php",
    ROOT / "src/usr/local/www/wizards/pfblockerng_wizard.xml",
)


def test_save_persists_consent_before_applying_pkg_conf() -> None:
    source = SOFTWARE_PAGE.read_text()
    save = source.split("if ($_POST && isset($_POST['save'])) {", 1)[1].split(
        '// "Check now"', 1
    )[0]
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


def test_ui_is_conditional_and_posts_an_explicit_consent_token() -> None:
    source = SOFTWARE_PAGE.read_text()
    for token in (
        "$pfb_ca_state = pfb_pkgconf_ca_state();",
        "if ($pfb_ca_state !== '') {",
        "$pfb_ca_consent = pfb_pkg_ca_consent_enabled();",
        "new Form_Checkbox(\n\t\t'pfb_pkg_ca_consent'",
        "\n\t\t'on'\n\t))->setHelp($pfb_ca_help);",
        "new Form_Input('pfb_pkg_ca_consent_shown', 'pfb_pkg_ca_consent_shown', 'hidden', '1')",
        "SSL_CA_CERT_PATH=/etc/ssl/certs",
        "Unchecking this removes only that one line",
        "re-applies the line at boot and on every scheduled (cron) pass",
    ):
        assert token in source
    assert "config_get_path" not in source
    assert "gen/pfb_pkg_ca_consent" not in source


def test_cron_keeps_feed_sync_and_adds_best_effort_ca_tick() -> None:
    source = CRON_PAGE.read_text()
    case = source.split("case 'cron':", 1)[1].split("\n\t\tcase 'updateip':", 1)[0]
    feed = case.index("pfblockerng_sync_cron();")
    update = case.index("pfb_software_update_check();")
    tick = case.index("pfb_pkgconf_ca_tick();")
    assert feed < update < tick
    assert case.count("function_exists('pfb_software_update_check')") == 1
    assert case.count("function_exists('pfb_pkgconf_ca_tick')") == 1
    assert case.count("try { pfb_software_update_check(); }") == 1
    assert case.count("try { pfb_pkgconf_ca_tick(); }") == 1


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
