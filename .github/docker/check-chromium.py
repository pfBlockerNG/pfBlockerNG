"""Prove the VM image's baked Chromium actually RUNS (issue #2214).

The obvious check — reading ``chromium.executable_path`` — is worthless: at the pinned
Playwright it is a plain string getter that computes a path from
``PLAYWRIGHT_BROWSERS_PATH`` and returns it whether or not anything is installed there.
So it passes on an image with no browser at all, which is precisely the regression the
VM image's one unique deliverable needs guarded.

Launching the browser and rendering a page cannot pass without a working Chromium build
and its shared libraries. --no-sandbox is required because the image build runs as root
in a container without user namespaces; the smoke jobs pass the same flag.
"""

from pathlib import Path

from playwright.sync_api import sync_playwright

with sync_playwright() as play:
    executable = Path(play.chromium.executable_path)
    if not executable.is_file():
        raise SystemExit(f"Chromium is not installed at {executable}")

    browser = play.chromium.launch(args=["--no-sandbox"])
    try:
        page = browser.new_page()
        page.set_content("<h1 id='probe'>chromium-ok</h1>")
        rendered = page.text_content("#probe")
        if rendered != "chromium-ok":
            raise SystemExit(f"Chromium rendered {rendered!r}, expected 'chromium-ok'")
    finally:
        browser.close()

print(f"chromium OK: {executable}")
