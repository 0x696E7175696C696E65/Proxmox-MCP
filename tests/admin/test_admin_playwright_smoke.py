"""Optional Playwright smoke against a live admin UI.

Set PROXMOX_MCP_ADMIN_SMOKE_URL (e.g. https://localhost:8443/admin) plus
PROXMOX_MCP_ADMIN_USERNAME / PROXMOX_MCP_ADMIN_PASSWORD to enable.
"""

from __future__ import annotations

import os

import pytest


pytestmark = pytest.mark.skipif(
    not os.environ.get("PROXMOX_MCP_ADMIN_SMOKE_URL"),
    reason="Set PROXMOX_MCP_ADMIN_SMOKE_URL to run Playwright admin smoke",
)


def test_login_audit_hot_apply_smoke() -> None:
    playwright = pytest.importorskip("playwright.sync_api")
    base = os.environ["PROXMOX_MCP_ADMIN_SMOKE_URL"].rstrip("/")
    username = os.environ.get("PROXMOX_MCP_ADMIN_USERNAME", "admin")
    password = os.environ.get("PROXMOX_MCP_ADMIN_PASSWORD")
    if not password:
        pytest.skip("PROXMOX_MCP_ADMIN_PASSWORD required for Playwright smoke")

    with playwright.sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(base, wait_until="networkidle")
        page.get_by_label("Username").fill(username)
        page.get_by_label("Password").fill(password)
        page.get_by_role("button", name="Sign in").click()
        page.get_by_role("link", name="Audit").click()
        page.wait_for_selector("table.data", timeout=15_000)
        page.get_by_role("link", name="Config").click()
        page.get_by_label("Log level").select_option("info")
        page.get_by_role("button", name="Apply config").click()
        page.wait_for_selector("text=/Applied|hot-applied|applied/i", timeout=15_000)
        browser.close()
