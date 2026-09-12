"""Capture screenshots of the running demo for the README (requires the API + built UI on --base).

Usage: .venv/bin/python scripts/screenshots.py [--base http://127.0.0.1:8000] [--out docs/screenshots]
Uses Playwright for Python with the preinstalled Chromium (PLAYWRIGHT_BROWSERS_PATH honoured).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from throughline.simulator import storyline_constants as C  # noqa: E402

PAGES = [
    ("dashboard", "/"),
    ("alerts", "/alerts"),
    ("alert-detail-graph-context", f"/alerts/{C.ALERT_A['a009'][0]}?tab=graph"),
    ("alert-detail-flat-view", f"/alerts/{C.ALERT_A['a009'][0]}?tab=flat"),
    ("storyline-embercast", f"/storylines/{C.STORYLINE_A}"),
    ("explorer", f"/explorer?id={C.EP_BASTION}"),
    ("threat-intel-exposure", "/threat-intel?tab=exposure"),
]


def _launch_options() -> dict:
    """Use an explicitly configured or preinstalled Chromium when Playwright's own download is absent."""
    import glob
    import os

    explicit = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
    if explicit:
        return {"executable_path": explicit}
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    for pattern in ("chromium-*/chrome-linux/chrome", "chromium_headless_shell-*/chrome-linux/headless_shell"):
        matches = sorted(glob.glob(os.path.join(root, pattern)))
        if matches:
            return {"executable_path": matches[-1]}
    return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--out", default="docs/screenshots")
    ap.add_argument("--chat", default="Which credentials used in cloud API calls today were seen being stolen on an endpoint?")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(**_launch_options())
        page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        for name, path in PAGES:
            page.goto(args.base + path, wait_until="networkidle")
            time.sleep(1.5)
            page.screenshot(path=str(out / f"{name}.png"))
            print("captured", name)
        # analyst drawer mid-answer
        page.goto(args.base + f"/alerts/{C.ALERT_A['a009'][0]}?tab=graph", wait_until="networkidle")
        time.sleep(1.0)
        opened = False
        for selector in ("[data-testid='analyst-toggle']", "button:has-text('Analyst')", "button:has-text('Ask analyst')"):
            if page.locator(selector).count():
                page.locator(selector).first.click()
                opened = True
                break
        if opened:
            box = page.locator("[data-testid='analyst-input'], textarea").first
            box.fill(args.chat)
            box.press("Enter")
            time.sleep(4.0)
            page.screenshot(path=str(out / "analyst-drawer.png"))
            print("captured analyst-drawer")
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
