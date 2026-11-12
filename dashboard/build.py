"""Build the GHQR estate-health dashboard as a single, self-contained HTML file,
and optionally export the dashboard itself as a PDF.

The page has no external dependencies (no CDNs, fonts or network calls), so it can be
presented offline and shared without exposing report data to third parties. Printing the
page (Ctrl+P, or "Export PDF" in the dashboard) produces a PDF of every dashboard section,
with all findings expanded.

With no report argument, the dashboard starts empty. Upload a report in the browser,
then use "Unload report" to clear it and return to the upload screen.

Usage:
    python build.py [-o output.html]                              # empty dashboard (drag-and-drop a report)
    python build.py <ghqr-report.json> -o <private-output.html>  # embed a report outside the checkout
    python build.py <ghqr-report.json> -o <private-output.html> --pdf [--theme light]

PDF export needs Microsoft Edge or Google Chrome. It runs the browser headless with a
throwaway profile; set GHQR_BROWSER or pass --browser to choose a specific executable.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src"
DATA_TAG = '<script id="ghqr-data" type="application/json">null</script>'
CSS_MARK = "/*__GHQR_CSS__*/"
JS_MARK = "/*__GHQR_JS__*/"
BROWSER_CANDIDATES = [
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def read_parts(folder: str, pattern: str) -> str:
    parts = sorted((SRC / folder).glob(pattern))
    if not parts:
        raise SystemExit(f"No {pattern} files found in {SRC / folder}")
    return "\n".join(p.read_text(encoding="utf-8") for p in parts)


def assert_inline_safe(name: str, text: str) -> None:
    lowered = text.lower()
    for token in ("</script", "</style", "<!--"):
        if token in lowered:
            raise SystemExit(f"{name} contains '{token}', which is unsafe to inline in HTML")


def json_script(tag_id: str, value: object, source: str | None = None) -> str:
    # Escaping '<' keeps the payload valid JSON while making '</script>' impossible inside it.
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    attr = f' data-source="{html.escape(source, quote=True)}"' if source else ""
    return f'<script id="{tag_id}" type="application/json"{attr}>{payload}</script>'


def require_private_output(path: pathlib.Path) -> None:
    boundary = next((parent for parent in (ROOT, *ROOT.parents) if (parent / ".git").exists()), ROOT)
    if path.resolve().is_relative_to(boundary):
        raise SystemExit("Report-bearing HTML and PDF exports must be written outside the repository checkout (or application folder for standalone copies).")


def build(report: pathlib.Path | None, out: pathlib.Path) -> pathlib.Path:
    if report is not None:
        require_private_output(out)
    page = (SRC / "index.html").read_text(encoding="utf-8")
    css = read_parts("css", "*.css")
    js = "(() => {\n'use strict';\n" + read_parts("js", "*.js") + "\n})();\n"
    assert_inline_safe("CSS", css)
    assert_inline_safe("JavaScript", js)
    for mark in (CSS_MARK, JS_MARK, DATA_TAG):
        if page.count(mark) != 1:
            raise SystemExit(f"Template marker {mark!r} must appear exactly once")
    page = page.replace(CSS_MARK, css, 1).replace(JS_MARK, js, 1)

    if report is not None:
        data = json.loads(report.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not any(k in data for k in ("enterprises", "organizations", "repositories")):
            raise SystemExit(f"{report} does not look like a GHQR JSON report")
        page = page.replace(DATA_TAG, json_script("ghqr-data", data, report.name), 1)

    out.write_text(page, encoding="utf-8", newline="\n")
    return out


def find_browser(explicit: str | None = None) -> str | None:
    for candidate in (explicit, os.environ.get("GHQR_BROWSER"), *BROWSER_CANDIDATES):
        if candidate:
            path = pathlib.Path(os.path.expandvars(candidate))
            if path.is_file():
                return str(path)
    for name in ("msedge", "microsoft-edge", "google-chrome", "chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return None


def export_pdf(page: pathlib.Path, pdf: pathlib.Path, browser: str, theme: str) -> int:
    """Print the dashboard with a headless Chromium browser; export mode expands every section and finding."""
    pdf = pdf.resolve()
    require_private_output(pdf)
    pdf.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="ghqr-browser-", ignore_cleanup_errors=True) as profile:
        cmd = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--disable-extensions", "--hide-scrollbars", "--window-size=1440,1018", f"--user-data-dir={profile}",
            "--no-pdf-header-footer", "--virtual-time-budget=20000", f"--print-to-pdf={pdf}",
            page.resolve().as_uri() + f"?export=pdf&theme={theme}",
        ]
        try:
            subprocess.run(cmd, check=True, timeout=300, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError) as err:
            raise SystemExit(f"PDF export failed while running {browser}: {err}") from err
    if not pdf.is_file() or pdf.stat().st_size == 0:
        raise SystemExit(f"PDF export failed: {browser} did not write {pdf}")
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf.read_bytes()))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", nargs="?", type=pathlib.Path, help="GHQR JSON report to embed")
    parser.add_argument("-o", "--output", type=pathlib.Path, help="output HTML file")
    parser.add_argument("--pdf", nargs="?", const="", metavar="PATH", help="also export the dashboard as PDF (optionally to PATH)")
    parser.add_argument("--theme", choices=("dark", "light"), default="dark", help="colour theme for the PDF (default: dark, as on screen)")
    parser.add_argument("--browser", help="Edge or Chrome executable to use for PDF export")
    args = parser.parse_args(argv)

    if args.report is not None and not args.report.is_file():
        parser.error(f"report not found: {args.report}")
    if args.pdf is not None and args.report is None:
        parser.error("--pdf needs a report to render")
    if args.report is not None and args.output is None:
        parser.error("embedding a report requires --output outside the repository checkout")
    out = args.output or (ROOT / "ghqr-dashboard.html")
    if args.pdf is not None:
        suffix = "" if args.theme == "dark" else f"-{args.theme}"
        pdf = (pathlib.Path(args.pdf) if args.pdf else out.with_name(f"{out.stem}{suffix}.pdf")).resolve()
        require_private_output(pdf)
    path = build(args.report, out)
    print(f"Wrote {path} ({path.stat().st_size / 1024:,.0f} KB)")

    if args.pdf is not None:
        browser = find_browser(args.browser)
        if not browser:
            raise SystemExit("PDF export needs Microsoft Edge or Google Chrome; pass --browser or set GHQR_BROWSER.")
        pages = export_pdf(path, pdf, browser, args.theme)
        print(f"Wrote {pdf} ({pdf.stat().st_size / 1024:,.0f} KB, {pages} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
