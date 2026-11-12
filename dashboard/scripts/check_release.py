"""Check the blank public dashboard, tests, sensitive data, and Git publication boundary."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
PRIVATE_SUFFIXES = {".json", ".csv", ".pdf", ".zip", ".bak", ".log", ".pem", ".key"}
PERSONAL_DATA = (
    ("email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("personal filesystem path", re.compile(r"(?:[A-Z]:[\\/]+Users[\\/]+[^\\/\s\"'<>]+|/(?:Users|home)/[^/\s\"'<>]+)", re.I)),
)


class ReleaseCheckError(Exception):
    pass


def check_content(name: str, data: bytes, private_terms: tuple[str, ...] = ()) -> None:
    if any(term.casefold() in name.casefold() for term in private_terms):
        raise ReleaseCheckError("A filename contains a private identifier; rename it before publishing.")
    path = Path(name)
    if path.suffix.lower() in PRIVATE_SUFFIXES:
        raise ReleaseCheckError(f"Remove report/export/credential file from the application: {name}")
    if path.suffix.lower() == ".html" and name not in ("ghqr-dashboard.html", str(Path("src") / "index.html")):
        raise ReleaseCheckError(f"Unexpected HTML artifact requires review: {name}")
    if b"\0" in data:
        raise ReleaseCheckError(f"Binary file requires manual public-data review: {name}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ReleaseCheckError(f"Non-UTF-8 file requires manual public-data review: {name}") from err
    for line_number, line in enumerate(text.splitlines(), 1):
        for label, pattern in PERSONAL_DATA:
            if pattern.search(line):
                raise ReleaseCheckError(f"Possible {label} in {name}:{line_number}; matched data is not printed.")
        if any(term.casefold() in line.casefold() for term in private_terms):
            raise ReleaseCheckError(f"Private identifier in {name}:{line_number}; matched data is not printed.")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict) and any(key in value for key in ("enterprises", "organizations", "repositories")):
        raise ReleaseCheckError(f"Report data found in {name}.")


def check_files(root: Path, private_terms: tuple[str, ...] = ()) -> None:
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        for name in [*dirs, *files]:
            path = Path(directory) / name
            if path.name == ".git":
                continue
            if path.is_symlink():
                raise ReleaseCheckError("Symlinks require manual review before sharing the application folder.")
            if path.is_file():
                check_content(str(path.relative_to(root)), path.read_bytes(), private_terms)
                count += 1
    print(f"PASS: {count} application files checked for report artifacts and common personal-data patterns.", flush=True)


def run(command: list[str], *, cwd: Path = ROOT, input_data: bytes | None = None) -> None:
    result = subprocess.run(command, cwd=cwd, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.stdout:
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
    result.check_returncode()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--no-pager", "-C", str(root), *args], stderr=subprocess.PIPE)


def check_git(root: Path, private_terms: tuple[str, ...]) -> bytes:
    try:
        git(root, "rev-parse", "--show-toplevel")
    except subprocess.CalledProcessError as err:
        raise ReleaseCheckError("No Git checkout. Use --files-only here; run the full check in the destination checkout before pushing.") from err
    if git(root, "rev-parse", "--is-shallow-repository").strip() == b"true":
        raise ReleaseCheckError("History is shallow. Fetch full history before the publication scan.")
    if git(root, "ls-files", "--others", "--exclude-standard", "-z", "--", "."):
        raise ReleaseCheckError("Untracked application files are not in the intended commit. Review and stage them before full preflight.")
    run(["git", "--no-pager", "diff", "--check", "--", "."], cwd=root)
    run(["git", "--no-pager", "diff", "--cached", "--check", "--", "."], cwd=root)
    for entry in git(root, "ls-files", "--stage", "-z", "--", ".").split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.split()
        if stage != b"0" or mode == b"120000" or mode == b"160000":
            raise ReleaseCheckError("Resolve index conflicts and review symlinks/submodules before publishing.")
        name = os.fsdecode(raw_name).replace("/", os.sep)
        data = git(root, "cat-file", "blob", object_id.decode("ascii"))
        check_content(name, data, private_terms)
        working = root / name
        if not working.is_file() or working.read_bytes().replace(b"\r\n", b"\n") != data.replace(b"\r\n", b"\n"):
            raise ReleaseCheckError(f"Index differs from tested working content: {name}. Review and stage the intended version.")
    print("PASS: staged/index contents and Git whitespace checks.", flush=True)
    return git(root, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary", "--", ".")


def check_blank_build(root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="ghqr-blank-check-") as directory:
        expected = Path(directory) / "ghqr-dashboard.html"
        run([sys.executable, "-B", str(root / "build.py"), "--output", str(expected)], cwd=root)
        actual = root / "ghqr-dashboard.html"
        if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
            raise ReleaseCheckError("Public HTML is stale or report-bearing. Run python build.py without a report, then review and stage the result.")
        page = actual.read_text(encoding="utf-8")
        if '<script id="ghqr-data" type="application/json">null</script>' not in page or "data-source=" in page:
            raise ReleaseCheckError("Public HTML must contain only a null report payload and no report filename.")
    print("PASS: public HTML is byte-identical to a fresh blank build.", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files-only", action="store_true", help="Check a standalone folder; explicitly omit staged/history checks.")
    parser.add_argument("--node", default="node", help="Node.js executable (default: node).")
    parser.add_argument("--gitleaks", default="gitleaks", help="Gitleaks 8.30.1 or later executable (default: gitleaks).")
    args = parser.parse_args(argv)
    private_terms = tuple(term.strip() for term in os.environ.get("GHQR_PRIVATE_TERMS", "").splitlines() if term.strip())
    scanner = [args.gitleaks, "--redact", "--no-banner", "--no-color", "--log-level", "warn", "--ignore-gitleaks-allow"]
    try:
        check_files(ROOT, private_terms)
        staged = None if args.files_only else check_git(ROOT, private_terms)
        repository = ROOT if args.files_only else Path(os.fsdecode(git(ROOT, "rev-parse", "--show-toplevel")).strip()).resolve()
        run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"])
        tests = sorted((ROOT / "tests").glob("*.test.js"))
        if not tests:
            raise ReleaseCheckError("No JavaScript regression tests found.")
        run([args.node, "--test", *map(str, tests)])
        check_blank_build(ROOT)
        run([*scanner, "dir", str(repository)])
        print("PASS: Gitleaks scan of working files.", flush=True)
        if staged:
            run([*scanner, "stdin"], input_data=staged)
            print("PASS: Gitleaks scan of staged changes.", flush=True)
        if not args.files_only:
            if int(git(ROOT, "rev-list", "--all", "--count")):
                run([*scanner, "git", "--log-opts=--all --full-history", str(repository)])
                print("PASS: Gitleaks scan of all locally available Git history.", flush=True)
            else:
                print("NOTE: no commits exist yet; working files and the index were checked.", flush=True)
    except (ReleaseCheckError, OSError, subprocess.CalledProcessError) as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    if args.files_only:
        print("FILES-ONLY CHECK PASSED. Git index/history were NOT checked; full preflight is required in the destination checkout.")
    else:
        print("AUTOMATED PREFLIGHT PASSED. Complete the manual release checklist before publishing.")
    if not private_terms:
        print("NOTE: no project-specific deny terms supplied. Common-pattern checks do not prove the absence of all personal/customer data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
