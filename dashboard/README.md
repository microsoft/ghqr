# GHQR dashboard

A self-contained, offline dashboard for GitHub Quick Review (GHQR) JSON reports.
The app starts empty and contains no sample or embedded report.

The repository's [MIT licence](../LICENSE) applies. Contributions follow
[CONTRIBUTING.md](../CONTRIBUTING.md), including the Microsoft CLA process.
The commands below run from the `dashboard` directory.

## Use

Open `ghqr-dashboard.html` in a current web browser. Choose or drag and drop a GHQR
JSON report, then select **Unload report** to clear it and return to the upload
screen.

Uploaded reports are processed in page memory, not saved by the app or sent to a
server. Reloading the page starts empty. Only the selected colour theme is saved
in browser storage.

## Build

Requires Python 3.10 or later, with no additional packages:

```shell
python build.py
```

This combines `src/index.html`, `src/css/`, and `src/js/` into a blank,
self-contained `ghqr-dashboard.html`.

For public distribution, build without a report argument. Private report
embedding requires an explicit `--output` outside the repository checkout; HTML
and PDF exports inside the checkout are rejected. For copies without Git metadata,
the boundary is the application folder. See `python build.py --help`.

## Security regression checks

With a supported Node.js release installed, run the focused tests using only
synthetic report data:

```shell
node --test tests\security.test.js
```

Node.js is not needed to build or use the dashboard.

## Release checks

Follow [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) before committing or opening a
public PR. With Python, Git, a supported Node.js release, and Gitleaks 8.30.1 or later
installed, check the dashboard working files:

```shell
python -B -m scripts.check_release --files-only
```

After reviewing and staging the intended dashboard files in this checkout, run
the full check from the same directory:

```shell
python -B -m scripts.check_release
```

The command runs Python and JavaScript regressions, verifies that the distributable
exactly matches a blank build, rejects report/export files and common personal-data
patterns, and runs Gitleaks with redacted output. Full mode also checks dashboard
whitespace and index contents, and scans the repository's working files
and all locally available Git history for secrets. Existing repository licence
notices and contributor metadata outside `dashboard` are not subjected to the
dashboard's personal-data pattern checks. Set optional
`GHQR_PRIVATE_TERMS` locally to newline-separated private identifiers; matches
are reported without printing their values. These checks do not establish that
all personal data is absent.

Full preflight rejects untracked application files and staged versions that differ
from the working files being tested. It never silently stages or rewrites them.

GitHub Actions runs `Dashboard preflight` on pushes and PRs to the repository's
main and release branches. The existing CodeQL workflow analyzes Go, Python, and
JavaScript/TypeScript. Actions are pinned to commit SHAs, the scanner download is
checksum-verified, and checkout credentials are not persisted. No report artifacts
are uploaded. Configure the destination repository's required checks and review
CodeQL alerts separately; see the checklist for manual sign-offs.

## Publishing

Keep real reports, report-derived screenshots, and data-bearing exports out of
the contribution. Retain the repository's MIT licence when redistributing the
dashboard.

The ignore rules exclude JSON reports, CSV and PDF exports, other root-level HTML
outputs, and Python cache files. The blank `ghqr-dashboard.html` and source files
remain publishable. Do not replace the publishable HTML with a report-embedded
export. Review staged files before pushing; ignore rules do not remove files
already committed.
