# Public release checklist

Complete this checklist for the exact commit being published. Automated checks
are evidence, not proof that all personal data or security issues are absent.

## Before the first commit or push

- [ ] Confirm permission to publish every part of the code, including any code
  created for an employer or customer. Follow the repository's MIT licence and
  retain its notices when redistributing the dashboard.
- [ ] Keep the application under `dashboard`. Preserve the existing repository
  policies, PR template, and CLI workflows; do not copy standalone repository
  templates over them. Run dashboard commands from the `dashboard` directory.
- [ ] Remove real reports, exports, backups, personal paths, customer identifiers,
  credentials, and identifying filenames. Review all source and attachments,
  including screenshots, manually.
- [ ] Optionally set `GHQR_PRIVATE_TERMS` locally to newline-separated private
  identifiers. Do not commit the values or put them in PR descriptions.
- [ ] Run `python build.py` with no report argument. Do not stage a private build.
- [ ] Review the entire index with `git diff --cached --name-status` and
  `git diff --cached`. Confirm the intended commit contains only application
  files and synthetic tests.
- [ ] Install a supported Node.js release, Python 3.10 or later, Git, and Gitleaks
  8.30.1 or later. Run `python -B -m scripts.check_release` from `dashboard`.
  Fetch full history first if the clone is shallow.
- [ ] Review all refs that will be pushed. The history scan covers locally
  available refs, not inaccessible remote history. Ignore rules do not erase
  previously committed data. Rotate exposed credentials and coordinate cleanup
  before pushing; do not rely on deleting the current file.

## Browser and export checks

Use synthetic reports only. Record the browser, platform, and result in the PR.
Check at least a Chromium browser and Firefox; include Safari if supporting it.

- [ ] Open the standalone HTML and, if applicable, the intended hosted version.
  Both start blank, with report-only actions hidden.
- [ ] Choose a report and drag and drop a report. All eight sections, filters,
  organisation/repository details, and report replacement work.
- [ ] Invalid JSON and non-report JSON display an error without corrupting the
  current report. Cancelling file selection leaves the app usable.
- [ ] Unload clears report details and returns to the upload screen. Reuploading
  the same file works. Reload starts empty.
- [ ] The malicious-name regression displays markup as text, never executable
  elements. Browser console and application network activity show no unexpected
  errors or report uploads; report content is not persisted in browser storage.
- [ ] Keyboard focus, visible focus indication, drawer close/Escape, navigation,
  theme contrast, narrow screens, and presentation mode are usable.
- [ ] CSV opens with correct comma-delimited field boundaries and guarded formula
  prefixes. Import it explicitly as comma-delimited text, not semicolon-delimited.
  Test supported spreadsheet applications; their formula evaluation is not
  established by the automated Node checks.
- [ ] PDF export is readable, includes all sections/findings, and contains only
  synthetic data. Report-bearing builder outputs go outside the repository
  checkout; the builder rejects internal HTML/PDF outputs.

## Before opening or merging the PR

- [ ] Follow `CONTRIBUTING.md` and the existing PR template at the repository root.
  Reference the issue discussed with maintainers, complete any CLA-bot request,
  include exact commands/results, and disclose checks that were not run.
- [ ] Confirm fork access and any required organization SSO authorization.
  GitHub push permission does not establish ownership or legal release approval.
- [ ] Enable Actions and code scanning as appropriate in the fork. The dashboard
  uses the repository's existing advanced CodeQL workflow; do not add a competing
  default-setup or standalone CodeQL workflow.
- [ ] Request `Dashboard preflight` and the CodeQL language checks in the
  target branch ruleset after they first run. A successful CodeQL job does not
  itself mean there are no alerts: review the code-scanning results and configure
  the destination repo's alert/merge policy.
- [ ] Review required approvals and secret-scanning/push-protection settings.
  CI runs after a push, so it cannot replace the local pre-push review.
- [ ] Re-run the gates after fixes and verify the final staged/committed public
  HTML remains blank. Use only synthetic screenshots in the PR.

## Standalone folder checks

Before the folder is in Git, run:

```shell
python -B -m scripts.check_release --files-only
```

This explicitly omits index/history checks and is not full release sign-off.
The checker supports `--node` and `--gitleaks` for explicit executable paths.
Full mode scopes content/index checks to `dashboard`, while Gitleaks scans
repository working files and all locally available history for secrets.
It does not install dependencies, stage files, commit, push, or run real reports.
Missing tools or failed checks produce a nonzero exit.
