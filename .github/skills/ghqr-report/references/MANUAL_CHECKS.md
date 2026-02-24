# Manual Recommendations

This document lists recommendations that require manual review via the GitHub UI. They are not covered by automated scanning due to API limitations or data availability constraints.

---

## Batch Scan Limitations

When running org-wide or enterprise scans, the following recommendations are partially evaluated due to query complexity constraints. For full results, run a single-repository scan.

| Recommendation | Org/Enterprise Scan Behavior | How to Get Full Results |
|---|---|---|
| Open Dependabot alerts (critical/high/medium) | Not reported; alert enablement is still checked | Single-repository scan or GitHub UI |
| Collaborators with admin access (> 3 admins) | Evaluated as no collaborators — info only | Single-repository scan or Organization → Settings → Collaborators and teams |
| Write-enabled or unverified deploy keys | Evaluated as no deploy keys — info only | Single-repository scan or Repository → Settings → Deploy keys |

---

## GitHub Copilot

Seat management policy, public code suggestions, and seat utilization are evaluated automatically. The following settings require manual review:

| Recommendation | Where to Verify |
|---|---|
| IDE Chat, Platform Chat, and CLI features enabled/disabled | Organization → Settings → Copilot → Policies |
| Allowed/excluded AI models | Organization → Settings → Copilot → Policies |
| MCP (Model Context Protocol) enabled | Organization → Settings → Copilot → Policies |
| Copilot Extensions enabled; allowed/blocked extensions | Organization → Settings → Copilot → Policies |
| Default model and excluded MCPs (Enterprise policy) | Enterprise → Settings → Copilot |
| Seat count and assignment | Organization → Settings → Copilot → Seat Management |

---

## Organization Identity & Access Management

Org-wide security defaults for new repositories (Dependabot alerts/updates, secret scanning, push protection, advanced security, dependency graph) are evaluated automatically. The following settings require manual review:

| Recommendation | Where to Verify |
|---|---|
| SAML SSO enabled and enforced | Organization → Settings → Authentication Security |
| IP Allow List enabled and configured | Organization → Settings → Authentication Security → IP allow list |
| Enterprise Managed Users (EMU) in use | Organization → Settings → Authentication Security |
| SSH Certificate Authority configured | Organization → Settings → SSH Certificate Authorities |
| PAT policy restricted (token lifetime, SSO requirement) | Organization → Settings → Developer Settings → Personal access tokens |

---

## GitHub Apps

App installation details — including permissions and repository scope — require an org admin token to retrieve and are not available through standard scans.

| Recommendation | Where to Verify |
|---|---|
| Apps with write access to Administration, Actions, or Secrets | Organization → Settings → GitHub Apps |
| Apps with access to all repositories (should be scoped) | Organization → Settings → GitHub Apps |
| Regular audit of installed apps and their permissions | Organization → Settings → GitHub Apps → Review |

---

## Enterprise Audit Log

Suspicious events (`repo.destroy`, `org.remove_member`, `oauth_access.revoke`) are detected automatically from recent audit log entries. The following require manual verification:

| Recommendation | Where to Verify |
|---|---|
| Audit log streaming enabled | Enterprise → Settings → Audit log → Audit log streaming |
| Streaming targets configured (e.g., SIEM, Splunk, S3) | Enterprise → Settings → Audit log → Audit log streaming |
| Regular audit log reviews scheduled | Enterprise → Settings → Audit log |

---

## Secret Scanning

| Recommendation | Where to Verify |
|---|---|
| Secret scanning enabled | Repository → Settings → Security → Code security and analysis |
| Open secret scanning alerts (**CRITICAL** — rotate exposed secrets immediately) | Repository → Security → Secret scanning |
| Secret scanning push protection enabled | Repository → Settings → Security → Code security and analysis |

---

## Code Scanning (SAST)

| Recommendation | Where to Verify |
|---|---|
| Code scanning enabled | Repository → Settings → Security → Code security and analysis |
| Open code scanning alerts | Repository → Security → Code scanning |
| CodeQL analysis running on push/PR | Repository → Actions → CodeQL workflows |

---

## Dependabot Security Updates

| Recommendation | Where to Verify |
|---|---|
| Dependabot security updates enabled | Repository → Settings → Security → Code security and analysis |

---

## Private Vulnerability Reporting

| Recommendation | Where to Verify |
|---|---|
| Private vulnerability reporting enabled | Repository → Settings → Security → Private vulnerability reporting |

---

## GitHub Pages

| Recommendation | Where to Verify |
|---|---|
| HTTPS enforced for Pages site | Repository → Settings → Pages |
| Pages source branch is protected | Repository → Settings → Pages (verify against branch protection rules) |

---

## GitHub Actions Security

| Recommendation | Where to Verify |
|---|---|
| Default workflow permissions set to read-only | Repository → Settings → Actions → General → Workflow permissions |
| Workflows cannot approve pull requests | Repository → Settings → Actions → General → Workflow permissions |
| Self-hosted runners present (security risk for public repos) | Repository → Settings → Actions → Runners |
| Runner groups restricted to specific repos/workflows | Organization → Settings → Actions → Runner groups |
| Fork pull request workflows require approval | Repository → Settings → Actions → General → Fork pull request workflows |

---

## Branch Protection

The following branch protection settings are not covered by automated scanning:

| Recommendation | Where to Verify |
|---|---|
| Enforce admins (branch protection applies to administrators) | Repository → Settings → Branches → Branch protection rule |
| Required conversation resolution before merge | Repository → Settings → Branches → Branch protection rule |
| Lock branch (make branch read-only) | Repository → Settings → Branches → Branch protection rule |

---

## Stale Access Detection

| Recommendation | Where to Verify |
|---|---|
| Collaborators with no activity in 90+ days | Repository → Settings → Collaborators and teams (review login dates) |
| Deploy keys not rotated in 90+ days | Repository → Settings → Deploy keys (review Created date) |

---

## Security Metrics (MTTR)

| Recommendation | Where to Verify |
|---|---|
| Average time to remediate Dependabot alerts | Repository → Security → Dependabot (check age of alerts) |
| Average time to remediate code scanning alerts | Repository → Security → Code scanning (check alert age) |
| Percentage of alerts fixed vs dismissed | Repository → Security → Insights |

---

## Environment Protection Rules

| Recommendation | Where to Verify |
|---|---|
| Required reviewers configured for production environments | Repository → Settings → Environments |
| Wait timer configured for critical deployments | Repository → Settings → Environments |
| Prevent self-review enabled for regulated deployments | Repository → Settings → Environments |
| Deployment branch policies configured | Repository → Settings → Environments |

---

## Repository Criticality

| Recommendation | Where to Verify |
|---|---|
| High-traffic or critical repositories have additional controls | Repository → Insights → Traffic |
| Template repositories have enhanced protection | Repository → Settings → General (Is Template) |
