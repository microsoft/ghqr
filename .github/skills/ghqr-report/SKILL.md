---
name: ghqr-report
description: Generate an executive assessment report from GitHub Quick Review (ghqr) scan data. Produces an executive summary, a dedicated section per validated subject with all findings, and a prioritized 30/60/90-day remediation plan. Use when the user asks for a report, executive summary, best practices posture overview, or a remediation roadmap from ghqr scan results.
---

# GitHub Quick Review — Executive Report Skill

Expert guidance for transforming ghqr scan JSON output into a structured executive report with findings by category and a prioritized 30/60/90-day remediation plan.

## Overview

This skill enables agents to:
- Trigger a ghqr scan (or consume an existing scan result) for an enterprise, organization, or repository
- Produce a polished executive summary with overall best practices posture and key KPIs
- Generate one dedicated section per validated category with its issues and recommendations
- Build a prioritized remediation roadmap split into 30, 60, and 90-day milestones

## When to Use This Skill

Trigger this skill when the user asks for:
- "Generate a report", "executive report", "best practices report", or "posture report"
- "Remediation plan", "action plan", "30/60/90 plan"
- "What are the findings from the ghqr scan?"
- "Show me the issues and how to fix them"

## Data Sources

The ghqr JSON output contains the following top-level structure:

```json
{
  "generated_at": "<RFC3339 timestamp>",
  "summary": { "total_scanned": N, "non_compliant": N, "by_severity": {} },
  "enterprises": {
    "<slug>": {
      "ghas_settings": {
        "advanced_security": "enabled|disabled|not_set",
        "secret_scanning": "enabled|disabled|not_set",
        "secret_scanning_push_protection": "enabled|disabled|not_set",
        "dependabot_alerts": "enabled|disabled|not_set",
        "dependabot_security_updates": "enabled|disabled|not_set",
        "dependency_graph": "enabled|disabled|not_set",
        "secret_scanning_non_provider_patterns": "enabled|disabled|not_set"
      },
      "evaluation": { "recommendations": [] }
    }
  },
  "organizations": {
    "<name>": {
      "settings": {
        "security": {
          "advanced_security_enabled_for_new_repos": true,
          "secret_scanning_enabled_for_new_repos": true,
          "secret_scanning_push_protection_enabled_for_new_repos": true,
          "dependabot_alerts_enabled_for_new_repos": true,
          "dependabot_security_updates_enabled_for_new_repos": true,
          "dependency_graph_enabled_for_new_repos": true
        }
      },
      "evaluation": { "recommendations": [] }
    }
  },
  "repositories":  { "<owner/name>": { "evaluation": { "recommendations": [] } } }
}
```

Each `evaluation` object contains:
- `recommendations[]`: all findings (both hard issues and advisory items), each with `severity`, `category`, `issue`, `recommendation`, and an optional `learn_more` URL

### Severity Levels
| Severity | Meaning |
|----------|---------|
| `critical` | Immediate risk, must fix now |
| `high`     | Serious gap, fix within 30 days |
| `medium`   | Important improvement, fix within 60 days |
| `low`      | Minor gap, fix within 90 days |
| `info`     | Advisory only |

### Categories Validated by ghqr
| Category | Description |
|----------|-------------|
| `security` | Enterprise GHAS policy defaults; org-wide secret scanning, push protection, and GHAS defaults for new repos; org-level open code scanning and secret scanning alerts |
| `branch_protection` | Branch rules, required reviews, status checks |
| `access_control` | Collaborator permissions, deploy keys, admin access |
| `copilot_security` | Public code suggestions, content exclusions |
| `copilot_cost` | Seat utilization, inactive seats |
| `copilot_features` | IDE chat, CLI, platform chat enablement |
| `copilot_models` | Allowed/blocked model configuration |
| `copilot_mcp` | MCP server policy |
| `copilot_extensions` | Extension allowlist |
| `actions` | Workflow permissions, allowed actions, SHA pinning |
| `community` | SECURITY.md, CODEOWNERS, contributing guidelines |
| `dependencies` | Enterprise/org Dependabot alert defaults for new repos; Dependabot security updates defaults; aggregate open Dependabot alerts by severity |
| `permissions` | Default repo permissions, member privileges |
| `deployment` | Environment protection rules |
| `maintenance` | Stale branches, archived repos, empty repos |
| `risk` | Repository criticality, public visibility |
| `features` | Advanced Security, wiki, issue tracker |

## Workflow

### Phase 1 — Acquire Scan Data

If the user provides a scan result file path or JSON, use it directly. Otherwise:

1. Use the `ghqr_scan` tool to run a new scan:
   - Pass `enterprises`, `organizations`, or `repositories` based on the user's scope
   - The tool returns a file URI pointing to the JSON output
2. Read the JSON output file to load the scan data

### Phase 2 — Build the Report

Produce the full report in Markdown following the **Report Template** below. Populate every section with real data from the scan; never invent findings.

### Phase 3 — Validate Completeness

Before delivering the report, verify:
- [ ] Executive summary reflects actual issue counts
- [ ] Every category with at least one finding has its own section
- [ ] Every issue listed in the scan appears somewhere in the report
- [ ] Each finding in the 30/60/90 plan maps directly to a scan issue or recommendation
- [ ] No findings are duplicated across plan phases

---

## Report Template

```markdown
# GitHub Assessment Report — [Enterprise/Organization/Repository Name]

**Scope:** [Enterprise / Organization / Repository]
**Generated:** [Date]
**Scan Coverage:** [N enterprises / N organizations / N repositories]

---

## Executive Summary

> One paragraph (4–6 sentences) for a non-technical audience. State the overall
> security posture, the number of critical and high findings, the biggest
> risk areas, and the top improvement opportunity.

### Posture Scorecard

| Entity | Type | Critical | High | Medium | Low | Info |
|--------|------|----------|------|--------|-----|------|
| [name] | org  | 0 | 2 | 3 | 1 | 4 |
| [repo] | repo | 1 | 1 | 2 | 0 | 2 |

### Overall Risk Distribution

| Severity | Count | % of Total |
|----------|-------|-----------|
| 🔴 Critical | N | X% |
| 🟠 High     | N | X% |
| 🟡 Medium   | N | X% |
| 🟢 Low      | N | X% |
| ℹ️ Info     | N | X% |

---

## Findings by Subject

<!-- Repeat this block for every category that has at least one issue or recommendation -->

### [Category Display Name]  <!-- e.g. "Security — Dependabot & Code Scanning" -->

**Risk Level:** [Critical / High / Medium / Low]  
**Affected Entities:** [list of org/repo names]

#### Findings

| Severity | Entity | Finding | Action | Learn More |
|----------|--------|---------|--------|------------|
| 🔴 Critical | org/repo | [issue text from scan] | [recommendation text] | [link from `learn_more`] |
| 🟠 High     | org/repo | [issue text] | [recommendation text] | [link from `learn_more`] |

#### Why This Matters

[2–3 sentences explaining the business/security risk of this category in plain language]

---

<!-- Categories with zero findings are omitted -->

---

## Remediation Plan

### 30-Day Sprint — Immediate Actions 🔴

> Address all **critical** and **high** severity issues. These represent the
> highest risk to your organization and should be resolved within the first month.

| Priority | Entity | Action | Category | Effort | Owner |
|----------|--------|--------|----------|--------|-------|
| 1 | [entity] | [specific fix] | [category] | [S/M/L] | [team] |
| 2 | [entity] | [specific fix] | [category] | [S/M/L] | [team] |

**Expected outcome:** [Risk reduction summary]

---

### 60-Day Sprint — High-Priority Improvements 🟠

> Address all **medium** severity issues and any high-effort critical/high fixes
> that couldn't be completed in the 30-day sprint.

| Priority | Entity | Action | Category | Effort | Owner |
|----------|--------|--------|----------|--------|-------|
| 1 | [entity] | [specific fix] | [category] | [S/M/L] | [team] |

**Expected outcome:** [Risk reduction summary]

---

### 90-Day Sprint — Strategic Hardening 🟡

> Address all **low** severity issues, implement process improvements, and
> establish ongoing governance controls.

| Priority | Entity | Action | Category | Effort | Owner |
|----------|--------|--------|----------|--------|-------|
| 1 | [entity] | [specific fix] | [category] | [S/M/L] | [team] |

**Expected outcome:** [Risk reduction summary]

---

## Manual Checks Required

The following security areas **cannot be verified automatically** via the GitHub
API and require manual review:

| Area | What to Check | Where |
|------|--------------|-------|
| Audit log streaming | Connected to SIEM | Enterprise → Settings → Audit log |
| Secret scanning alerts | Open critical alerts reviewed and resolved | Repo → Security → Secret scanning |
| Secret scanning: custom patterns | Org/enterprise-level custom patterns defined | Org → Settings → Code security → Secret scanning |
| Secret scanning: bypass requests | Bypass request reviewers configured for push protection | Org → Settings → Code security → Secret scanning |
| Code scanning: default setup | Default setup enabled on all active repos (no workflow required) | Repo → Settings → Code security → Code scanning |
| Code scanning: alert triage | Open high/critical code scanning alerts reviewed | Repo → Security → Code scanning |
| Code scanning: tool coverage | All relevant languages covered by a scanning tool | Repo → Security → Code scanning |
| Dependency review | dependency-review-action present in PR workflows | Repo → `.github/workflows/` |
| Actions: self-hosted runners | Present on public repos | Repo → Settings → Actions → Runners |
| Branch protection: enforce admins | Enabled | Repo → Settings → Branches |
| Environment protection rules | Reviewers configured | Repo → Settings → Environments |
| SAML SSO enforcement & SCIM | SSO enforced; SCIM provisioning active | Org → Settings → Authentication Security |
| IP Allow List | Configured and enabled | Org → Settings → Authentication Security |
| Org webhooks | SSL verification enabled, shared secret set on all hooks | Org → Settings → Webhooks |
| Org-level rulesets | At least one ruleset defined for repo governance | Org → Settings → Rules → Rulesets |

---

## Appendix — Full Issue List

### [Entity Name]

<details>
<summary>Expand all findings</summary>

| Severity | Category | Finding | Action | Learn More |
|----------|----------|---------|--------|------------|
| [sev] | [cat] | [issue] | [recommendation] | [learn_more URL as hyperlink, or blank if empty] |

</details>
```

---

## Category Display Name Mapping

When rendering category names in the report use these human-readable titles:

| Raw category | Display name |
|--------------|-------------|
| `security` | Security — Vulnerability Management |
| `branch_protection` | Branch Protection |
| `access_control` | Access Control & Permissions |
| `copilot_security` | GitHub Copilot — Security & Compliance |
| `copilot_cost` | GitHub Copilot — Cost & Seat Utilization |
| `copilot_features` | GitHub Copilot — Feature Enablement |
| `copilot_models` | GitHub Copilot — Model Policy |
| `copilot_mcp` | GitHub Copilot — MCP Configuration |
| `copilot_extensions` | GitHub Copilot — Extensions |
| `actions` | GitHub Actions — Workflow Security |
| `community` | Community Health & Documentation |
| `dependencies` | Dependency Management |
| `permissions` | Member & Repository Permissions |
| `deployment` | Deployment & Environment Controls |
| `maintenance` | Repository Maintenance |
| `risk` | Visibility & Risk Exposure |
| `features` | Advanced Security Features |

## Effort Sizing Guide

When populating the **Effort** column in the plan tables:

| Label | Definition |
|-------|-----------|
| S — Small | Single setting toggle or one-click configuration; < 1 hour |
| M — Medium | Requires creating a file, policy, or workflow; 1–4 hours |
| L — Large | Requires team coordination, design decision, or phased rollout; 1+ days |

## Output Requirements

The agent MUST:
1. **Always use real scan data** — never fabricate issues
2. **Include every category** that has at least one finding; skip categories with zero findings
3. **Map every finding to exactly one plan phase** based on its severity:
   - `critical` + `high` → 30-day sprint
   - `medium` → 60-day sprint
   - `low` + `info` → 90-day sprint
4. **Estimate effort** using S/M/L sizing for each action item
5. **List manual checks** that ghqr cannot automate (reference `references/MANUAL_CHECKS.md` categories)
