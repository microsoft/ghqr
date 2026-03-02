// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"sort"
	"strings"

	"github.com/microsoft/ghqr/internal/renderers"
)

// generateManualChecks produces the manual checks table.
func generateManualChecks() string {
	var sb strings.Builder
	sb.WriteString("## Manual Checks Required\n\n")
	sb.WriteString("The following security areas **cannot be verified automatically** via the GitHub\n")
	sb.WriteString("API and require manual review:\n\n")
	sb.WriteString("| Area | What to Check | Where |\n")
	sb.WriteString("|------|--------------|-------|\n")
	sb.WriteString("| Audit log streaming | Connected to SIEM | Enterprise → Settings → Audit log |\n")
	sb.WriteString("| Secret scanning alerts | Open critical alerts reviewed and resolved | Repo → Security → Secret scanning |\n")
	sb.WriteString("| Secret scanning: custom patterns | Org/enterprise-level custom patterns defined | Org → Settings → Code security → Secret scanning |\n")
	sb.WriteString("| Secret scanning: bypass requests | Bypass request reviewers configured for push protection | Org → Settings → Code security → Secret scanning |\n")
	sb.WriteString("| Code scanning: default setup | Default setup enabled on all active repos (no workflow required) | Repo → Settings → Code security → Code scanning |\n")
	sb.WriteString("| Code scanning: alert triage | Open high/critical code scanning alerts reviewed | Repo → Security → Code scanning |\n")
	sb.WriteString("| Code scanning: tool coverage | All relevant languages covered by a scanning tool | Repo → Security → Code scanning |\n")
	sb.WriteString("| Dependency review | dependency-review-action present in PR workflows | Repo → `.github/workflows/` |\n")
	sb.WriteString("| Actions: self-hosted runners | Present on public repos | Repo → Settings → Actions → Runners |\n")
	sb.WriteString("| Branch protection: enforce admins | Enabled | Repo → Settings → Branches |\n")
	sb.WriteString("| Environment protection rules | Reviewers configured | Repo → Settings → Environments |\n")
	sb.WriteString("| SAML SSO enforcement & SCIM | SSO enforced; SCIM provisioning active | Org → Settings → Authentication Security |\n")
	sb.WriteString("| IP Allow List | Configured and enabled | Org → Settings → Authentication Security |\n")
	sb.WriteString("| Org webhooks | SSL verification enabled, shared secret set on all hooks | Org → Settings → Webhooks |\n")
	sb.WriteString("| Org-level rulesets | At least one ruleset defined for repo governance | Org → Settings → Rules → Rulesets |\n")
	sb.WriteString("\n")

	return sb.String()
}

// generateAppendix produces the expandable appendix with all findings per entity.
func generateAppendix(report *renderers.ScanReport) string {
	var sb strings.Builder
	sb.WriteString("## Appendix — Full Issue List\n\n")

	allFindings := collectAllFindings(report)

	for _, ef := range allFindings {
		sb.WriteString(fmt.Sprintf("### %s\n\n", ef.EntityName))
		sb.WriteString("<details>\n")
		sb.WriteString("<summary>Expand all findings</summary>\n\n")
		sb.WriteString("| Severity | Category | Finding | Action | Learn More |\n")
		sb.WriteString("|----------|----------|---------|--------|------------|\n")

		// Sort findings by severity.
		sorted := make([]recommendation, len(ef.Findings))
		copy(sorted, ef.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return severityOrder[sorted[i].Severity] < severityOrder[sorted[j].Severity]
		})

		for _, r := range sorted {
			displayCat := categoryDisplayNames[r.Category]
			if displayCat == "" {
				displayCat = r.Category
			}
			learnMore := ""
			if r.LearnMore != "" {
				learnMore = fmt.Sprintf("[Link](%s)", r.LearnMore)
			}
			sb.WriteString(fmt.Sprintf("| %s %s | %s | %s | %s | %s |\n",
				severityEmoji[r.Severity], titleCase(r.Severity),
				displayCat, r.Issue, r.Recommendation, learnMore,
			))
		}

		sb.WriteString("\n</details>\n\n")
	}

	return sb.String()
}
