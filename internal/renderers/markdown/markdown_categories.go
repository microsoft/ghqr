// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"sort"
	"strings"
)

// generateFindingsByCategory groups all findings by category and renders them.
func generateFindingsByCategory(allFindings []entityFindings) string {
	// Group by category.
	type catFinding struct {
		Entity string
		Rec    recommendation
	}
	grouped := map[string][]catFinding{}
	for _, ef := range allFindings {
		for _, r := range ef.Findings {
			grouped[r.Category] = append(grouped[r.Category], catFinding{
				Entity: ef.EntityName,
				Rec:    r,
			})
		}
	}

	// Sort categories by highest severity finding.
	cats := make([]string, 0, len(grouped))
	for cat := range grouped {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		minI, minJ := 99, 99
		for _, f := range grouped[cats[i]] {
			if o, ok := severityOrder[f.Rec.Severity]; ok && o < minI {
				minI = o
			}
		}
		for _, f := range grouped[cats[j]] {
			if o, ok := severityOrder[f.Rec.Severity]; ok && o < minJ {
				minJ = o
			}
		}
		if minI != minJ {
			return minI < minJ
		}
		return cats[i] < cats[j]
	})

	var sb strings.Builder
	for _, cat := range cats {
		findings := grouped[cat]
		displayName := categoryDisplayNames[cat]
		if displayName == "" {
			displayName = cat
		}

		// Determine overall risk level for category.
		highestSev := "info"
		for _, f := range findings {
			if severityOrder[f.Rec.Severity] < severityOrder[highestSev] {
				highestSev = f.Rec.Severity
			}
		}

		// Collect affected entities.
		entitySet := map[string]bool{}
		for _, f := range findings {
			entitySet[f.Entity] = true
		}
		entities := make([]string, 0, len(entitySet))
		for e := range entitySet {
			entities = append(entities, e)
		}
		sort.Strings(entities)

		sb.WriteString(fmt.Sprintf("### %s\n\n", displayName))
		sb.WriteString(fmt.Sprintf("**Risk Level:** %s %s\n", severityEmoji[highestSev], titleCase(highestSev)))
		sb.WriteString(fmt.Sprintf("**Affected Entities:** %s\n\n", strings.Join(entities, ", ")))

		sb.WriteString("#### Findings\n\n")
		sb.WriteString("| Severity | Entity | Finding | Action | Learn More |\n")
		sb.WriteString("|----------|--------|---------|--------|------------|\n")

		// Sort findings within category by severity.
		sort.Slice(findings, func(i, j int) bool {
			return severityOrder[findings[i].Rec.Severity] < severityOrder[findings[j].Rec.Severity]
		})

		for _, f := range findings {
			learnMore := ""
			if f.Rec.LearnMore != "" {
				learnMore = fmt.Sprintf("[Docs](%s)", f.Rec.LearnMore)
			}
			sb.WriteString(fmt.Sprintf("| %s %s | %s | %s | %s | %s |\n",
				severityEmoji[f.Rec.Severity], titleCase(f.Rec.Severity),
				f.Entity, f.Rec.Issue, f.Rec.Recommendation, learnMore,
			))
		}

		sb.WriteString("\n#### Why This Matters\n\n")
		sb.WriteString(categoryRiskDescription(cat))
		sb.WriteString("\n\n---\n\n")
	}

	return sb.String()
}

// categoryRiskDescription returns a short business risk explanation for each category.
func categoryRiskDescription(category string) string {
	descriptions := map[string]string{
		"security":           "Unaddressed security settings leave repositories exposed to known vulnerabilities and potential data breaches. Enabling automated vulnerability detection is a foundational control that prevents exploitation of publicly disclosed CVEs.",
		"branch_protection":  "Without branch protection, any collaborator can push directly to production branches, bypassing code review and CI checks. This significantly increases the risk of introducing bugs, regressions, or malicious code into production.",
		"access_control":     "Overly permissive access controls expand the attack surface and increase the risk of unauthorized changes. Proper access governance ensures least-privilege principles are applied consistently.",
		"copilot_security":   "Allowing public code suggestions without guardrails can lead to copyright or license compliance issues. Content exclusions ensure sensitive code patterns are not surfaced in AI-generated suggestions.",
		"copilot_cost":       "Unused or over-provisioned Copilot seats represent direct cost waste. Monitoring utilization and reclaiming inactive seats can yield significant monthly savings.",
		"copilot_features":   "Incomplete feature enablement means teams are not getting full value from their Copilot investment. Ensuring all capabilities are enabled maximizes developer productivity.",
		"copilot_models":     "Model policy misconfigurations can lead to unexpected AI behavior or use of unapproved models in sensitive contexts.",
		"copilot_mcp":        "MCP server configuration gaps can affect Copilot's ability to integrate with external tools and services securely.",
		"copilot_extensions": "Extension allowlist gaps may permit untrusted extensions to access code and context, creating potential data exfiltration vectors.",
		"actions":            "Unrestricted GitHub Actions workflows can execute arbitrary third-party code in your CI/CD pipeline, creating a significant supply-chain attack vector. Restricting allowed actions reduces this risk.",
		"community":          "Missing community health files (SECURITY.md, CODEOWNERS, descriptions, topics) reduce discoverability, make vulnerability reporting difficult, and signal a lack of project maturity to stakeholders.",
		"dependencies":       "Unmonitored dependencies can harbor known vulnerabilities that attackers actively exploit. Automated dependency scanning provides early warning of security issues in your supply chain.",
		"permissions":        "Excessive default permissions grant broader access than necessary, violating least-privilege principles and increasing the blast radius of compromised accounts.",
		"deployment":         "Deployments without environment protection rules allow changes to reach production without proper approval gates, increasing the risk of unvetted releases.",
		"maintenance":        "Stale branches and unarchived dormant repositories increase cognitive overhead, expand the attack surface, and may contain outdated dependencies with known vulnerabilities.",
		"risk":               "Publicly visible repositories expose internal code and configurations, potentially leaking sensitive information. Proper visibility controls limit exposure.",
		"features":           "Disabled advanced security features represent missed opportunities for automated vulnerability detection and prevention built into the development workflow.",
	}
	if desc, ok := descriptions[category]; ok {
		return desc
	}
	return "This category contains findings that should be reviewed and addressed to improve the overall security posture."
}
