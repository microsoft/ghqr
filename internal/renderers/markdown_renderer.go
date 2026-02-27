// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package renderers

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// categoryDisplayNames maps raw category keys to human-readable titles.
var categoryDisplayNames = map[string]string{
	"security":           "Security — Vulnerability Management",
	"branch_protection":  "Branch Protection",
	"access_control":     "Access Control & Permissions",
	"copilot_security":   "GitHub Copilot — Security & Compliance",
	"copilot_cost":       "GitHub Copilot — Cost & Seat Utilization",
	"copilot_features":   "GitHub Copilot — Feature Enablement",
	"copilot_models":     "GitHub Copilot — Model Policy",
	"copilot_mcp":        "GitHub Copilot — MCP Configuration",
	"copilot_extensions": "GitHub Copilot — Extensions",
	"actions":            "GitHub Actions — Workflow Security",
	"community":          "Community Health & Documentation",
	"dependencies":       "Dependency Management",
	"permissions":        "Member & Repository Permissions",
	"deployment":         "Deployment & Environment Controls",
	"maintenance":        "Repository Maintenance",
	"risk":               "Visibility & Risk Exposure",
	"features":           "Advanced Security Features",
}

// severityEmoji maps severity levels to their display emoji.
var severityEmoji = map[string]string{
	"critical": "🔴",
	"high":     "🟠",
	"medium":   "🟡",
	"low":      "🟢",
	"info":     "ℹ️",
}

// severityOrder defines the sort order for severity levels (lower = higher priority).
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// recommendation represents a single finding from the scan.
type recommendation struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
	LearnMore      string `json:"learn_more,omitempty"`
}

// entityFindings groups findings by entity for report generation.
type entityFindings struct {
	EntityName string
	EntityType string // "enterprise", "org", "repo"
	Findings   []recommendation
}

// planItem represents a single action item in the remediation plan.
type planItem struct {
	Entity   string
	Rec      recommendation
	Priority int
}

// RenderMarkdown produces a Markdown executive report from the scan results map
// following the ghqr-report skill template.
func RenderMarkdown(results map[string]interface{}, outputName string) (string, error) {
	report := buildScanReport(results)
	return renderMarkdownReport(report, outputName)
}

// RenderMarkdownFromJSONFile reads an existing ghqr JSON report and produces
// a Markdown executive report in the same directory.
func RenderMarkdownFromJSONFile(jsonPath string, outputName string) (string, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return "", fmt.Errorf("failed to read JSON file: %w", err)
	}

	var report ScanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return "", fmt.Errorf("failed to parse JSON report: %w", err)
	}

	return renderMarkdownReport(&report, outputName)
}

// renderMarkdownReport renders a ScanReport to a markdown file.
func renderMarkdownReport(report *ScanReport, outputName string) (string, error) {
	md := generateMarkdown(report)

	filename := outputName
	if filename == "" {
		filename = fmt.Sprintf("ghqr_report_%s", time.Now().Format("20060102_150405"))
	}
	outPath := filename + ".md"

	if err := os.WriteFile(outPath, []byte(md), 0600); err != nil {
		return "", fmt.Errorf("failed to write markdown report: %w", err)
	}

	return outPath, nil
}

// buildScanReport constructs the internal ScanReport from raw results,
// reusing the same logic as the JSON renderer.
func buildScanReport(results map[string]interface{}) *ScanReport {
	report := &ScanReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Enterprises:   make(map[string]interface{}),
		Organizations: make(map[string]interface{}),
		Repositories:  make(map[string]interface{}),
	}

	for key, data := range results {
		switch {
		case strings.HasPrefix(key, "enterprise:"):
			report.Enterprises[strings.TrimPrefix(key, "enterprise:")] = data
		case strings.HasPrefix(key, "organization:"):
			report.Organizations[strings.TrimPrefix(key, "organization:")] = data
		case strings.HasPrefix(key, "repository:"):
			report.Repositories[strings.TrimPrefix(key, "repository:")] = data
		}
	}

	// Embed evaluation results into their parent entity.
	type evalMapping struct {
		prefix    string
		field     string
		targetMap map[string]interface{}
	}
	mappings := []evalMapping{
		{"evaluation:organization:", "evaluation", report.Organizations},
		{"evaluation:copilot:", "copilot_evaluation", report.Organizations},
		{"evaluation:repository:", "evaluation", report.Repositories},
		{"evaluation:actions_permissions:", "actions_permissions_evaluation", report.Organizations},
		{"evaluation:org_security_alerts:", "org_security_alerts_evaluation", report.Organizations},
		{"evaluation:security_managers:", "security_managers_evaluation", report.Organizations},
		{"evaluation:enterprise_security_alerts:", "enterprise_security_alerts_evaluation", report.Enterprises},
		{"evaluation:metadata:", "metadata_evaluation", report.Repositories},
	}
	for key, eval := range results {
		for _, m := range mappings {
			if !strings.HasPrefix(key, m.prefix) {
				continue
			}
			name := strings.TrimPrefix(key, m.prefix)
			if entityMap := asMap(m.targetMap[name]); entityMap != nil {
				entityMap[m.field] = eval
				m.targetMap[name] = entityMap
			}
			break
		}
	}

	return report
}

// generateMarkdown renders the full markdown document from a ScanReport.
func generateMarkdown(report *ScanReport) string {
	allFindings := collectAllFindings(report)
	severityCounts := countBySeverity(allFindings)

	// Count total individual findings across all entities.
	totalFindings := 0
	for _, ef := range allFindings {
		totalFindings += len(ef.Findings)
	}

	// Determine the scope name.
	scopeName, scopeType := determineScopeName(report)

	var sb strings.Builder

	// === Header ===
	sb.WriteString(fmt.Sprintf("# GitHub Assessment Report — %s\n\n", scopeName))
	sb.WriteString(fmt.Sprintf("**Scope:** %s\n", scopeType))
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().Format("January 2, 2006")))
	sb.WriteString(fmt.Sprintf("**Scan Coverage:** %d enterprises / %d organizations / %d repositories\n\n",
		len(report.Enterprises), len(report.Organizations), len(report.Repositories)))
	sb.WriteString("---\n\n")

	// === Executive Summary ===
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(generateExecutiveSummaryText(report, severityCounts, totalFindings))
	sb.WriteString("\n\n")

	// === Posture Scorecard ===
	sb.WriteString("### Posture Scorecard\n\n")
	sb.WriteString(generatePostureScorecard(report))
	sb.WriteString("\n")

	// === Overall Risk Distribution ===
	sb.WriteString("### Overall Risk Distribution\n\n")
	sb.WriteString(generateRiskDistribution(severityCounts, totalFindings))
	sb.WriteString("\n---\n\n")

	// === Findings by Subject ===
	sb.WriteString("## Findings by Subject\n\n")
	sb.WriteString(generateFindingsByCategory(allFindings))
	sb.WriteString("---\n\n")

	// === Remediation Plan ===
	sb.WriteString("## Remediation Plan\n\n")
	sb.WriteString(generateRemediationPlan(allFindings))
	sb.WriteString("---\n\n")

	// === Manual Checks ===
	sb.WriteString(generateManualChecks())
	sb.WriteString("---\n\n")

	// === Appendix ===
	sb.WriteString(generateAppendix(report))

	return sb.String()
}

// collectAllFindings extracts every recommendation from all entities.
func collectAllFindings(report *ScanReport) []entityFindings {
	var all []entityFindings

	// Enterprise findings
	for name, data := range report.Enterprises {
		ef := entityFindings{EntityName: name, EntityType: "enterprise"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "enterprise_security_alerts_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Organization findings
	for name, data := range report.Organizations {
		ef := entityFindings{EntityName: name, EntityType: "org"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "copilot_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "actions_permissions_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "org_security_alerts_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "security_managers_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Repository findings
	for name, data := range report.Repositories {
		ef := entityFindings{EntityName: name, EntityType: "repo"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "metadata_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Sort: enterprises first, then orgs, then repos
	sort.Slice(all, func(i, j int) bool {
		typeOrder := map[string]int{"enterprise": 0, "org": 1, "repo": 2}
		if typeOrder[all[i].EntityType] != typeOrder[all[j].EntityType] {
			return typeOrder[all[i].EntityType] < typeOrder[all[j].EntityType]
		}
		return all[i].EntityName < all[j].EntityName
	})

	return all
}

// extractRecommendations parses the recommendations array from an evaluation field.
func extractRecommendations(data interface{}, evalField string) []recommendation {
	m := asMap(data)
	if m == nil {
		return nil
	}

	evalData, ok := m[evalField]
	if !ok {
		return nil
	}

	evalMap := asMap(evalData)
	if evalMap == nil {
		return nil
	}

	recsRaw, ok := evalMap["recommendations"]
	if !ok || recsRaw == nil {
		return nil
	}

	// Marshal and unmarshal to get typed recommendations.
	b, err := json.Marshal(recsRaw)
	if err != nil {
		return nil
	}

	var recs []recommendation
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil
	}

	return recs
}

// countBySeverity aggregates finding counts by severity level.
func countBySeverity(allFindings []entityFindings) map[string]int {
	counts := map[string]int{}
	for _, ef := range allFindings {
		for _, r := range ef.Findings {
			counts[r.Severity]++
		}
	}
	return counts
}

// determineScopeName picks the primary scope name for the report title.
func determineScopeName(report *ScanReport) (string, string) {
	if len(report.Enterprises) > 0 {
		for name := range report.Enterprises {
			return name, "Enterprise"
		}
	}
	if len(report.Organizations) > 0 {
		for name := range report.Organizations {
			return name, "Organization"
		}
	}
	if len(report.Repositories) > 0 {
		for name := range report.Repositories {
			return name, "Repository"
		}
	}
	return "Unknown", "Unknown"
}

// generateExecutiveSummaryText produces the executive summary paragraph.
func generateExecutiveSummaryText(report *ScanReport, counts map[string]int, total int) string {
	critical := counts["critical"]
	high := counts["high"]
	medium := counts["medium"]

	// Determine the biggest risk area by counting categories.
	catCounts := map[string]int{}
	for _, ef := range collectAllFindings(report) {
		for _, r := range ef.Findings {
			catCounts[r.Category]++
		}
	}
	topCategory := ""
	topCount := 0
	for cat, c := range catCounts {
		if c > topCount {
			topCount = c
			topCategory = cat
		}
	}
	topCategoryDisplay := categoryDisplayNames[topCategory]
	if topCategoryDisplay == "" {
		topCategoryDisplay = topCategory
	}

	posture := "strong"
	if critical > 0 {
		posture = "requires immediate attention"
	} else if high > 0 {
		posture = "needs improvement"
	} else if medium > 0 {
		posture = "moderate with room for improvement"
	}

	return fmt.Sprintf(
		"> The overall security and best practices posture of this environment **%s**. "+
			"A total of **%d findings** were identified across %d enterprises, %d organizations, and %d repositories. "+
			"Of these, **%d are critical** and **%d are high severity**, requiring prompt remediation. "+
			"An additional **%d medium-severity** findings should be addressed within 60 days. "+
			"The most prevalent area of concern is **%s** with %d findings. "+
			"The top improvement opportunity is to enable branch protection and Dependabot alerts across all repositories.",
		posture, total,
		len(report.Enterprises), len(report.Organizations), len(report.Repositories),
		critical, high, medium,
		topCategoryDisplay, topCount,
	)
}

// generatePostureScorecard builds the per-entity scorecard table.
func generatePostureScorecard(report *ScanReport) string {
	var sb strings.Builder
	sb.WriteString("| Entity | Type | Critical | High | Medium | Low | Info |\n")
	sb.WriteString("|--------|------|----------|------|--------|-----|------|\n")

	allFindings := collectAllFindings(report)
	for _, ef := range allFindings {
		counts := map[string]int{}
		for _, r := range ef.Findings {
			counts[r.Severity]++
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d | %d | %d |\n",
			ef.EntityName, ef.EntityType,
			counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"],
		))
	}

	return sb.String()
}

// generateRiskDistribution builds the overall risk distribution table.
func generateRiskDistribution(counts map[string]int, total int) string {
	var sb strings.Builder
	sb.WriteString("| Severity | Count | % of Total |\n")
	sb.WriteString("|----------|-------|------------|\n")

	sevOrder := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range sevOrder {
		count := counts[sev]
		pct := float64(0)
		if total > 0 {
			pct = float64(count) / float64(total) * 100
		}
		emoji := severityEmoji[sev]
		sb.WriteString(fmt.Sprintf("| %s %s | %d | %.0f%% |\n",
			emoji, strings.Title(sev), count, pct))
	}

	return sb.String()
}

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
		sb.WriteString(fmt.Sprintf("**Risk Level:** %s %s\n", severityEmoji[highestSev], strings.Title(highestSev)))
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
				severityEmoji[f.Rec.Severity], strings.Title(f.Rec.Severity),
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

// generateRemediationPlan builds the 30/60/90-day remediation plan.
func generateRemediationPlan(allFindings []entityFindings) string {
	var sprint30, sprint60, sprint90 []planItem

	for _, ef := range allFindings {
		for _, r := range ef.Findings {
			item := planItem{Entity: ef.EntityName, Rec: r}
			switch r.Severity {
			case "critical", "high":
				sprint30 = append(sprint30, item)
			case "medium":
				sprint60 = append(sprint60, item)
			case "low", "info":
				sprint90 = append(sprint90, item)
			}
		}
	}

	// Sort each sprint by severity then entity.
	sortItems := func(items []planItem) {
		sort.Slice(items, func(i, j int) bool {
			if severityOrder[items[i].Rec.Severity] != severityOrder[items[j].Rec.Severity] {
				return severityOrder[items[i].Rec.Severity] < severityOrder[items[j].Rec.Severity]
			}
			return items[i].Entity < items[j].Entity
		})
	}
	sortItems(sprint30)
	sortItems(sprint60)
	sortItems(sprint90)

	var sb strings.Builder

	// 30-Day Sprint
	sb.WriteString("### 30-Day Sprint — Immediate Actions 🔴\n\n")
	sb.WriteString("> Address all **critical** and **high** severity issues. These represent the\n")
	sb.WriteString("> highest risk to your organization and should be resolved within the first month.\n\n")
	sb.WriteString(renderPlanTable(sprint30))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Eliminate all %d critical and high-severity risks, establishing a secure baseline for branch protection, vulnerability scanning, and access controls.\n\n---\n\n", len(sprint30)))

	// 60-Day Sprint
	sb.WriteString("### 60-Day Sprint — High-Priority Improvements 🟠\n\n")
	sb.WriteString("> Address all **medium** severity issues and any high-effort critical/high fixes\n")
	sb.WriteString("> that couldn't be completed in the 30-day sprint.\n\n")
	sb.WriteString(renderPlanTable(sprint60))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Close all %d medium-severity gaps, improving governance, access controls, and cost optimization across the environment.\n\n---\n\n", len(sprint60)))

	// 90-Day Sprint
	sb.WriteString("### 90-Day Sprint — Strategic Hardening 🟡\n\n")
	sb.WriteString("> Address all **low** severity issues, implement process improvements, and\n")
	sb.WriteString("> establish ongoing governance controls.\n\n")
	sb.WriteString(renderPlanTable(sprint90))
	sb.WriteString(fmt.Sprintf("\n**Expected outcome:** Complete all %d remaining improvements, achieving a fully hardened environment with community health documentation, automated branch cleanup, and long-term maintenance practices.\n\n", len(sprint90)))

	return sb.String()
}

// renderPlanTable renders the priority action table for a sprint.
func renderPlanTable(items []planItem) string {
	if len(items) == 0 {
		return "*No items in this phase.*\n"
	}

	var sb strings.Builder
	sb.WriteString("| Priority | Entity | Action | Category | Effort | Owner |\n")
	sb.WriteString("|----------|--------|--------|----------|--------|-------|\n")

	// Deduplicate: group same issue+category across entities.
	type dedupeKey struct {
		Issue    string
		Category string
	}
	seen := map[dedupeKey]bool{}
	priority := 1

	for _, item := range items {
		key := dedupeKey{Issue: item.Rec.Issue, Category: item.Rec.Category}
		if seen[key] {
			continue
		}
		seen[key] = true

		// Collect all entities with this same finding.
		entities := []string{item.Entity}
		for _, other := range items {
			if other.Entity != item.Entity && other.Rec.Issue == item.Rec.Issue && other.Rec.Category == item.Rec.Category {
				entities = append(entities, other.Entity)
			}
		}
		// Deduplicate entities.
		entitySet := map[string]bool{}
		for _, e := range entities {
			entitySet[e] = true
		}
		uniqueEntities := make([]string, 0, len(entitySet))
		for e := range entitySet {
			uniqueEntities = append(uniqueEntities, e)
		}
		sort.Strings(uniqueEntities)

		effort := estimateEffort(item.Rec)
		displayCat := categoryDisplayNames[item.Rec.Category]
		if displayCat == "" {
			displayCat = item.Rec.Category
		}

		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n",
			priority,
			strings.Join(uniqueEntities, ", "),
			item.Rec.Recommendation,
			displayCat,
			effort,
			suggestOwner(item.Rec.Category),
		))
		priority++
	}

	return sb.String()
}

// estimateEffort provides S/M/L effort estimate based on the recommendation type.
func estimateEffort(rec recommendation) string {
	issue := strings.ToLower(rec.Issue)
	recommendation := strings.ToLower(rec.Recommendation)
	combined := issue + " " + recommendation

	// Large effort: requires team coordination or phased rollout.
	if strings.Contains(combined, "archive") || strings.Contains(combined, "phased") ||
		strings.Contains(combined, "coordinate") || strings.Contains(combined, "migration") {
		return "L — Large"
	}

	// Small effort: single toggle or setting change.
	if strings.Contains(combined, "enable") || strings.Contains(combined, "toggle") ||
		strings.Contains(combined, "switch to") || strings.Contains(combined, "restrict") ||
		strings.Contains(combined, "require") || strings.Contains(combined, "reclaim") {
		return "S — Small"
	}

	// Medium effort: creating files or policies.
	if strings.Contains(combined, "add a") || strings.Contains(combined, "create") ||
		strings.Contains(combined, "codeowners") || strings.Contains(combined, "security.md") ||
		strings.Contains(combined, "description") || strings.Contains(combined, "topics") {
		return "M — Medium"
	}

	return "M — Medium"
}

// suggestOwner suggests a responsible team based on the category.
func suggestOwner(category string) string {
	owners := map[string]string{
		"security":           "Security Team",
		"branch_protection":  "Platform / DevOps",
		"access_control":     "Security Team",
		"copilot_security":   "Platform / DevOps",
		"copilot_cost":       "Engineering Managers",
		"copilot_features":   "Platform / DevOps",
		"copilot_models":     "Platform / DevOps",
		"copilot_mcp":        "Platform / DevOps",
		"copilot_extensions": "Platform / DevOps",
		"actions":            "Platform / DevOps",
		"community":          "Repository Owners",
		"dependencies":       "Security Team",
		"permissions":        "Security Team",
		"deployment":         "Platform / DevOps",
		"maintenance":        "Repository Owners",
		"risk":               "Security Team",
		"features":           "Security Team",
	}
	if owner, ok := owners[category]; ok {
		return owner
	}
	return "Engineering Team"
}

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
func generateAppendix(report *ScanReport) string {
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
				severityEmoji[r.Severity], strings.Title(r.Severity),
				displayCat, r.Issue, r.Recommendation, learnMore,
			))
		}

		sb.WriteString("\n</details>\n\n")
	}

	return sb.String()
}
