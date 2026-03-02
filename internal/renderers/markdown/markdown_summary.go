// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/renderers"
)

// generateExecutiveSummaryText produces the executive summary paragraph.
func generateExecutiveSummaryText(report *renderers.ScanReport, counts map[string]int, total int) string {
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
func generatePostureScorecard(report *renderers.ScanReport) string {
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

	for _, sev := range severityLevels {
		count := counts[sev]
		pct := float64(0)
		if total > 0 {
			pct = float64(count) / float64(total) * 100
		}
		emoji := severityEmoji[sev]
		sb.WriteString(fmt.Sprintf("| %s %s | %d | %.0f%% |\n",
			emoji, titleCase(sev), count, pct))
	}

	return sb.String()
}
