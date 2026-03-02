// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"strings"
	"time"

	"github.com/microsoft/ghqr/internal/renderers"
)

// generateMarkdown renders the full markdown document from a ScanReport.
func generateMarkdown(report *renderers.ScanReport) string {
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
