// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import "strings"

// titleCase capitalises only the first letter of s.
// It replaces the deprecated strings.Title for simple ASCII inputs.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

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

var severityLevels = []string{"critical", "high", "medium", "low", "info"}

// severityOrder defines the sort order for severity levels (lower = higher priority).
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}
