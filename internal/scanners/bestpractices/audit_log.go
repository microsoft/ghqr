// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateEnterpriseAuditLog checks recent enterprise audit log events for suspicious activity.
func (e *Evaluator) EvaluateEnterpriseAuditLog(data *scanners.EnterpriseAuditLogData) *EvaluationResult {
	if data == nil {
		return noDataResult("No enterprise audit log data available")
	}

	var issues []Issue
	var recommendations []Issue

	if len(data.SuspiciousEvents) > 0 {
		addIssue(&issues, SeverityCritical, CategorySecurity,
			fmt.Sprintf("%d suspicious audit log event(s) detected in the last %d events scanned: %s",
				len(data.SuspiciousEvents),
				data.TotalEventsScanned,
				summarizeSuspiciousEvents(data.SuspiciousEvents)),
			"Review these events in the Enterprise audit log immediately. "+
				"Actions like repo.destroy, org.remove_member, and oauth_access.revoke can indicate account compromise.",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
			fmt.Sprintf("No suspicious audit log events detected in the last %d events scanned",
				data.TotalEventsScanned),
			"Continue monitoring the audit log regularly and configure audit log streaming to a SIEM",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise")
	}

	addRecommendation(&recommendations, SeverityHigh, CategorySecurity,
		"Audit log streaming configuration cannot be verified automatically",
		"Manually verify that audit log streaming is enabled and targets a SIEM or secure storage (Enterprise → Settings → Audit log → Audit log streaming)",
		"https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise")

	return createResult(e, issues, recommendations)
}

// EvaluateOrgSecurityDefaults checks org-wide security defaults applied to new repositories.
func (e *Evaluator) EvaluateOrgSecurityDefaults(settings *scanners.OrgSecurity) *EvaluationResult {
	if settings == nil {
		return noDataResult("No organization security settings available")
	}

	var issues []Issue
	var recommendations []Issue

	if !settings.DependabotAlertsForNewRepos {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			"Dependabot alerts are not enabled by default for new repositories",
			"Enable 'Dependabot alerts' in Organization → Settings → Code security and analysis",
			"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/configuring-dependabot-alerts")
	}
	if !settings.DependabotSecurityUpdatesForNewRepos {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			"Dependabot security updates are not enabled by default for new repositories",
			"Enable 'Dependabot security updates' in Organization → Settings → Code security and analysis",
			"https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates")
	}
	if !settings.DependencyGraphForNewRepos {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			"Dependency graph is not enabled by default for new repositories",
			"Enable the dependency graph in Organization → Settings → Code security and analysis",
			"https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph")
	}
	if !settings.SecretScanningForNewRepos {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning is not enabled by default for new repositories",
			"Enable 'Secret scanning' in Organization → Settings → Code security and analysis",
			"https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning")
	}
	if !settings.SecretScanningPushProtectionForNewRepos {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning push protection is not enabled by default for new repositories",
			"Enable 'Push protection' in Organization → Settings → Code security and analysis",
			"https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection")
	}
	if !settings.AdvancedSecurityForNewRepos {
		addRecommendation(&recommendations, SeverityMedium, CategorySecurity,
			"GitHub Advanced Security is not enabled by default for new repositories",
			"Enable 'GitHub Advanced Security' in Organization → Settings → Code security and analysis (requires GHAS license)",
			"https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security")
	}

	return createResult(e, issues, recommendations)
}

func summarizeSuspiciousEvents(events []*scanners.SuspiciousAuditEvent) string {
	seen := map[string]int{}
	for _, e := range events {
		seen[e.Action]++
	}
	var parts []string
	for action, count := range seen {
		parts = append(parts, fmt.Sprintf("%s (x%d)", action, count))
	}
	return strings.Join(parts, ", ")
}

// EvaluateEnterpriseGHASSettings checks enterprise-wide GHAS policy defaults.
// Values are strings like "enabled", "disabled", or "not_set".
func (e *Evaluator) EvaluateEnterpriseGHASSettings(s *scanners.EnterpriseGHASSettings) *EvaluationResult {
	if s == nil {
		return noDataResult("Enterprise GHAS settings not available (requires enterprise admin token)")
	}

	var issues []Issue
	var recommendations []Issue

	enabled := func(v string) bool { return strings.EqualFold(v, "enabled") }

	if !enabled(s.AdvancedSecurity) {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"GitHub Advanced Security is not enabled at the enterprise level",
			"Enable GHAS enterprise-wide to unlock code scanning, secret scanning, and dependency review across all organizations",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-github-advanced-security-for-your-enterprise/enabling-github-advanced-security-for-your-enterprise")
	}

	if !enabled(s.SecretScanning) {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning is not enabled as an enterprise default",
			"Enable secret scanning enterprise-wide to detect leaked credentials across all repositories",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-secret-scanning-for-your-enterprise")
	}

	if !enabled(s.SecretScanningPushProtection) {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning push protection is not enabled as an enterprise default",
			"Enable push protection enterprise-wide to block commits containing secrets before they reach repositories",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-secret-scanning-for-your-enterprise")
	}

	if !enabled(s.DependabotAlerts) {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			"Dependabot alerts are not enabled as an enterprise default",
			"Enable Dependabot alerts enterprise-wide to surface vulnerable dependencies across all organizations",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-dependabot/enabling-dependabot-for-your-enterprise")
	}

	if !enabled(s.DependabotSecurityUpdates) {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			"Dependabot security updates are not enabled as an enterprise default",
			"Enable Dependabot security updates enterprise-wide to automatically open PRs that remediate vulnerable dependencies",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-dependabot/enabling-dependabot-for-your-enterprise")
	}

	if !enabled(s.DependencyGraph) {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			"Dependency graph is not enabled as an enterprise default",
			"Enable the dependency graph enterprise-wide to power Dependabot alerts and dependency review",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-dependabot/enabling-dependabot-for-your-enterprise")
	}

	if !enabled(s.SecretScanningNonProviderPatterns) {
		addRecommendation(&recommendations, SeverityLow, CategorySecurity,
			"Secret scanning for non-provider patterns is not enabled as an enterprise default",
			"Enable detection of generic secrets (e.g. high-entropy tokens) for broader coverage",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-secret-scanning-for-your-enterprise")
	}

	return createResult(e, issues, recommendations)
}
