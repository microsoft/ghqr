// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateActionsPermissions checks GitHub Actions workflow permission settings.
func (e *Evaluator) EvaluateActionsPermissions(perms *scanners.OrgActionsPermissions) *EvaluationResult {
	if perms == nil {
		return noDataResult("Actions permissions data not available")
	}

	var issues []Issue
	var recommendations []Issue

	// Default token should be read-only to follow least-privilege.
	if perms.DefaultWorkflowPermissions == "write" {
		addIssue(&issues, SeverityHigh, CategoryActions,
			"Default GITHUB_TOKEN permission is set to 'write'",
			"Change the default workflow permission to 'read' to enforce least-privilege; grant write access only in workflows that explicitly need it",
			"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token")
	}

	// Actions should be restricted — 'all' allows any third-party action without review.
	switch perms.AllowedActions {
	case "all":
		addIssue(&issues, SeverityHigh, CategoryActions,
			"GitHub Actions allows ALL third-party actions without restriction",
			"Restrict allowed actions to 'local_only' or 'selected' (trusted publishers/verified creators) to reduce supply-chain risk",
			"https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization")
	case "local_only":
		// Good — but recommend 'selected' for more nuance.
		addRecommendation(&recommendations, SeverityLow, CategoryActions,
			"Actions are restricted to local/internal repositories only",
			"Consider using 'selected' to allow specific trusted third-party actions (e.g., actions/* and verified creators)",
			"https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateOrgSecurityAlerts evaluates aggregate open security alert counts for an org.
func (e *Evaluator) EvaluateOrgSecurityAlerts(alerts *scanners.OrgSecurityAlerts) *EvaluationResult {
	if alerts == nil || !alerts.Available {
		return noDataResult("Org-level security alerts not available (GHAS may not be licensed)")
	}

	var issues []Issue
	var recommendations []Issue

	if alerts.CriticalDependabot > 0 {
		addIssue(&issues, SeverityCritical, CategoryDependencies,
			fmt.Sprintf("%d critical Dependabot alerts open across the organization", alerts.CriticalDependabot),
			"Immediately remediate critical dependency vulnerabilities",
			"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.HighDependabot > 0 {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			fmt.Sprintf("%d high-severity Dependabot alerts open across the organization", alerts.HighDependabot),
			"Prioritize fixing high-severity dependency vulnerabilities",
			"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.OpenDependabotAlerts > 0 && alerts.CriticalDependabot == 0 && alerts.HighDependabot == 0 {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			fmt.Sprintf("%d Dependabot alerts open across the organization (no critical/high)", alerts.OpenDependabotAlerts),
			"Review and remediate remaining open Dependabot alerts",
			"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}

	if alerts.OpenCodeScanningAlerts > 0 {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			fmt.Sprintf("%d code scanning alerts open across the organization", alerts.OpenCodeScanningAlerts),
			"Review and address open code scanning findings",
			"https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/managing-code-scanning-alerts-for-your-repository")
	}

	if alerts.OpenSecretScanningAlerts > 0 {
		addIssue(&issues, SeverityCritical, CategorySecurity,
			fmt.Sprintf("%d secret scanning alerts open across the organization", alerts.OpenSecretScanningAlerts),
			"Immediately revoke and rotate any exposed secrets",
			"https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateEnterpriseSecurityAlerts evaluates enterprise-wide aggregate security alerts.
func (e *Evaluator) EvaluateEnterpriseSecurityAlerts(alerts *scanners.EnterpriseSecurityAlerts) *EvaluationResult {
	if alerts == nil || !alerts.Available {
		return noDataResult("Enterprise-level security alerts not available (GHAS may not be licensed or lacks enterprise admin token)")
	}

	var issues []Issue
	var recommendations []Issue

	if alerts.CriticalDependabot > 0 {
		addIssue(&issues, SeverityCritical, CategoryDependencies,
			fmt.Sprintf("%d critical Dependabot alerts open across the enterprise", alerts.CriticalDependabot),
			"Immediately remediate critical dependency vulnerabilities across all organizations",
			"https://docs.github.com/en/enterprise-cloud@latest/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.HighDependabot > 0 {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			fmt.Sprintf("%d high-severity Dependabot alerts open across the enterprise", alerts.HighDependabot),
			"Prioritize fixing high-severity dependency vulnerabilities",
			"https://docs.github.com/en/enterprise-cloud@latest/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.OpenCodeScanningAlerts > 0 {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			fmt.Sprintf("%d code scanning alerts open across the enterprise", alerts.OpenCodeScanningAlerts),
			"Review and address code scanning findings across all organizations",
			"https://docs.github.com/en/enterprise-cloud@latest/code-security/code-scanning")
	}
	if alerts.OpenSecretScanningAlerts > 0 {
		addIssue(&issues, SeverityCritical, CategorySecurity,
			fmt.Sprintf("%d secret scanning alerts open across the enterprise", alerts.OpenSecretScanningAlerts),
			"Immediately revoke and rotate any exposed secrets",
			"https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateSecurityManagers checks whether a security manager team is assigned.
func (e *Evaluator) EvaluateSecurityManagers(mgrs *scanners.OrgSecurityManagers) *EvaluationResult {
	if mgrs == nil {
		return noDataResult("Security managers data not available")
	}

	var issues []Issue
	var recommendations []Issue

	if !mgrs.HasSecurityManager {
		addRecommendation(&recommendations, SeverityMedium, CategoryAccessControl,
			"No security manager team is assigned to this organization",
			"Assign a security manager team to ensure security alerts and configurations are actively monitored by the right people",
			"https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/managing-security-managers-in-your-organization")
	}

	return createResult(e, issues, recommendations)
}
