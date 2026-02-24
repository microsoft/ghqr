// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// evaluateRepositorySecurity evaluates security features from GraphQL data
func evaluateRepositorySecurity(security *scanners.RepoSecurityFeatures, archived bool, issues *[]Issue, recommendations *[]Issue) {
	if security == nil {
		return
	}

	// Vulnerability alerts (Dependabot)
	if !checkEnabled(security.VulnerabilityAlerts) {
		addIssue(issues, SeverityHigh, CategorySecurity,
			"Dependabot alerts are not enabled",
			"Enable Dependabot alerts to receive security vulnerability notifications")
	}

	// Open Dependabot alerts by severity
	if security.DependabotAlerts != nil && security.DependabotAlerts.Enabled {
		if critical, ok := security.DependabotAlerts.BySeverity["critical"]; ok && critical > 0 {
			addIssue(issues, SeverityCritical, CategorySecurity,
				fmt.Sprintf("%d critical Dependabot alerts", critical),
				"Immediately address critical security vulnerabilities")
		}
		if high, ok := security.DependabotAlerts.BySeverity["high"]; ok && high > 0 {
			addIssue(issues, SeverityHigh, CategorySecurity,
				fmt.Sprintf("%d high-severity Dependabot alerts", high),
				"Prioritize fixing high-severity vulnerabilities")
		}
	}

	// Skip file-level checks for archived repos — they are read-only and cannot be modified.
	if archived {
		return
	}

	// Security policy (SECURITY.md)
	if !checkEnabled(security.SecurityPolicy) {
		addRecommendation(recommendations, SeverityLow, CategorySecurity,
			"No SECURITY.md file found",
			"Add a SECURITY.md file to document vulnerability reporting process")
	}

	// CODEOWNERS file
	if security.CodeOwnersFile == nil || !security.CodeOwnersFile.Exists {
		addRecommendation(recommendations, SeverityMedium, CategoryAccessControl,
			"No CODEOWNERS file found",
			"Add a CODEOWNERS file to require code owner reviews for critical paths")
	}
}

// evaluateRepositoryAccessAndFeatures evaluates repository features and access configuration
func evaluateRepositoryAccessAndFeatures(basicFeatures *scanners.RepoBasicFeatures, access *scanners.RepoAccessConfig, recommendations *[]Issue) {
	if access == nil {
		return
	}

	if access.Archived {
		addRecommendation(recommendations, SeverityInfo, CategoryAccess,
			"Repository is archived",
			"Archived repositories are read-only",
			"https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories")
		// Archived repos are read-only — skip all actionable recommendations.
		return
	}

	if basicFeatures != nil && !basicFeatures.HasIssues && !basicFeatures.HasDiscussions {
		addRecommendation(recommendations, SeverityLow, CategoryFeatures,
			"Issues and Discussions are both disabled",
			"Consider enabling Issues or Discussions for community feedback",
			"https://docs.github.com/en/discussions/quickstart")
	}

	if !access.DeleteBranchOnMerge {
		addRecommendation(recommendations, SeverityLow, CategoryMaintenance,
			"Branches are not auto-deleted after merge",
			"Enable auto-delete to keep the repository clean",
			"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-the-automatic-deletion-of-branches")
	}
}

// EvaluateRepositoryFeatures checks repository features and security
func (e *Evaluator) EvaluateRepositoryFeatures(repoData *scanners.RepositoryData) *EvaluationResult {
	if repoData == nil {
		return noDataResult("Repository data not available")
	}

	issues := []Issue{}
	recommendations := []Issue{}

	archived := repoData.Access != nil && repoData.Access.Archived
	evaluateRepositorySecurity(repoData.Security, archived, &issues, &recommendations)
	evaluateRepositoryAccessAndFeatures(repoData.BasicFeatures, repoData.Access, &recommendations)

	return createResult(e, issues, recommendations)
}
