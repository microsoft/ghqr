// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// evaluateRepositorySecurity evaluates security features from GraphQL data.
func (e *Evaluator) evaluateRepositorySecurity(security *scanners.RepoSecurityFeatures, archived bool, findings *[]Issue) {
	if security == nil {
		return
	}

	if !checkEnabled(security.VulnerabilityAlerts) {
		e.addFinding(findings, "repo-sec-001", "")
	}

	if security.DependabotAlerts != nil && security.DependabotAlerts.Enabled {
		if critical, ok := security.DependabotAlerts.BySeverity["critical"]; ok && critical > 0 {
			e.addFinding(findings, "repo-sec-002",
				fmt.Sprintf("%d critical Dependabot alerts", critical))
		}
		if high, ok := security.DependabotAlerts.BySeverity["high"]; ok && high > 0 {
			e.addFinding(findings, "repo-sec-003",
				fmt.Sprintf("%d high-severity Dependabot alerts", high))
		}
	}

	// Skip file-level checks for archived repos — they are read-only and cannot be modified.
	if archived {
		return
	}

	if !checkEnabled(security.SecurityPolicy) {
		e.addFinding(findings, "repo-sec-004", "")
	}

	if security.CodeOwnersFile == nil || !security.CodeOwnersFile.Exists {
		e.addFinding(findings, "repo-sec-005", "")
	}
}

// evaluateRepositoryAccessAndFeatures evaluates repository features and access configuration.
func (e *Evaluator) evaluateRepositoryAccessAndFeatures(basicFeatures *scanners.RepoBasicFeatures, access *scanners.RepoAccessConfig, findings *[]Issue) {
	if access == nil {
		return
	}

	if access.Archived {
		addRecommendation(findings, SeverityInfo, CategoryAccess,
			"Repository is archived",
			"Archived repositories are read-only",
			"https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories")
		// Archived repos are read-only — skip all actionable recommendations.
		return
	}

	if basicFeatures != nil && !basicFeatures.HasIssues && !basicFeatures.HasDiscussions {
		e.addFinding(findings, "repo-feat-001", "")
	}

	if !access.DeleteBranchOnMerge {
		e.addFinding(findings, "repo-feat-002", "")
	}
}

// EvaluateRepositoryFeatures checks repository features and security.
func (e *Evaluator) EvaluateRepositoryFeatures(repoData *scanners.RepositoryData) *EvaluationResult {
	if repoData == nil {
		return noDataResult("Repository data not available")
	}

	var findings []Issue

	archived := repoData.Access != nil && repoData.Access.Archived
	e.evaluateRepositorySecurity(repoData.Security, archived, &findings)
	e.evaluateRepositoryAccessAndFeatures(repoData.BasicFeatures, repoData.Access, &findings)

	return createResult(e, findings)
}
