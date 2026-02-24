// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateCollaborators evaluates repository collaborator access
func (e *Evaluator) EvaluateCollaborators(collaborators []*scanners.CollaboratorInfo) *EvaluationResult {
	var issues []Issue
	var recommendations []Issue

	if len(collaborators) == 0 {
		addRecommendation(&recommendations, SeverityInfo, CategoryAccessControl,
			"No direct collaborators found",
			"Consider using teams for better access management",
			"https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams")
		return createResult(e, issues, recommendations)
	}

	adminCount := 0
	writeCount := 0
	readCount := 0

	for _, collab := range collaborators {
		switch collab.Permissions {
		case "admin":
			adminCount++
		case "write", "maintain":
			writeCount++
		case "read":
			readCount++
		}
	}

	// Check for too many admins
	if adminCount > 3 {
		addIssue(&issues, SeverityHigh, CategoryAccessControl,
			fmt.Sprintf("%d users have admin access to this repository", adminCount),
			"Review admin access and follow principle of least privilege. Consider using teams with limited permissions.",
			"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization")
	} else if adminCount > 0 {
		addRecommendation(&recommendations, SeverityInfo, CategoryAccessControl,
			fmt.Sprintf("%d users have admin access", adminCount),
			"Regularly review admin access to ensure it's still needed",
			"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization")
	}

	// Check for external collaborators
	addRecommendation(&recommendations, SeverityMedium, CategoryAccessControl,
		fmt.Sprintf("%d direct collaborators found (Admin: %d, Write: %d, Read: %d)", len(collaborators), adminCount, writeCount, readCount),
		"Prefer team-based access over direct collaborators for better auditability",
		"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/about-outside-collaborators")

	return createResult(e, issues, recommendations)
}

// EvaluateDeployKeys evaluates deploy key security
func (e *Evaluator) EvaluateDeployKeys(deployKeys []*scanners.DeployKeyInfo) *EvaluationResult {
	var issues []Issue
	var recommendations []Issue

	if len(deployKeys) == 0 {
		addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
			"No deploy keys found",
			"If automated deployments are needed, use GitHub Apps or OIDC instead of deploy keys",
			"https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys")
		return createResult(e, issues, recommendations)
	}

	writeKeyCount := 0
	unverifiedCount := 0

	for _, key := range deployKeys {
		if !key.ReadOnly {
			writeKeyCount++
		}
		if !key.Verified {
			unverifiedCount++
		}
	}

	// Check for write-enabled deploy keys
	if writeKeyCount > 0 {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			fmt.Sprintf("%d deploy keys have write access", writeKeyCount),
			"Deploy keys should be read-only when possible. Use GitHub Apps or OIDC for write operations.")
	}

	// Check for unverified keys
	if unverifiedCount > 0 {
		addIssue(&issues, SeverityMedium, CategorySecurity,
			fmt.Sprintf("%d deploy keys are unverified", unverifiedCount),
			"Verify all deploy keys to ensure they belong to authorized systems")
	}

	// General recommendation
	if len(deployKeys) > 0 {
		addRecommendation(&recommendations, SeverityMedium, CategorySecurity,
			fmt.Sprintf("%d deploy keys configured", len(deployKeys)),
			"Consider migrating to GitHub Apps or OIDC federation for better security and auditability")
	}

	return createResult(e, issues, recommendations)
}
