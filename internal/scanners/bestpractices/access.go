// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateCollaborators evaluates repository collaborator access.
func (e *Evaluator) EvaluateCollaborators(collaborators []*scanners.CollaboratorInfo) *EvaluationResult {
	var findings []Issue

	if len(collaborators) == 0 {
		addRecommendation(&findings, SeverityInfo, CategoryAccessControl,
			"No direct collaborators found",
			"Consider using teams for better access management",
			"https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams")
		return createResult(e, findings)
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

	if adminCount > 3 {
		e.addFinding(&findings, "repo-acc-001",
			fmt.Sprintf("%d users have admin access to this repository", adminCount))
	} else if adminCount > 0 {
		addRecommendation(&findings, SeverityInfo, CategoryAccessControl,
			fmt.Sprintf("%d users have admin access", adminCount),
			"Regularly review admin access to ensure it's still needed",
			"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization")
	}

	e.addFinding(&findings, "repo-acc-002",
		fmt.Sprintf("%d direct collaborators found (Admin: %d, Write: %d, Read: %d)", len(collaborators), adminCount, writeCount, readCount))

	return createResult(e, findings)
}

// EvaluateDeployKeys evaluates deploy key security.
func (e *Evaluator) EvaluateDeployKeys(deployKeys []*scanners.DeployKeyInfo) *EvaluationResult {
	var findings []Issue

	if len(deployKeys) == 0 {
		addRecommendation(&findings, SeverityInfo, CategorySecurity,
			"No deploy keys found",
			"If automated deployments are needed, use GitHub Apps or OIDC instead of deploy keys",
			"https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys")
		return createResult(e, findings)
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

	if writeKeyCount > 0 {
		e.addFinding(&findings, "repo-acc-003",
			fmt.Sprintf("%d deploy keys have write access", writeKeyCount))
	}

	if unverifiedCount > 0 {
		e.addFinding(&findings, "repo-acc-004",
			fmt.Sprintf("%d deploy keys are unverified", unverifiedCount))
	}

	e.addFinding(&findings, "repo-acc-005",
		fmt.Sprintf("%d deploy keys configured", len(deployKeys)))

	return createResult(e, findings)
}
