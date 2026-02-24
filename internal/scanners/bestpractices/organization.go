// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateOrganizationSecurity checks organization security best practices
func (e *Evaluator) EvaluateOrganizationSecurity(settings *scanners.OrgSettings) *EvaluationResult {
	if settings == nil {
		return noDataResult("No organization settings available")
	}

	issues := []Issue{}
	recommendations := []Issue{}

	// Check 2FA requirement
	if !settings.Security.TwoFactorRequirementEnabled {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Two-factor authentication is not required for organization members",
			"Enable 2FA requirement in organization settings",
			"https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization")
	}

	// Check web commit signoff
	if !settings.Security.WebCommitSignoffRequired {
		addRecommendation(&recommendations, SeverityMedium, CategorySecurity,
			"Web commit signoff is not required",
			"Consider enabling web commit signoff for audit trail",
			"https://docs.github.com/en/organizations/managing-organization-settings/managing-the-commit-signoff-policy-for-your-organization")
	}

	// Check default repository permissions
	if settings.Visibility.DefaultRepositoryPermission == "admin" {
		addIssue(&issues, SeverityHigh, CategoryAccessControl,
			"Default repository permission is set to admin",
			"Change default permission to read or write",
			"https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization")
	}

	// Check repository creation permissions
	if settings.Visibility.MembersCanCreatePublicRepositories {
		addRecommendation(&recommendations, SeverityMedium, CategoryAccessControl,
			"Members can create public repositories",
			"Consider restricting public repository creation",
			"https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization")
	}

	return createResult(e, issues, recommendations)
}
