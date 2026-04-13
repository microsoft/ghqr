// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateOrganizationSecurity checks organization security best practices.
func (e *Evaluator) EvaluateOrganizationSecurity(settings *scanners.OrgSettings) *EvaluationResult {
	if settings == nil {
		return noDataResult("No organization settings available")
	}

	var findings []Issue

	if !settings.Security.TwoFactorRequirementEnabled {
		if settings.Security.EMUEnabled {
			e.addFinding(&findings, "org-sec-001-emu", "")
		} else {
			e.addFinding(&findings, "org-sec-001", "")
		}
	}

	if !settings.Security.WebCommitSignoffRequired {
		e.addFinding(&findings, "org-sec-002", "")
	}

	if settings.Visibility.DefaultRepositoryPermission == "admin" {
		e.addFinding(&findings, "org-sec-003", "")
	}

	if settings.Visibility.MembersCanCreatePublicRepositories {
		e.addFinding(&findings, "org-sec-004", "")
	}

	return createResult(e, findings)
}
