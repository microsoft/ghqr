// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateCopilot checks Copilot policy settings for an organization.
func (e *Evaluator) EvaluateCopilot(data *scanners.OrgCopilotData) *EvaluationResult {
	if data == nil {
		return noDataResult("No Copilot data available")
	}

	if !data.BillingEnabled {
		var findings []Issue
		addRecommendation(&findings, SeverityInfo, CategoryCopilotSecurity,
			"GitHub Copilot is not enabled for this organization",
			"Consider enabling GitHub Copilot to improve developer productivity",
			"https://docs.github.com/en/copilot/about-github-copilot/what-is-github-copilot")
		return createResult(e, findings)
	}

	var findings []Issue

	switch data.SeatManagementSetting {
	case "assign_all":
		e.addFinding(&findings, "org-cop-001", "")
	case "disabled":
		addRecommendation(&findings, SeverityInfo, CategoryCopilotSecurity,
			"Copilot seat assignment is disabled",
			"No action needed unless you intend to roll out Copilot",
			"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization/granting-access-to-copilot-for-members-of-your-organization")
	}

	if data.PublicCodeSuggestions == "allowed" {
		e.addFinding(&findings, "org-cop-002", "")
	}

	if data.TotalSeats > 0 {
		inactivePct := float64(data.InactiveThisCycle) / float64(data.TotalSeats) * 100
		if inactivePct > 20 {
			e.addFinding(&findings, "org-cop-003",
				fmt.Sprintf("%.0f%% of Copilot seats (%d/%d) were inactive this billing cycle",
					inactivePct, data.InactiveThisCycle, data.TotalSeats))
		} else {
			addRecommendation(&findings, SeverityInfo, CategoryCopilotCost,
				fmt.Sprintf("Copilot seat utilization: %d active, %d inactive out of %d total",
					data.ActiveThisCycle, data.InactiveThisCycle, data.TotalSeats),
				"Monitor seat utilization regularly for cost efficiency",
				"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/reviewing-activity-related-to-github-copilot-in-your-organization/reviewing-your-organization-s-copilot-seat-assignments")
		}
	}

	return createResult(e, findings)
}
