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
		return &EvaluationResult{
			Recommendations: []Issue{{
				Severity:       SeverityInfo,
				Category:       CategoryCopilotSecurity,
				Issue:          "GitHub Copilot is not enabled for this organization",
				Recommendation: "Consider enabling GitHub Copilot to improve developer productivity",
				LearnMore:      "https://docs.github.com/en/copilot/about-github-copilot/what-is-github-copilot",
			}},
			Summary: &Summary{},
		}
	}

	var issues []Issue
	var recommendations []Issue

	// Seat management: assign_selected is safest; assign_all exposes all members.
	switch data.SeatManagementSetting {
	case "assign_all":
		addIssue(&issues, SeverityMedium, CategoryCopilotCost,
			"Copilot seats assigned to all organization members (assign_all)",
			"Switch to 'assign_selected' to control costs and limit access to intended users",
			"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization/granting-access-to-copilot-for-members-of-your-organization")
	case "disabled":
		addRecommendation(&recommendations, SeverityInfo, CategoryCopilotSecurity,
			"Copilot seat assignment is disabled",
			"No action needed unless you intend to roll out Copilot",
			"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-access-to-github-copilot-in-your-organization/granting-access-to-copilot-for-members-of-your-organization")
	}

	// Public code suggestions: "allowed" means completions may reproduce public licensed code.
	if data.PublicCodeSuggestions == "allowed" {
		addIssue(&issues, SeverityHigh, CategoryCopilotSecurity,
			"Copilot is allowed to suggest code matching public repository content",
			"Set public code suggestions to 'blocked' to reduce IP/license risk",
			"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-policies-for-copilot-in-your-organization")
	}

	// Seat utilization: flag when more than 20% of seats are inactive this cycle.
	if data.TotalSeats > 0 {
		inactivePct := float64(data.InactiveThisCycle) / float64(data.TotalSeats) * 100
		if inactivePct > 20 {
			addRecommendation(&recommendations, SeverityMedium, CategoryCopilotCost,
				fmt.Sprintf("%.0f%% of Copilot seats (%d/%d) were inactive this billing cycle",
					inactivePct, data.InactiveThisCycle, data.TotalSeats),
				"Reclaim unused seats to reduce costs",
				"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/reviewing-activity-related-to-github-copilot-in-your-organization/reviewing-your-organization-s-copilot-seat-assignments")
		} else {
			addRecommendation(&recommendations, SeverityInfo, CategoryCopilotCost,
				fmt.Sprintf("Copilot seat utilization: %d active, %d inactive out of %d total",
					data.ActiveThisCycle, data.InactiveThisCycle, data.TotalSeats),
				"Monitor seat utilization regularly for cost efficiency",
				"https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/reviewing-activity-related-to-github-copilot-in-your-organization/reviewing-your-organization-s-copilot-seat-assignments")
		}
	}

	return createResult(e, issues, recommendations)
}
