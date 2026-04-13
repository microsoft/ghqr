// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateBranchProtectionDetail checks detailed branch protection from GraphQL data.
// When legacy branch protection is absent, it falls back to ruleset-based protection
// if available — preventing false negatives for orgs that use repository rulesets.
func (e *Evaluator) EvaluateBranchProtectionDetail(detail *scanners.BranchProtectionDetail) *EvaluationResult {
	var findings []Issue

	if detail == nil || !detail.Protected {
		e.addFinding(&findings, "repo-bp-001", "")
		return createResult(e, findings)
	}

	e.evaluateBranchProtectionSettings(detail.RequiredPullRequestReviews, detail.RequiredStatusChecks, detail.AllowForcePushes, detail.AllowDeletions, detail.RequiredSignatures, detail.RequiredLinearHistory, &findings)

	return createResult(e, findings)
}

// EvaluateRulesetProtection checks branch protection provided by repository rulesets.
// It returns nil when no ruleset data is available so callers can skip the merge.
func (e *Evaluator) EvaluateRulesetProtection(detail *scanners.RulesetProtectionDetail) *EvaluationResult {
	if detail == nil || !detail.Protected {
		return nil
	}

	var findings []Issue

	// Emit an informational note that protection comes from rulesets.
	e.addFinding(&findings, "repo-bp-014", "")

	e.evaluateBranchProtectionSettings(detail.RequiredPullRequestReviews, detail.RequiredStatusChecks, detail.AllowForcePushes, detail.AllowDeletions, detail.RequiredSignatures, detail.RequiredLinearHistory, &findings)

	return createResult(e, findings)
}

// evaluateBranchProtectionSettings contains the shared evaluation logic for both
// legacy branch protection and ruleset-based protection.
func (e *Evaluator) evaluateBranchProtectionSettings(
	reviews *scanners.RequiredPRReviews,
	statusChecks *scanners.RequiredStatusChecks,
	allowForcePushes bool,
	allowDeletions bool,
	requiredSignatures bool,
	requiredLinearHistory bool,
	findings *[]Issue,
) {
	if reviews != nil {
		if reviews.RequiredApprovingReviewCount < 1 {
			e.addFinding(findings, "repo-bp-002", "")
		} else if reviews.RequiredApprovingReviewCount < 2 {
			e.addFinding(findings, "repo-bp-003", "")
		}

		if !reviews.DismissStaleReviews {
			e.addFinding(findings, "repo-bp-004", "")
		}

		if !reviews.RequireCodeOwnerReviews {
			e.addFinding(findings, "repo-bp-005", "")
		}
	} else {
		e.addFinding(findings, "repo-bp-006", "")
	}

	if statusChecks != nil {
		if !statusChecks.Strict {
			e.addFinding(findings, "repo-bp-007", "")
		}
		if len(statusChecks.Contexts) == 0 {
			e.addFinding(findings, "repo-bp-008", "")
		}
	} else {
		e.addFinding(findings, "repo-bp-009", "")
	}

	if allowForcePushes {
		e.addFinding(findings, "repo-bp-010", "")
	}

	if allowDeletions {
		e.addFinding(findings, "repo-bp-011", "")
	}

	if !requiredSignatures {
		e.addFinding(findings, "repo-bp-012", "")
	}

	if !requiredLinearHistory {
		e.addFinding(findings, "repo-bp-013", "")
	}
}
