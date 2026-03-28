// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateBranchProtectionDetail checks detailed branch protection from GraphQL data.
func (e *Evaluator) EvaluateBranchProtectionDetail(detail *scanners.BranchProtectionDetail) *EvaluationResult {
	var findings []Issue

	if detail == nil || !detail.Protected {
		e.addFinding(&findings, "repo-bp-001", "")
		return createResult(e, findings)
	}

	if detail.RequiredPullRequestReviews != nil {
		reviews := detail.RequiredPullRequestReviews

		if reviews.RequiredApprovingReviewCount < 1 {
			e.addFinding(&findings, "repo-bp-002", "")
		} else if reviews.RequiredApprovingReviewCount < 2 {
			e.addFinding(&findings, "repo-bp-003", "")
		}

		if !reviews.DismissStaleReviews {
			e.addFinding(&findings, "repo-bp-004", "")
		}

		if !reviews.RequireCodeOwnerReviews {
			e.addFinding(&findings, "repo-bp-005", "")
		}
	} else {
		e.addFinding(&findings, "repo-bp-006", "")
	}

	if detail.RequiredStatusChecks != nil {
		if !detail.RequiredStatusChecks.Strict {
			e.addFinding(&findings, "repo-bp-007", "")
		}
		if len(detail.RequiredStatusChecks.Contexts) == 0 {
			e.addFinding(&findings, "repo-bp-008", "")
		}
	} else {
		e.addFinding(&findings, "repo-bp-009", "")
	}

	if detail.AllowForcePushes {
		e.addFinding(&findings, "repo-bp-010", "")
	}

	if detail.AllowDeletions {
		e.addFinding(&findings, "repo-bp-011", "")
	}

	if !detail.RequiredSignatures {
		e.addFinding(&findings, "repo-bp-012", "")
	}

	if !detail.RequiredLinearHistory {
		e.addFinding(&findings, "repo-bp-013", "")
	}

	return createResult(e, findings)
}
