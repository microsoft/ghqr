// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateBranchProtectionDetail checks detailed branch protection from GraphQL data
func (e *Evaluator) EvaluateBranchProtectionDetail(detail *scanners.BranchProtectionDetail) *EvaluationResult {
	issues := []Issue{}
	recommendations := []Issue{}

	if detail == nil || !detail.Protected {
		addIssue(&issues, SeverityCritical, CategoryBranchProtection,
			"No branch protection configured on default branch",
			"CRITICAL: Enable comprehensive branch protection on production branches",
			"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches")
		return createResult(e, issues, recommendations)
	}

	// Required PR reviews
	if detail.RequiredPullRequestReviews != nil {
		reviews := detail.RequiredPullRequestReviews

		if reviews.RequiredApprovingReviewCount < 1 {
			addIssue(&issues, SeverityCritical, CategoryBranchProtection,
				"No approving reviews required",
				"CRITICAL: Require at least 1 approving review before merge",
				"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging")
		} else if reviews.RequiredApprovingReviewCount < 2 {
			addRecommendation(&recommendations, SeverityMedium, CategoryBranchProtection,
				"Only 1 approving review required",
				"Consider requiring 2+ reviews for production branches",
				"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging")
		}

		if !reviews.DismissStaleReviews {
			addIssue(&issues, SeverityHigh, CategoryBranchProtection,
				"Stale reviews not dismissed on new commits",
				"Enable stale review dismissal to ensure up-to-date approvals",
				"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#dismiss-stale-pull-request-approvals-when-new-commits-are-pushed")
		}

		if !reviews.RequireCodeOwnerReviews {
			addIssue(&issues, SeverityMedium, CategoryBranchProtection,
				"Code owner review not required",
				"Enable code owner review requirement for critical paths",
				"https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners")
		}
	} else {
		addIssue(&issues, SeverityCritical, CategoryBranchProtection,
			"Pull request reviews not configured",
			"CRITICAL: Configure PR review requirements",
			"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-pull-request-reviews-before-merging")
	}

	// Status checks
	if detail.RequiredStatusChecks != nil {
		if !detail.RequiredStatusChecks.Strict {
			addIssue(&issues, SeverityHigh, CategoryBranchProtection,
				"Strict status checks not enabled",
				"Enable strict checks to require up-to-date branches before merge",
				"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging")
		}
		if len(detail.RequiredStatusChecks.Contexts) == 0 {
			addRecommendation(&recommendations, SeverityHigh, CategoryBranchProtection,
				"No specific status checks required",
				"Configure required CI/CD checks that must pass before merge",
				"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging")
		}
	} else {
		addIssue(&issues, SeverityHigh, CategoryBranchProtection,
			"No required status checks configured",
			"Configure CI/CD checks that must pass before merge",
			"https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging")
	}

	// Force pushes and deletions
	if detail.AllowForcePushes {
		addIssue(&issues, SeverityCritical, CategoryBranchProtection,
			"Force pushes are allowed",
			"CRITICAL: Disable force pushes to prevent history rewriting")
	}

	if detail.AllowDeletions {
		addIssue(&issues, SeverityHigh, CategoryBranchProtection,
			"Branch deletion is allowed",
			"Disable branch deletion for protected branches")
	}

	// Signed commits
	if !detail.RequiredSignatures {
		addRecommendation(&recommendations, SeverityMedium, CategoryBranchProtection,
			"Signed commits not required",
			"Enable commit signing to verify authorship and integrity")
	}

	// Linear history
	if !detail.RequiredLinearHistory {
		addRecommendation(&recommendations, SeverityLow, CategoryBranchProtection,
			"Linear history not required",
			"Consider requiring squash/rebase for cleaner history")
	}

	return createResult(e, issues, recommendations)
}
