// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateDiscussionSettings evaluates whether GitHub Discussions are enabled
func (e *Evaluator) EvaluateDiscussionSettings(repoData *scanners.RepositoryData) *EvaluationResult {
	issues := []Issue{}
	recommendations := []Issue{}

	if repoData.DiscussionSettings == nil {
		return createResult(e, issues, recommendations)
	}

	if !repoData.DiscussionSettings.Enabled {
		addRecommendation(&recommendations, SeverityInfo, CategoryCommunity,
			"GitHub Discussions not enabled",
			"Consider enabling Discussions for community Q&A and reducing issue tracker noise",
			"https://docs.github.com/en/discussions/quickstart")
	}

	return createResult(e, issues, recommendations)
}
