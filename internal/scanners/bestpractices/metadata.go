// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"time"

	"github.com/microsoft/ghqr/internal/scanners"
)

const dormantThresholdDays = 365

// EvaluateRepositoryMetadata checks repository naming/description/topic hygiene
// and flags repositories that appear dormant (no push in > 1 year while not archived).
func (e *Evaluator) EvaluateRepositoryMetadata(repoData *scanners.RepositoryData) *EvaluationResult {
	if repoData == nil {
		return noDataResult("Repository data not available")
	}

	var issues []Issue
	var recommendations []Issue

	archived := repoData.Access != nil && repoData.Access.Archived

	// G3 — Description coverage
	if repoData.Description == "" {
		addRecommendation(&recommendations, SeverityMedium, CategoryCommunity,
			"Repository has no description",
			"Add a concise description to every repository to improve discoverability and team orientation",
			"https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-repository-metadata")
	}

	// G3 — Topic coverage
	hasTopics := repoData.Metadata != nil && len(repoData.Metadata.Topics) > 0
	if !hasTopics && !archived {
		addRecommendation(&recommendations, SeverityLow, CategoryCommunity,
			"Repository has no topics",
			"Add GitHub topics to improve searchability and enable org-wide filtering via custom properties or ruleset targeting",
			"https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics")
	}

	// R8 — Dormant repository (not archived, no push for > 1 year)
	if !archived && repoData.PushedAt != "" {
		if pushedAt, err := time.Parse(time.RFC3339, repoData.PushedAt); err == nil {
			age := time.Since(pushedAt)
			if age > time.Hour*24*dormantThresholdDays {
				addRecommendation(&recommendations, SeverityLow, CategoryMaintenance,
					"Repository appears dormant (no push in over 1 year) but is not archived",
					"Archive inactive repositories to reduce maintenance burden and signal deprecation to developers",
					"https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories")
			}
		}
	}

	return createResult(e, issues, recommendations)
}
