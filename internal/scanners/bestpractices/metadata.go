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

	var findings []Issue

	archived := repoData.Access != nil && repoData.Access.Archived

	if repoData.Description == "" {
		e.addFinding(&findings, "repo-meta-001", "")
	}

	hasTopics := repoData.Metadata != nil && len(repoData.Metadata.Topics) > 0
	if !hasTopics && !archived {
		e.addFinding(&findings, "repo-meta-002", "")
	}

	if !archived && repoData.PushedAt != "" {
		if pushedAt, err := time.Parse(time.RFC3339, repoData.PushedAt); err == nil {
			age := time.Since(pushedAt)
			if age > time.Hour*24*dormantThresholdDays {
				e.addFinding(&findings, "repo-meta-003", "")
			}
		}
	}

	return createResult(e, findings)
}
