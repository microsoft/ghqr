// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateDiscussionSettings evaluates whether GitHub Discussions are enabled.
func (e *Evaluator) EvaluateDiscussionSettings(repoData *scanners.RepositoryData) *EvaluationResult {
	var findings []Issue

	if repoData.DiscussionSettings != nil && !repoData.DiscussionSettings.Enabled {
		e.addFinding(&findings, "repo-comm-001", "")
	}

	return createResult(e, findings)
}
