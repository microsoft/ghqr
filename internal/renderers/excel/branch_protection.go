// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
)

func renderBranchProtection(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "BranchProtection"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create BranchProtection sheet")
		return
	}

	headers := []string{
		"Repository", "Branch", "Protected",
		"Required Approvals", "Dismiss Stale Reviews", "Require CODEOWNERS",
		"Require Status Checks", "Strict Status Checks",
		"Allow Force Pushes", "Allow Deletions", "Required Signatures",
	}
	createFirstRow(f, sheet, headers, styles)

	rows := buildBranchProtectionTable(results)
	lastRow, err := writeRows(f, sheet, rows, 1)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write BranchProtection rows")
	}

	configureSheet(f, sheet, headers, lastRow, styles)
}

func buildBranchProtectionTable(results map[string]interface{}) [][]string {
	type row struct {
		name string
		cols []string
	}

	var rows []row

	for key, val := range results {
		if !strings.HasPrefix(key, "repository:") {
			continue
		}
		name := strings.TrimPrefix(key, "repository:")
		repoData, ok := val.(*scanners.RepositoryData)
		if !ok {
			continue
		}

		bp := repoData.BranchProtection
		if bp == nil {
			bp = &scanners.BranchProtectionDetail{}
		}

		protected := boolStr(bp.Protected)
		branch := bp.Branch
		requiredApprovals := ""
		dismissStale := ""
		requireCodeowners := ""
		requireStatusChecks := boolStr(bp.RequiredStatusChecks != nil)
		strictStatusChecks := ""
		allowForcePushes := boolStr(bp.AllowForcePushes)
		allowDeletions := boolStr(bp.AllowDeletions)
		requiredSignatures := boolStr(bp.RequiredSignatures)

		if r := bp.RequiredPullRequestReviews; r != nil {
			requiredApprovals = fmt.Sprintf("%d", r.RequiredApprovingReviewCount)
			dismissStale = boolStr(r.DismissStaleReviews)
			requireCodeowners = boolStr(r.RequireCodeOwnerReviews)
		}
		if sc := bp.RequiredStatusChecks; sc != nil {
			strictStatusChecks = boolStr(sc.Strict)
		}

		rows = append(rows, row{name: name, cols: []string{
			name, branch, protected,
			requiredApprovals, dismissStale, requireCodeowners,
			requireStatusChecks, strictStatusChecks,
			allowForcePushes, allowDeletions, requiredSignatures,
		}})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}
