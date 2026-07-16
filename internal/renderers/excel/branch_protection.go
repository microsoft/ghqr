// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"sort"
	"strconv"
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
		"Repository", "Branch", "Protected", "Protection Source",
		"Required Approvals", "Dismiss Stale Reviews", "Require CODEOWNERS",
		"Require Status Checks", "Strict Status Checks",
		"Allow Force Pushes", "Allow Deletions", "Required Signatures",
	}

	data := buildBranchProtectionTable(results)
	rows := make([][]string, 0, len(data)+1)
	rows = append(rows, headers)
	rows = append(rows, data...)
	streamSheet(f, sheet, rows, styles)
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
		repoData := asType[scanners.RepositoryData](val)
		if repoData == nil {
			continue
		}

		rows = append(rows, row{name: name, cols: branchProtectionRow(name, repoData)})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}

// effectiveBranchProtection holds the branch-protection fields resolved from
// whichever mechanism actually protects the default branch: a legacy branch
// protection rule or a repository ruleset.
type effectiveBranchProtection struct {
	source               string
	branch               string
	protected            bool
	requiredReviews      *scanners.RequiredPRReviews
	requiredStatusChecks *scanners.RequiredStatusChecks
	allowForcePushes     bool
	allowDeletions       bool
	requiredSignatures   bool
}

// resolveBranchProtection determines the effective branch protection for a
// repository. Legacy branch protection takes precedence; when it is absent the
// repository's ruleset-based protection is used. This mirrors the precedence
// applied by the evaluation stage so the Excel report matches the findings.
func resolveBranchProtection(repo *scanners.RepositoryData) effectiveBranchProtection {
	bp := repo.BranchProtection
	rs := repo.RulesetProtection

	switch {
	case bp != nil && bp.Protected:
		return effectiveBranchProtection{
			source:               "Branch Protection",
			branch:               bp.Branch,
			protected:            true,
			requiredReviews:      bp.RequiredPullRequestReviews,
			requiredStatusChecks: bp.RequiredStatusChecks,
			allowForcePushes:     bp.AllowForcePushes,
			allowDeletions:       bp.AllowDeletions,
			requiredSignatures:   bp.RequiredSignatures,
		}
	case rs != nil && rs.Protected:
		return effectiveBranchProtection{
			source:               "Ruleset",
			branch:               rs.Branch,
			protected:            true,
			requiredReviews:      rs.RequiredPullRequestReviews,
			requiredStatusChecks: rs.RequiredStatusChecks,
			allowForcePushes:     rs.AllowForcePushes,
			allowDeletions:       rs.AllowDeletions,
			requiredSignatures:   rs.RequiredSignatures,
		}
	default:
		branch := ""
		if bp != nil {
			branch = bp.Branch
		}
		return effectiveBranchProtection{source: "None", branch: branch}
	}
}

// branchProtectionRow builds a single BranchProtection sheet row for a
// repository, using its effective protection (legacy rule or ruleset).
func branchProtectionRow(name string, repo *scanners.RepositoryData) []string {
	e := resolveBranchProtection(repo)

	requiredApprovals := ""
	dismissStale := ""
	requireCodeowners := ""
	if r := e.requiredReviews; r != nil {
		requiredApprovals = strconv.Itoa(r.RequiredApprovingReviewCount)
		dismissStale = boolStr(r.DismissStaleReviews)
		requireCodeowners = boolStr(r.RequireCodeOwnerReviews)
	}

	strictStatusChecks := ""
	if sc := e.requiredStatusChecks; sc != nil {
		strictStatusChecks = boolStr(sc.Strict)
	}

	return []string{
		name, e.branch, boolStr(e.protected), e.source,
		requiredApprovals, dismissStale, requireCodeowners,
		boolStr(e.requiredStatusChecks != nil), strictStatusChecks,
		boolStr(e.allowForcePushes), boolStr(e.allowDeletions), boolStr(e.requiredSignatures),
	}
}
