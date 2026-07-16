// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"testing"

	"github.com/microsoft/ghqr/internal/scanners"
)

// Column indexes within a BranchProtection sheet data row.
const (
	colRepository = iota
	colBranch
	colProtected
	colSource
	colRequiredApprovals
	colDismissStale
	colRequireCodeowners
	colRequireStatusChecks
	colStrictStatusChecks
	colAllowForcePushes
	colAllowDeletions
	colRequiredSignatures
	colCount
)

func TestBuildBranchProtectionTable(t *testing.T) {
	tests := []struct {
		name string
		repo *scanners.RepositoryData
		want map[int]string
	}{
		{
			name: "legacy branch protection takes precedence",
			repo: &scanners.RepositoryData{
				BranchProtection: &scanners.BranchProtectionDetail{
					Protected:          true,
					Branch:             "main",
					AllowForcePushes:   false,
					AllowDeletions:     false,
					RequiredSignatures: true,
					RequiredPullRequestReviews: &scanners.RequiredPRReviews{
						RequiredApprovingReviewCount: 2,
						DismissStaleReviews:          true,
						RequireCodeOwnerReviews:      true,
					},
					RequiredStatusChecks: &scanners.RequiredStatusChecks{Strict: true},
				},
				// Ruleset present too, but legacy must win.
				RulesetProtection: &scanners.RulesetProtectionDetail{Protected: true, RulesetCount: 1},
			},
			want: map[int]string{
				colBranch:              "main",
				colProtected:           "Yes",
				colSource:              "Branch Protection",
				colRequiredApprovals:   "2",
				colDismissStale:        "Yes",
				colRequireCodeowners:   "Yes",
				colRequireStatusChecks: "Yes",
				colStrictStatusChecks:  "Yes",
				colAllowForcePushes:    "No",
				colAllowDeletions:      "No",
				colRequiredSignatures:  "Yes",
			},
		},
		{
			name: "ruleset-only protection is reflected",
			repo: &scanners.RepositoryData{
				BranchProtection: &scanners.BranchProtectionDetail{Protected: false},
				RulesetProtection: &scanners.RulesetProtectionDetail{
					Protected:        true,
					Branch:           "main",
					AllowForcePushes: false,
					AllowDeletions:   false,
					RulesetCount:     1,
					RequiredPullRequestReviews: &scanners.RequiredPRReviews{
						RequiredApprovingReviewCount: 1,
					},
				},
			},
			want: map[int]string{
				colBranch:              "main",
				colProtected:           "Yes",
				colSource:              "Ruleset",
				colRequiredApprovals:   "1",
				colDismissStale:        "No",
				colRequireCodeowners:   "No",
				colRequireStatusChecks: "No",
				colStrictStatusChecks:  "",
				colAllowForcePushes:    "No",
				colAllowDeletions:      "No",
				colRequiredSignatures:  "No",
			},
		},
		{
			name: "unprotected repository",
			repo: &scanners.RepositoryData{
				BranchProtection: &scanners.BranchProtectionDetail{Protected: false},
			},
			want: map[int]string{
				colBranch:            "",
				colProtected:         "No",
				colSource:            "None",
				colRequiredApprovals: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]interface{}{
				"repository:owner/repo": tt.repo,
			}

			table := buildBranchProtectionTable(results)
			if len(table) != 1 {
				t.Fatalf("expected 1 row, got %d", len(table))
			}
			row := table[0]
			if len(row) != colCount {
				t.Fatalf("expected %d columns, got %d", colCount, len(row))
			}
			if row[colRepository] != "owner/repo" {
				t.Errorf("repository = %q, want %q", row[colRepository], "owner/repo")
			}
			for idx, want := range tt.want {
				if row[idx] != want {
					t.Errorf("column %d = %q, want %q", idx, row[idx], want)
				}
			}
		})
	}
}
