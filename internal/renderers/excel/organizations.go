// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
)

func renderOrganizations(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "Organizations"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create Organizations sheet")
		return
	}

	headers := []string{
		"Organization", "Enterprise",
		"Default Repo Permission", "Members Can Create Public Repos",
		"2FA Required", "Web Commit Signoff Required",
		"Advanced Security New Repos", "Dependabot Alerts New Repos",
		"Total Issues",
	}
	createFirstRow(f, sheet, headers, styles)

	rows := buildOrganizationsTable(results)
	lastRow, err := writeRows(f, sheet, rows, 1)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write Organizations rows")
	}

	configureSheet(f, sheet, headers, lastRow, styles)
}

func buildOrganizationsTable(results map[string]interface{}) [][]string {
	type row struct {
		name string
		cols []string
	}

	var rows []row

	for key, val := range results {
		if !strings.HasPrefix(key, "organization:") {
			continue
		}
		name := strings.TrimPrefix(key, "organization:")
		orgData, ok := val.(*scanners.OrganizationData)
		if !ok {
			continue
		}

		ownerEnterprise := orgData.Enterprise

		defaultRepoPerm := ""
		membersCanCreatePublic := ""
		twoFA := ""
		webCommitSignoff := ""
		advSecNewRepos := ""
		dependabotAlertsNewRepos := ""

		if s := orgData.Settings; s != nil {
			defaultRepoPerm = s.Visibility.DefaultRepositoryPermission
			membersCanCreatePublic = boolStr(s.Visibility.MembersCanCreatePublicRepositories)
			if s.Security.EMUEnabled {
				twoFA = "IdP (EMU)"
			} else {
				twoFA = boolStr(s.Security.TwoFactorRequirementEnabled)
			}
			webCommitSignoff = boolStr(s.Security.WebCommitSignoffRequired)
			advSecNewRepos = boolStr(s.Security.AdvancedSecurityForNewRepos)
			dependabotAlertsNewRepos = boolStr(s.Security.DependabotAlertsForNewRepos)
		}

		total := ""
		evalKey := "evaluation:organization:" + name
		if evalVal, ok := results[evalKey]; ok {
			if eval, ok := evalVal.(*bestpractices.EvaluationResult); ok {
				if s := eval.Summary; s != nil {
					total = fmt.Sprintf("%d", s.TotalIssues)
				}
			}
		}

		rows = append(rows, row{name: name, cols: []string{
			name, ownerEnterprise,
			defaultRepoPerm, membersCanCreatePublic,
			twoFA, webCommitSignoff,
			advSecNewRepos, dependabotAlertsNewRepos,
			total,
		}})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}
