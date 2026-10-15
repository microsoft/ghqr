// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"sort"
	"strconv"
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
		"Advanced Security New Repos (legacy)", "Dependabot Alerts New Repos (legacy)",
		"Default Code Security Config (New Repos)",
		"Total Issues",
	}

	data := buildOrganizationsTable(results)
	rows := append([][]string{headers}, data...)
	streamSheet(f, sheet, rows, styles)
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
		orgData := asType[scanners.OrganizationData](val)
		if orgData == nil {
			continue
		}

		ownerEnterprise := orgData.Enterprise

		defaultRepoPerm := ""
		membersCanCreatePublic := ""
		twoFA := ""
		webCommitSignoff := ""
		advSecNewRepos := ""
		dependabotAlertsNewRepos := ""
		defaultCodeSecurityConfig := ""

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
			defaultCodeSecurityConfig = describeDefaultCodeSecurityConfigs(s.Security.CodeSecurityConfigurations)
		}

		total := ""
		evalKey := "evaluation:organization:" + name
		if evalVal, ok := results[evalKey]; ok {
			if eval, ok := evalVal.(*bestpractices.EvaluationResult); ok {
				if s := eval.Summary; s != nil {
					total = strconv.Itoa(s.TotalIssues)
				}
			}
		}

		rows = append(rows, row{name: name, cols: []string{
			name, ownerEnterprise,
			defaultRepoPerm, membersCanCreatePublic,
			twoFA, webCommitSignoff,
			advSecNewRepos, dependabotAlertsNewRepos,
			defaultCodeSecurityConfig,
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

// describeDefaultCodeSecurityConfigs renders the organization's default code security
// configurations for new repositories as "scope: name" pairs, distinguishing data that
// was not collected (empty), not readable, and readable with no default set ("none").
func describeDefaultCodeSecurityConfigs(csc *scanners.OrgCodeSecurityConfigurations) string {
	if csc == nil {
		return ""
	}
	if !csc.DefaultsReadable {
		return "not readable (" + csc.DefaultsUnavailableReason + ")"
	}
	parts := make([]string, 0, len(csc.DefaultConfigurations))
	for _, d := range csc.DefaultConfigurations {
		if d == nil {
			continue
		}
		name := "unknown"
		if cfg := d.GetConfiguration(); cfg != nil {
			name = cfg.Name
		}
		parts = append(parts, d.GetDefaultForNewRepos()+": "+name)
	}
	if len(parts) == 0 {
		return "none"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
