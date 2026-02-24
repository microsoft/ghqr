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

func renderRepositories(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "Repositories"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create Repositories sheet")
		return
	}

	headers := []string{
		"Repository", "Organization", "Enterprise",
		"Visibility", "Private", "Archived", "Fork",
		"Default Branch", "Language", "License",
		"Total Issues", "Critical", "High", "Medium", "Low",
	}
	createFirstRow(f, sheet, headers, styles)

	rows := buildRepositoriesTable(results)
	lastRow, err := writeRows(f, sheet, rows, 1)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write Repositories rows")
	}

	configureSheet(f, sheet, headers, lastRow, styles)
}

func buildRepositoriesTable(results map[string]interface{}) [][]string {
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

		ownerOrg := repoData.Organization
		ownerEnterprise := repoData.Enterprise

		visibility, private, archived, fork := "", "", "", ""
		defaultBranch, language, license := "", "", ""

		if a := repoData.Access; a != nil {
			visibility = a.Visibility
			private = boolStr(a.Private)
			archived = boolStr(a.Archived)
			fork = boolStr(a.Fork)
		}
		if m := repoData.Metadata; m != nil {
			defaultBranch = m.DefaultBranch
			language = m.Language
			license = m.License
		}

		total, critical, high, medium, low := "", "", "", "", ""
		evalKey := "evaluation:repository:" + name
		if evalVal, ok := results[evalKey]; ok {
			if eval, ok := evalVal.(*bestpractices.EvaluationResult); ok {
				if s := eval.Summary; s != nil {
					total = fmt.Sprintf("%d", s.TotalIssues)
					critical = fmt.Sprintf("%d", s.Critical)
					high = fmt.Sprintf("%d", s.HighSeverity)
					medium = fmt.Sprintf("%d", s.MediumSeverity)
					low = fmt.Sprintf("%d", s.LowSeverity)
				}
			}
		}

		rows = append(rows, row{name: name, cols: []string{
			name, ownerOrg, ownerEnterprise,
			visibility, private, archived, fork,
			defaultBranch, language, license,
			total, critical, high, medium, low,
		}})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}
