// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"sort"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
	"github.com/rs/zerolog/log"
	"github.com/xuri/excelize/v2"
)

func renderIssues(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "Findings"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create Findings sheet")
		return
	}

	headers := []string{"Type", "Name", "Severity", "Category", "Issue", "Recommendation", "Learn More"}
	createFirstRow(f, sheet, headers, styles)

	rows := buildIssuesTable(results)
	lastRow, err := writeRows(f, sheet, rows, 1)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write Findings rows")
	}

	configureSheet(f, sheet, headers, lastRow, styles)
}

// buildIssuesTable flattens all evaluation results into a sortable table of findings.
func buildIssuesTable(results map[string]interface{}) [][]string {
	type entry struct {
		entityType string
		name       string
		severity   string
		category   string
		issue      string
		rec        string
		learnMore  string
	}

	// Severity order for sorting
	sevOrder := map[string]int{
		bestpractices.SeverityCritical: 0,
		bestpractices.SeverityHigh:     1,
		bestpractices.SeverityMedium:   2,
		bestpractices.SeverityLow:      3,
		bestpractices.SeverityInfo:     4,
	}

	var entries []entry

	for key, val := range results {
		evalResult, ok := val.(*bestpractices.EvaluationResult)
		if !ok {
			continue
		}

		var entityType, name string
		switch {
		case strings.HasPrefix(key, "evaluation:repository:"):
			entityType = "repository"
			name = strings.TrimPrefix(key, "evaluation:repository:")
		case strings.HasPrefix(key, "evaluation:organization:"):
			entityType = "organization"
			name = strings.TrimPrefix(key, "evaluation:organization:")
		case strings.HasPrefix(key, "evaluation:copilot:"):
			entityType = "copilot"
			name = strings.TrimPrefix(key, "evaluation:copilot:")
		case strings.HasPrefix(key, "evaluation:audit_log:"):
			entityType = "audit_log"
			name = strings.TrimPrefix(key, "evaluation:audit_log:")
		case strings.HasPrefix(key, "evaluation:collaborators:"):
			entityType = "collaborators"
			name = strings.TrimPrefix(key, "evaluation:collaborators:")
		case strings.HasPrefix(key, "evaluation:deploy_keys:"):
			entityType = "deploy_keys"
			name = strings.TrimPrefix(key, "evaluation:deploy_keys:")
		case strings.HasPrefix(key, "evaluation:dependabot:"):
			entityType = "dependabot"
			name = strings.TrimPrefix(key, "evaluation:dependabot:")
		case strings.HasPrefix(key, "evaluation:code_scanning:"):
			entityType = "code_scanning"
			name = strings.TrimPrefix(key, "evaluation:code_scanning:")
		case strings.HasPrefix(key, "evaluation:org_security_defaults:"):
			entityType = "org_security_defaults"
			name = strings.TrimPrefix(key, "evaluation:org_security_defaults:")
		case strings.HasPrefix(key, "evaluation:discussions:"):
			entityType = "discussions"
			name = strings.TrimPrefix(key, "evaluation:discussions:")
		case strings.HasPrefix(key, "evaluation:actions_permissions:"):
			entityType = "actions_permissions"
			name = strings.TrimPrefix(key, "evaluation:actions_permissions:")
		case strings.HasPrefix(key, "evaluation:org_security_alerts:"):
			entityType = "org_security_alerts"
			name = strings.TrimPrefix(key, "evaluation:org_security_alerts:")
		case strings.HasPrefix(key, "evaluation:enterprise_security_alerts:"):
			entityType = "enterprise_security_alerts"
			name = strings.TrimPrefix(key, "evaluation:enterprise_security_alerts:")
		case strings.HasPrefix(key, "evaluation:security_managers:"):
			entityType = "security_managers"
			name = strings.TrimPrefix(key, "evaluation:security_managers:")
		case strings.HasPrefix(key, "evaluation:metadata:"):
			entityType = "metadata"
			name = strings.TrimPrefix(key, "evaluation:metadata:")
		default:
			continue
		}

		for _, rec := range evalResult.Recommendations {
			entries = append(entries, entry{
				entityType: entityType,
				name:       name,
				severity:   rec.Severity,
				category:   rec.Category,
				issue:      rec.Issue,
				rec:        rec.Recommendation,
				learnMore:  rec.LearnMore,
			})
		}
	}

	// Sort by severity then entity name
	sort.Slice(entries, func(i, j int) bool {
		si := sevOrder[entries[i].severity]
		sj := sevOrder[entries[j].severity]
		if si != sj {
			return si < sj
		}
		return entries[i].name < entries[j].name
	})

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			e.entityType,
			e.name,
			e.severity,
			e.category,
			e.issue,
			e.rec,
			e.learnMore,
		})
	}
	return rows
}
