// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"encoding/json"
	"sort"

	"github.com/microsoft/ghqr/internal/renderers"
)

// collectAllFindings extracts every recommendation from all entities.
func collectAllFindings(report *renderers.ScanReport) []entityFindings {
	var all []entityFindings

	// Enterprise findings
	for name, data := range report.Enterprises {
		ef := entityFindings{EntityName: name, EntityType: "enterprise"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "enterprise_security_alerts_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Organization findings
	for name, data := range report.Organizations {
		ef := entityFindings{EntityName: name, EntityType: "org"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "copilot_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "actions_permissions_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "org_security_alerts_evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "security_managers_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Repository findings
	for name, data := range report.Repositories {
		ef := entityFindings{EntityName: name, EntityType: "repo"}
		ef.Findings = append(ef.Findings, extractRecommendations(data, "evaluation")...)
		ef.Findings = append(ef.Findings, extractRecommendations(data, "metadata_evaluation")...)
		if len(ef.Findings) > 0 {
			all = append(all, ef)
		}
	}

	// Sort: enterprises first, then orgs, then repos
	sort.Slice(all, func(i, j int) bool {
		typeOrder := map[string]int{"enterprise": 0, "org": 1, "repo": 2}
		if typeOrder[all[i].EntityType] != typeOrder[all[j].EntityType] {
			return typeOrder[all[i].EntityType] < typeOrder[all[j].EntityType]
		}
		return all[i].EntityName < all[j].EntityName
	})

	return all
}

// extractRecommendations parses the recommendations array from an evaluation field.
func extractRecommendations(data interface{}, evalField string) []recommendation {
	m := asMap(data)
	if m == nil {
		return nil
	}

	evalData, ok := m[evalField]
	if !ok {
		return nil
	}

	evalMap := asMap(evalData)
	if evalMap == nil {
		return nil
	}

	recsRaw, ok := evalMap["recommendations"]
	if !ok || recsRaw == nil {
		return nil
	}

	// Marshal and unmarshal to get typed recommendations.
	b, err := json.Marshal(recsRaw)
	if err != nil {
		return nil
	}

	var recs []recommendation
	if err := json.Unmarshal(b, &recs); err != nil {
		return nil
	}

	return recs
}

// countBySeverity aggregates finding counts by severity level.
func countBySeverity(allFindings []entityFindings) map[string]int {
	counts := map[string]int{}
	for _, ef := range allFindings {
		for _, r := range ef.Findings {
			counts[r.Severity]++
		}
	}
	return counts
}

// determineScopeName picks the primary scope name for the report title.
func determineScopeName(report *renderers.ScanReport) (string, string) {
	if len(report.Enterprises) > 0 {
		for name := range report.Enterprises {
			return name, "Enterprise"
		}
	}
	if len(report.Organizations) > 0 {
		for name := range report.Organizations {
			return name, "Organization"
		}
	}
	if len(report.Repositories) > 0 {
		for name := range report.Repositories {
			return name, "Repository"
		}
	}
	return "Unknown", "Unknown"
}

// asMap round-trips v through JSON to produce a map[string]interface{},
// allowing evaluation results to be embedded into existing entity objects.
func asMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}
