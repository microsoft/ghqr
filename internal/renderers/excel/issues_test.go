// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"testing"

	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
)

func TestBuildIssuesTable_EnterpriseBudgetsAndGHAS(t *testing.T) {
	results := map[string]interface{}{
		"evaluation:enterprise_budgets:acme": &bestpractices.EvaluationResult{
			Recommendations: []bestpractices.Issue{
				{
					Severity:       bestpractices.SeverityInfo,
					Category:       bestpractices.CategoryBudget,
					Issue:          "19 budget(s) configured",
					Recommendation: "Keep monitoring",
				},
			},
		},
		"evaluation:enterprise_ghas:acme": &bestpractices.EvaluationResult{
			Recommendations: []bestpractices.Issue{
				{
					Severity:       bestpractices.SeverityHigh,
					Category:       bestpractices.CategorySecurity,
					Issue:          "Advanced Security not enabled by default",
					Recommendation: "Enable GHAS defaults",
				},
			},
		},
	}

	rows := buildIssuesTable(results)

	found := map[string]string{} // entityType -> issue text
	for _, r := range rows {
		// columns: Type, Name, Severity, Category, Issue, Recommendation, Learn More
		found[r[0]] = r[4]
	}

	if got, ok := found["enterprise_budgets"]; !ok || got != "19 budget(s) configured" {
		t.Errorf("enterprise_budgets finding missing/incorrect: %q (present=%v)", got, ok)
	}
	if got, ok := found["enterprise_ghas"]; !ok || got != "Advanced Security not enabled by default" {
		t.Errorf("enterprise_ghas finding missing/incorrect: %q (present=%v)", got, ok)
	}
}
