// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateBudgets checks enterprise billing budget configuration for governance best practices.
func (e *Evaluator) EvaluateBudgets(data *scanners.EnterpriseBudgets) *EvaluationResult {
	if data == nil || !data.Available {
		return noDataResult("Enterprise budgets not available (insufficient permissions or feature not enabled)")
	}

	var findings []Issue

	if len(data.Budgets) == 0 {
		e.addFinding(&findings, "ent-budget-001", "")
		return createResult(e, findings)
	}

	// Check if any budget has alerting enabled.
	hasAlerting := false
	for _, b := range data.Budgets {
		if b.BudgetAlerting != nil && b.BudgetAlerting.WillAlert {
			hasAlerting = true
			break
		}
	}
	if !hasAlerting {
		e.addFinding(&findings, "ent-budget-002", "")
	}

	// Check for budgets without "prevent further usage" enabled.
	var unprotected []string
	for _, b := range data.Budgets {
		if !b.PreventFurtherUsage {
			label := fmt.Sprintf("%s/%s", b.BudgetScope, b.ID)
			if b.BudgetEntityName != "" {
				label = fmt.Sprintf("%s/%s", b.BudgetScope, b.BudgetEntityName)
			}
			unprotected = append(unprotected, label)
		}
	}
	if len(unprotected) > 0 {
		e.addFinding(&findings, "ent-budget-003",
			fmt.Sprintf("%d budget(s) do not prevent further usage when exceeded: %s",
				len(unprotected), strings.Join(unprotected, ", ")))
	}

	// Add a positive info finding when budgets are properly configured.
	if hasAlerting && len(unprotected) == 0 {
		addRecommendation(&findings, SeverityInfo, CategoryBudget,
			fmt.Sprintf("%d budget(s) configured with alerting and usage prevention enabled", len(data.Budgets)),
			"Continue monitoring budget consumption regularly for cost governance",
			"https://docs.github.com/en/enterprise-cloud@latest/billing/using-the-new-billing-platform/about-the-new-billing-platform-for-enterprises")
	}

	return createResult(e, findings)
}
