// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/renderers"
	"github.com/microsoft/ghqr/internal/scanners"
)

// generateBudgetOverview renders the Budget Overview section that appears right
// after the Executive Summary when enterprise data is present.
func generateBudgetOverview(report *renderers.ScanReport) string {
	if len(report.Enterprises) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Budget Overview\n\n")

	for name, data := range report.Enterprises {
		budgets := extractBudgets(data)
		if budgets == nil || !budgets.Available {
			sb.WriteString(fmt.Sprintf("### Enterprise: %s\n\n", name))
			sb.WriteString("> 🚨 **Alert:** Budget data is not available for this enterprise. ")
			sb.WriteString("To access budget data, use a **classic Personal Access Token** (fine-grained PATs are not supported) with the `manage_billing:enterprise` scope, ")
			sb.WriteString("and the authenticated user must be an **enterprise admin** or **billing manager**. ")
			sb.WriteString("Alternatively, the enhanced billing platform may not be enabled for this enterprise.\n\n")
			continue
		}

		sb.WriteString(fmt.Sprintf("### Enterprise: %s\n\n", name))

		if len(budgets.Budgets) == 0 {
			sb.WriteString("> 🚨 **Alert — No budgets configured.** There are no billing budgets defined for this enterprise. ")
			sb.WriteString("This represents a **critical governance risk** — usage-based spending (Actions, Copilot, Packages) is unbounded. ")
			sb.WriteString("Configure budgets immediately to establish spending controls.\n\n")
			continue
		}

		// Summary counts by scope.
		scopeCounts := map[string]int{}
		alertingCount := 0
		preventCount := 0
		for _, b := range budgets.Budgets {
			scopeCounts[b.BudgetScope]++
			if b.BudgetAlerting != nil && b.BudgetAlerting.WillAlert {
				alertingCount++
			}
			if b.PreventFurtherUsage {
				preventCount++
			}
		}

		sb.WriteString(fmt.Sprintf("> ✅ **%d budget(s) configured** — ", len(budgets.Budgets)))
		sb.WriteString(fmt.Sprintf("%d with alerting enabled, %d with usage prevention.\n\n", alertingCount, preventCount))

		// Budget table.
		sb.WriteString("| Scope | Entity | Product/SKU | Amount ($) | Alerting | Prevent Overage |\n")
		sb.WriteString("|-------|--------|-------------|-----------|----------|----------------|\n")
		for _, b := range budgets.Budgets {
			entity := b.BudgetEntityName
			if entity == "" {
				entity = "—"
			}
			skus := "—"
			if len(b.BudgetProductSkus) > 0 {
				skus = strings.Join(b.BudgetProductSkus, ", ")
			}
			alerting := "❌ No"
			if b.BudgetAlerting != nil && b.BudgetAlerting.WillAlert {
				alerting = "✅ Yes"
			}
			prevent := "❌ No"
			if b.PreventFurtherUsage {
				prevent = "✅ Yes"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s | %s |\n",
				b.BudgetScope, entity, skus, b.BudgetAmount, alerting, prevent))
		}
		sb.WriteString("\n")

		// Warnings inline.
		if alertingCount == 0 {
			sb.WriteString("> ⚠️ **Warning:** No budgets have alerting enabled. Admins will not receive notifications when spending approaches limits.\n\n")
		}
		noPrevent := len(budgets.Budgets) - preventCount
		if noPrevent > 0 {
			sb.WriteString(fmt.Sprintf("> ⚠️ **Warning:** %d budget(s) do not prevent further usage when exceeded. Spending can continue past configured limits.\n\n", noPrevent))
		}
	}

	sb.WriteString("---\n\n")
	return sb.String()
}

// extractBudgets extracts EnterpriseBudgets from the raw enterprise data map.
func extractBudgets(data interface{}) *scanners.EnterpriseBudgets {
	m := asMap(data)
	if m == nil {
		return nil
	}

	budgetsRaw, ok := m["budgets"]
	if !ok || budgetsRaw == nil {
		return nil
	}

	b, err := json.Marshal(budgetsRaw)
	if err != nil {
		return nil
	}

	var budgets scanners.EnterpriseBudgets
	if err := json.Unmarshal(b, &budgets); err != nil {
		return nil
	}

	return &budgets
}
