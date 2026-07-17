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

// renderBudgets writes the Budgets sheet, listing every enterprise billing
// budget with its scope, amount, alerting, and usage-prevention configuration.
func renderBudgets(f *excelize.File, results map[string]interface{}, styles *StyleCache) {
	const sheet = "Budgets"
	if _, err := f.NewSheet(sheet); err != nil {
		log.Error().Err(err).Msg("Failed to create Budgets sheet")
		return
	}

	headers := []string{
		"Enterprise", "Budget Entity", "Scope", "Type", "Product/SKUs",
		"Amount ($)", "Prevent Overage", "Alerting", "Alert Recipients", "Budget ID",
	}

	data := buildBudgetsTable(results)
	rows := append([][]string{headers}, data...)
	streamSheet(f, sheet, rows, styles)
}

func buildBudgetsTable(results map[string]interface{}) [][]string {
	type row struct {
		enterprise string
		entity     string
		cols       []string
	}

	var rows []row

	for key, val := range results {
		if !strings.HasPrefix(key, "enterprise:") {
			continue
		}
		name := strings.TrimPrefix(key, "enterprise:")
		entData := asType[scanners.EnterpriseData](val)
		if entData == nil {
			continue
		}

		budgets := entData.Budgets

		// Distinguish "no access" from "zero budgets configured" so the sheet
		// never silently hides an enterprise.
		if budgets == nil || !budgets.Available {
			rows = append(rows, row{enterprise: name, cols: []string{
				name, "—", "N/A", "Budget data not available (no access)", "", "", "", "", "", "",
			}})
			continue
		}
		if len(budgets.Budgets) == 0 {
			rows = append(rows, row{enterprise: name, cols: []string{
				name, "—", "—", "No budgets configured", "", "", "", "", "", "",
			}})
			continue
		}

		for _, b := range budgets.Budgets {
			if b == nil {
				continue
			}
			entity := b.BudgetEntityName
			if entity == "" {
				entity = "—"
			}
			skus := ""
			if len(b.BudgetProductSkus) > 0 {
				skus = strings.Join(b.BudgetProductSkus, ", ")
			}
			alerting := "No"
			recipients := ""
			if b.BudgetAlerting != nil {
				alerting = boolStr(b.BudgetAlerting.WillAlert)
				recipients = strings.Join(b.BudgetAlerting.AlertRecipients, ", ")
			}

			rows = append(rows, row{enterprise: name, entity: b.BudgetEntityName, cols: []string{
				name, entity, b.BudgetScope, b.BudgetType, skus,
				strconv.Itoa(b.BudgetAmount), boolStr(b.PreventFurtherUsage),
				alerting, recipients, b.ID,
			}})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].enterprise != rows[j].enterprise {
			return rows[i].enterprise < rows[j].enterprise
		}
		return rows[i].entity < rows[j].entity
	})

	result := make([][]string, 0, len(rows))
	for _, r := range rows {
		result = append(result, r.cols)
	}
	return result
}
