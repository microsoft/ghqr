// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"encoding/json"
	"testing"

	"github.com/microsoft/ghqr/internal/scanners"
)

func TestBuildBudgetsTable(t *testing.T) {
	ent := &scanners.EnterpriseData{
		Budgets: &scanners.EnterpriseBudgets{
			Available:  true,
			TotalCount: 2,
			Budgets: []*scanners.BudgetEntry{
				{
					ID:                  "b-1",
					BudgetType:          "BundlePricing",
					BudgetScope:         "enterprise",
					BudgetEntityName:    "acme",
					BudgetAmount:        1000,
					PreventFurtherUsage: true,
					BudgetProductSkus:   []string{"actions", "copilot"},
					BudgetAlerting: &scanners.BudgetAlertConfig{
						WillAlert:       true,
						AlertRecipients: []string{"U1", "U2"},
					},
				},
				{
					ID:           "b-2",
					BudgetType:   "BundlePricing",
					BudgetScope:  "organization",
					BudgetAmount: 50,
					// No alerting configured.
				},
			},
		},
	}

	t.Run("live struct and replay map produce identical rows", func(t *testing.T) {
		replay := toMap(t, ent)
		for label, val := range map[string]interface{}{"struct": ent, "map": replay} {
			results := map[string]interface{}{"enterprise:acme": val}
			table := buildBudgetsTable(results)
			if len(table) != 2 {
				t.Fatalf("[%s] expected 2 rows, got %d", label, len(table))
			}
			// Rows are sorted by entity name; the budget with an empty entity
			// ("—") sorts before "acme".
			r0 := table[0]
			want0 := []string{"acme", "—", "organization", "BundlePricing", "", "50", "No", "No", "", "b-2"}
			assertRow(t, label+"/row0", r0, want0)
			r1 := table[1]
			want1 := []string{"acme", "acme", "enterprise", "BundlePricing", "actions, copilot", "1000", "Yes", "Yes", "U1, U2", "b-1"}
			assertRow(t, label+"/row1", r1, want1)
		}
	})

	t.Run("no access", func(t *testing.T) {
		results := map[string]interface{}{
			"enterprise:acme": &scanners.EnterpriseData{
				Budgets: &scanners.EnterpriseBudgets{Available: false},
			},
		}
		table := buildBudgetsTable(results)
		if len(table) != 1 {
			t.Fatalf("expected 1 row, got %d", len(table))
		}
		if table[0][3] != "Budget data not available (no access)" {
			t.Errorf("type column = %q", table[0][3])
		}
	})

	t.Run("available but zero budgets", func(t *testing.T) {
		results := map[string]interface{}{
			"enterprise:acme": &scanners.EnterpriseData{
				Budgets: &scanners.EnterpriseBudgets{Available: true},
			},
		}
		table := buildBudgetsTable(results)
		if len(table) != 1 {
			t.Fatalf("expected 1 row, got %d", len(table))
		}
		if table[0][3] != "No budgets configured" {
			t.Errorf("type column = %q", table[0][3])
		}
	})
}

func TestBuildGHASTable(t *testing.T) {
	ent := &scanners.EnterpriseData{
		GHASSettings: &scanners.EnterpriseGHASSettings{
			AdvancedSecurity:                  "enabled",
			SecretScanning:                    "enabled",
			SecretScanningPushProtection:      "disabled",
			DependabotAlerts:                  "enabled",
			DependabotSecurityUpdates:         "not_set",
			DependencyGraph:                   "enabled",
			SecretScanningNonProviderPatterns: "", // -> not_set
		},
	}

	t.Run("live struct and replay map produce identical rows", func(t *testing.T) {
		replay := toMap(t, ent)
		want := []string{"acme", "enabled", "enabled", "disabled", "enabled", "not_set", "enabled", "not_set"}
		for label, val := range map[string]interface{}{"struct": ent, "map": replay} {
			results := map[string]interface{}{"enterprise:acme": val}
			table := buildGHASTable(results)
			if len(table) != 1 {
				t.Fatalf("[%s] expected 1 row, got %d", label, len(table))
			}
			assertRow(t, label, table[0], want)
		}
	})

	t.Run("settings not available", func(t *testing.T) {
		results := map[string]interface{}{
			"enterprise:acme": &scanners.EnterpriseData{},
		}
		table := buildGHASTable(results)
		if len(table) != 1 {
			t.Fatalf("expected 1 row, got %d", len(table))
		}
		for i := 1; i < len(table[0]); i++ {
			if table[0][i] != "Not available" {
				t.Errorf("column %d = %q, want %q", i, table[0][i], "Not available")
			}
		}
	})
}

// toMap round-trips a value through JSON to emulate the map[string]interface{}
// shape stored when replaying a scan from a JSON file (--from-json).
func toMap(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func assertRow(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("[%s] row len = %d, want %d (%v)", label, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%s] col %d = %q, want %q", label, i, got[i], want[i])
		}
	}
}
