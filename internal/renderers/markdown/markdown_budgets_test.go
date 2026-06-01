// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"strings"
	"testing"

	"github.com/microsoft/ghqr/internal/renderers"
)

func TestGenerateBudgetOverview_UnavailableBudgetsScopeGuidance(t *testing.T) {
	report := &renderers.ScanReport{
		Enterprises: map[string]interface{}{
			"contoso": map[string]interface{}{
				"budgets": map[string]interface{}{
					"available": false,
				},
			},
		},
	}

	out := generateBudgetOverview(report)

	if !strings.Contains(out, "`manage_billing:enterprise` scope") {
		t.Fatalf("expected least-privilege budget scope guidance in output, got:\n%s", out)
	}
	if strings.Contains(out, "`admin:enterprise`") {
		t.Fatalf("expected admin scope to be removed from guidance, got:\n%s", out)
	}
}
