// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import "testing"

func TestCollectAllFindings_IncludesOrgSecurityDefaults(t *testing.T) {
	results := map[string]interface{}{
		"organization:acme": map[string]interface{}{"login": "acme"},
		"evaluation:org_security_defaults:acme": map[string]interface{}{
			"recommendations": []interface{}{
				map[string]interface{}{
					"rule_id":  "org-def-004",
					"severity": "high",
					"category": "security",
					"issue":    "Secret scanning not enabled by default for new repositories",
				},
			},
		},
	}

	all := collectAllFindings(buildScanReport(results))
	if len(all) != 1 || all[0].EntityName != "acme" {
		t.Fatalf("expected findings for org acme, got %+v", all)
	}
	if got := len(all[0].Findings); got != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", got)
	}
}
