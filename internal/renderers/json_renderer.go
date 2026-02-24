// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package renderers

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanSummary is included in the report when OnlyIssues is set.
type ScanSummary struct {
	TotalScanned int            `json:"total_scanned"`
	NonCompliant int            `json:"non_compliant"`
	SkippedClean int            `json:"skipped_clean"`
	BySeverity   map[string]int `json:"by_severity,omitempty"`
}

// ScanReport is the top-level JSON summary written by the JSON renderer.
type ScanReport struct {
	GeneratedAt   string                 `json:"generated_at"`
	Summary       *ScanSummary           `json:"summary,omitempty"`
	Enterprises   map[string]interface{} `json:"enterprises,omitempty"`
	Organizations map[string]interface{} `json:"organizations,omitempty"`
	Repositories  map[string]interface{} `json:"repositories,omitempty"`
}

// RenderJSON writes a consolidated JSON report from the results map.
// Keys in results follow: "enterprise:<slug>", "organization:<name>", "repository:<owner>/<repo>".
func RenderJSON(results map[string]interface{}, outputName string) (string, error) {
	report := &ScanReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Enterprises:   make(map[string]interface{}),
		Organizations: make(map[string]interface{}),
		Repositories:  make(map[string]interface{}),
	}

	// First pass: populate entity maps.
	for key, data := range results {
		switch {
		case strings.HasPrefix(key, "enterprise:"):
			report.Enterprises[strings.TrimPrefix(key, "enterprise:")] = data
		case strings.HasPrefix(key, "organization:"):
			report.Organizations[strings.TrimPrefix(key, "organization:")] = data
		case strings.HasPrefix(key, "repository:"):
			report.Repositories[strings.TrimPrefix(key, "repository:")] = data
		}
	}

	// Second pass: embed evaluation results into their parent entity.
	type evalMapping struct {
		prefix    string
		field     string
		targetMap map[string]interface{}
	}
	mappings := []evalMapping{
		{"evaluation:organization:", "evaluation", report.Organizations},
		{"evaluation:copilot:", "copilot_evaluation", report.Organizations},
		{"evaluation:repository:", "evaluation", report.Repositories},
		{"evaluation:actions_permissions:", "actions_permissions_evaluation", report.Organizations},
		{"evaluation:org_security_alerts:", "org_security_alerts_evaluation", report.Organizations},
		{"evaluation:security_managers:", "security_managers_evaluation", report.Organizations},
		{"evaluation:enterprise_security_alerts:", "enterprise_security_alerts_evaluation", report.Enterprises},
		{"evaluation:metadata:", "metadata_evaluation", report.Repositories},
	}
	for key, eval := range results {
		for _, m := range mappings {
			if !strings.HasPrefix(key, m.prefix) {
				continue
			}
			name := strings.TrimPrefix(key, m.prefix)
			if entityMap := asMap(m.targetMap[name]); entityMap != nil {
				entityMap[m.field] = eval
				m.targetMap[name] = entityMap
			}
			break
		}
	}

	// Third pass: replace raw collaborator and deploy-key arrays with compact count summaries.
	// This reduces output size significantly without losing any information needed for evaluation.
	for name, entityData := range report.Repositories {
		entityMap, ok := entityData.(map[string]interface{})
		if !ok {
			continue
		}

		if collabs, ok := entityMap["collaborators"].([]interface{}); ok {
			counts := map[string]int{}
			for _, c := range collabs {
				if cm, ok := c.(map[string]interface{}); ok {
					if perm, ok := cm["permissions"].(string); ok {
						counts[strings.ToLower(perm)]++
					}
				}
			}
			entityMap["collaborator_summary"] = counts
			delete(entityMap, "collaborators")
		}

		if keys, ok := entityMap["deploy_keys"].([]interface{}); ok {
			writeable, unverified := 0, 0
			for _, k := range keys {
				if km, ok := k.(map[string]interface{}); ok {
					if ro, ok := km["read_only"].(bool); ok && !ro {
						writeable++
					}
					if v, ok := km["verified"].(bool); ok && !v {
						unverified++
					}
				}
			}
			entityMap["deploy_key_summary"] = map[string]int{
				"total":      len(keys),
				"writeable":  writeable,
				"unverified": unverified,
			}
			delete(entityMap, "deploy_keys")
		}

		report.Repositories[name] = entityMap
	}

	filename := outputName
	if filename == "" {
		filename = fmt.Sprintf("ghqr_report_%s", time.Now().Format("20060102_150405"))
	}
	outPath := filename + ".json"

	var (
		jsonData []byte
		err      error
	)
	jsonData, err = json.MarshalIndent(report, "", "\t")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(outPath, jsonData, 0600); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return outPath, nil
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
