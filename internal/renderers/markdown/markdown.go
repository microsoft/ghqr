// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/microsoft/ghqr/internal/renderers"
)

// RenderMarkdown produces a Markdown executive report from the scan results map
// following the ghqr-report skill template.
func RenderMarkdown(results map[string]interface{}, outputName string) (string, error) {
	report := buildScanReport(results)
	return renderMarkdownReport(report, outputName)
}

// renderMarkdownReport renders a ScanReport to a markdown file.
func renderMarkdownReport(report *renderers.ScanReport, outputName string) (string, error) {
	md := generateMarkdown(report)

	filename := outputName
	if filename == "" {
		filename = fmt.Sprintf("ghqr_report_%s", time.Now().Format("20060102_150405"))
	}
	outPath := filename + ".md"

	if err := os.WriteFile(outPath, []byte(md), 0600); err != nil {
		return "", fmt.Errorf("failed to write markdown report: %w", err)
	}

	return outPath, nil
}

// buildScanReport constructs the internal ScanReport from raw results,
// reusing the same logic as the JSON renderer.
func buildScanReport(results map[string]interface{}) *renderers.ScanReport {
	report := &renderers.ScanReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Enterprises:   make(map[string]interface{}),
		Organizations: make(map[string]interface{}),
		Repositories:  make(map[string]interface{}),
	}

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

	// Embed evaluation results into their parent entity.
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

	return report
}
