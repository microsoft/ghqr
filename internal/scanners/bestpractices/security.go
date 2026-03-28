// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateDependabotConfig evaluates Dependabot configuration.
func (e *Evaluator) EvaluateDependabotConfig(config *scanners.DependabotConfigInfo, dependabotInfo *scanners.DependabotInfo) *EvaluationResult {
	var findings []Issue

	if config == nil || !config.Exists {
		if dependabotInfo != nil && dependabotInfo.Enabled {
			e.addFinding(&findings, "repo-sec-006", "")
		} else {
			e.addFinding(&findings, "repo-sec-007", "")
		}
		return createResult(e, findings)
	}

	// Informational: Dependabot is configured — positive confirmation.
	addRecommendation(&findings, SeverityInfo, CategorySecurity,
		fmt.Sprintf("Dependabot configured at %s", config.Path),
		"Good! Dependabot helps keep dependencies up-to-date",
		"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")

	return createResult(e, findings)
}

// EvaluateCodeScanningConfig evaluates code scanning configuration.
func (e *Evaluator) EvaluateCodeScanningConfig(config *scanners.CodeScanningConfigInfo) *EvaluationResult {
	var findings []Issue

	if config == nil {
		e.addFinding(&findings, "repo-sec-008", "")
		return createResult(e, findings)
	}

	if config.CodeQLConfigExists {
		addRecommendation(&findings, SeverityInfo, CategorySecurity,
			fmt.Sprintf("CodeQL configuration found at %s", config.CodeQLConfigPath),
			"Custom CodeQL configuration allows fine-tuned security scanning",
			"https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning")
	} else {
		e.addFinding(&findings, "repo-sec-009", "")
	}

	return createResult(e, findings)
}
