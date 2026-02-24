// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateDependabotConfig evaluates Dependabot configuration
func (e *Evaluator) EvaluateDependabotConfig(config *scanners.DependabotConfigInfo, dependabotInfo *scanners.DependabotInfo) *EvaluationResult {
	var issues []Issue
	var recommendations []Issue

	if config == nil || !config.Exists {
		if dependabotInfo != nil && dependabotInfo.Enabled {
			addIssue(&issues, SeverityMedium, CategorySecurity,
				"Dependabot alerts enabled but no dependabot.yml configuration found",
				"Create .github/dependabot.yml to enable automated dependency updates",
				"https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file")
		} else {
			addIssue(&issues, SeverityHigh, CategorySecurity,
				"Dependabot is not configured",
				"Enable Dependabot alerts and create .github/dependabot.yml for automated security and version updates",
				"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
		}
		return createResult(e, issues, recommendations)
	}

	addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
		fmt.Sprintf("Dependabot configured at %s", config.Path),
		"Good! Dependabot helps keep dependencies up-to-date",
		"https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")

	return createResult(e, issues, recommendations)
}

// EvaluateCodeScanningConfig evaluates code scanning configuration
func (e *Evaluator) EvaluateCodeScanningConfig(config *scanners.CodeScanningConfigInfo) *EvaluationResult {
	var issues []Issue
	var recommendations []Issue

	if config == nil {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Code scanning (CodeQL) is not configured",
			"Enable GitHub code scanning (CodeQL) to automatically detect security vulnerabilities",
			"https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning")
		return createResult(e, issues, recommendations)
	}

	if config.CodeQLConfigExists {
		addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
			fmt.Sprintf("CodeQL configuration found at %s", config.CodeQLConfigPath),
			"Custom CodeQL configuration allows fine-tuned security scanning",
			"https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
			"No CodeQL configuration file detected",
			"Consider creating a custom CodeQL config for extended security queries",
			"https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning")
	}

	return createResult(e, issues, recommendations)
}
