// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"github.com/microsoft/ghqr/internal/recommendations"
	"github.com/microsoft/ghqr/internal/scanners"
)

// Severity levels for issues and recommendations
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Category types for issues
const (
	CategorySecurity          = "security"
	CategoryAccessControl     = "access_control"
	CategoryBranchProtection  = "branch_protection"
	CategoryCopilotSecurity   = "copilot_security"
	CategoryCopilotCost       = "copilot_cost"
	CategoryCopilotFeatures   = "copilot_features"
	CategoryCopilotModels     = "copilot_models"
	CategoryCopilotMCP        = "copilot_mcp"
	CategoryCopilotExtensions = "copilot_extensions"
	CategoryActions           = "actions"
	CategoryFeatures          = "features"
	CategoryAccess            = "access"
	CategoryMaintenance       = "maintenance"
	CategoryPermissions       = "permissions"
	CategoryDeployment        = "deployment"
	CategoryRisk              = "risk"
	CategoryDependencies      = "dependencies"
	CategoryCommunity         = "community"
)

// Issue represents a finding (issue or recommendation)
type Issue struct {
	RuleID         string `json:"rule_id,omitempty"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
	LearnMore      string `json:"learn_more,omitempty"`
}

// EvaluationResult represents the evaluation result
type EvaluationResult struct {
	Recommendations []Issue  `json:"recommendations"`
	Summary         *Summary `json:"summary"`
	Message         string   `json:"message,omitempty"`
}

// Summary provides a summary of evaluation results
type Summary struct {
	TotalIssues    int `json:"total_issues"`
	Critical       int `json:"critical,omitempty"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
	Info           int `json:"info,omitempty"`
}

// Evaluator provides best practices evaluation
type Evaluator struct {
	registry *recommendations.Registry
}

// NewEvaluator creates a new evaluator backed by the provided rule registry.
func NewEvaluator(registry *recommendations.Registry) *Evaluator {
	return &Evaluator{registry: registry}
}

// Helper functions to reduce repetition

// addFinding looks up the rule in the registry and appends a finding to the slice.
// If the rule is not found or is disabled, no finding is added.
// The title override allows callers to supply a dynamic message (e.g. alert counts)
// while still pulling severity, category, and learnMore from the registry.
func (e *Evaluator) addFinding(findings *[]Issue, ruleID, titleOverride string) {
	if e.registry == nil {
		return
	}
	def, ok := e.registry.Get(ruleID)
	if !ok || !def.Enabled {
		return
	}
	title := def.Title
	if titleOverride != "" {
		title = titleOverride
	}
	*findings = append(*findings, Issue{
		RuleID:         def.ID,
		Severity:       def.Severity,
		Category:       def.Category,
		Issue:          title,
		Recommendation: def.Recommendation,
		LearnMore:      def.LearnMore,
	})
}

func addRecommendation(recommendations *[]Issue, severity, category, issue, recommendation string, learnMore ...string) {
	url := ""
	if len(learnMore) > 0 {
		url = learnMore[0]
	}
	*recommendations = append(*recommendations, Issue{
		Severity:       severity,
		Category:       category,
		Issue:          issue,
		Recommendation: recommendation,
		LearnMore:      url,
	})
}

func checkEnabled(feature *scanners.SecurityFeature) bool {
	return feature != nil && feature.Enabled
}

func createResult(e *Evaluator, findings []Issue) *EvaluationResult {
	return &EvaluationResult{
		Recommendations: findings,
		Summary:         e.createSummary(findings),
	}
}

func noDataResult(message string) *EvaluationResult {
	return &EvaluationResult{
		Message:         message,
		Recommendations: []Issue{},
	}
}

// Summary is the public wrapper around createSummary, allowing callers to
// recompute the summary after mutating an EvaluationResult's Recommendations slice.
func (e *Evaluator) Summary(findings []Issue) *Summary {
	return e.createSummary(findings)
}

// createSummary creates a summary of evaluation results
func (e *Evaluator) createSummary(findings []Issue) *Summary {
	summary := &Summary{TotalIssues: len(findings)}
	for _, item := range findings {
		switch item.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.HighSeverity++
		case SeverityMedium:
			summary.MediumSeverity++
		case SeverityLow:
			summary.LowSeverity++
		case SeverityInfo:
			summary.Info++
		}
	}
	return summary
}
