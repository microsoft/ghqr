// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

// recommendation represents a single finding from the scan.
type recommendation struct {
	RuleID         string `json:"rule_id,omitempty"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
	LearnMore      string `json:"learn_more,omitempty"`
}

// groupKey returns a stable deduplication key for this recommendation.
// It prefers RuleID when available; otherwise falls back to the
// (Severity, Category, Recommendation) triple.
func (r recommendation) groupKey() string {
	if r.RuleID != "" {
		return r.RuleID + "|" + r.Severity + "|" + r.Category
	}
	return r.Severity + "|" + r.Category + "|" + r.Recommendation
}

// entityFindings groups findings by entity for report generation.
type entityFindings struct {
	EntityName string
	EntityType string // "enterprise", "org", "repo"
	Findings   []recommendation
}

// planItem represents a single action item in the remediation plan.
type planItem struct {
	Entity   string
	Rec      recommendation
	Priority int
}
