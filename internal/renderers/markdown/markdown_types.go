// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package markdown

// recommendation represents a single finding from the scan.
type recommendation struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Issue          string `json:"issue"`
	Recommendation string `json:"recommendation"`
	LearnMore      string `json:"learn_more,omitempty"`
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
