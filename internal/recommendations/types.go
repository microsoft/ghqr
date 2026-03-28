// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package recommendations provides a declarative, data-driven recommendation registry for ghqr.
// Rules are defined as YAML files embedded in the binary at build time.
// Each recommendation has a stable ID, metadata (severity, category, description,
// remediation, learn-more link), and an optional scope tag.
//
// This approach is inspired by the Azure Quick Review (azqr) project, which
// stores each recommendation as a YAML descriptor alongside a KQL query file. ghqr
// adapts this pattern to GitHub's API model: recommendation metadata is fully
// data-driven, while the evaluation logic remains in Go (GitHub has no
// equivalent to Azure Resource Graph).
package recommendations

// Scope identifies the GitHub entity type a recommendation applies to.
type Scope string

const (
	// ScopeRepository indicates the recommendation evaluates a single repository.
	ScopeRepository Scope = "repository"
	// ScopeOrganization indicates the recommendation evaluates an organization.
	ScopeOrganization Scope = "organization"
	// ScopeEnterprise indicates the recommendation evaluates an enterprise.
	ScopeEnterprise Scope = "enterprise"
)

// Recommendation is the declarative descriptor for a single best-practice rule.
// Instances are loaded from embedded YAML files at startup.
type Recommendation struct {
	// ID is a stable, unique identifier in the form {scope-abbrev}-{category-abbrev}-{seq}.
	// Examples: repo-bp-001, org-sec-003, ent-ghas-002
	ID string `yaml:"id" json:"id"`

	// Scope is the GitHub entity type this recommendation targets.
	Scope Scope `yaml:"scope" json:"scope"`

	// Title is a short, human-readable recommendation name.
	Title string `yaml:"title" json:"title"`

	// Category groups related rules (e.g. branch_protection, security).
	Category string `yaml:"category" json:"category"`

	// Severity is one of: critical, high, medium, low, info.
	Severity string `yaml:"severity" json:"severity"`

	// Description explains what the recommendation checks and why it matters.
	Description string `yaml:"description" json:"description"`

	// Recommendation is the actionable remediation guidance.
	Recommendation string `yaml:"recommendation" json:"recommendation"`

	// LearnMore is a URL to documentation for further reading.
	LearnMore string `yaml:"learnMore" json:"learn_more,omitempty"`

	// Tags are optional labels for grouping and filtering.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Enabled controls whether findings are emitted for this rule.
	// Defaults to true when omitted.
	Enabled bool `yaml:"enabled" json:"enabled"`
}
