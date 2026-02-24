// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import "github.com/google/go-github/v83/github"

// EnterpriseData holds enterprise information
type EnterpriseData struct {
	Settings       *EnterpriseSettings       `json:"settings,omitempty"`
	Organizations  []*github.Organization    `json:"organizations,omitempty"`
	AuditLog       *EnterpriseAuditLogData   `json:"audit_log,omitempty"`
	SecurityAlerts *EnterpriseSecurityAlerts `json:"security_alerts,omitempty"`
	GHASSettings   *EnterpriseGHASSettings   `json:"ghas_settings,omitempty"`
}

// EnterpriseSecurityAlerts holds aggregate open security alert counts at the enterprise level.
type EnterpriseSecurityAlerts struct {
	OpenDependabotAlerts     int  `json:"open_dependabot_alerts"`
	CriticalDependabot       int  `json:"critical_dependabot"`
	HighDependabot           int  `json:"high_dependabot"`
	OpenCodeScanningAlerts   int  `json:"open_code_scanning_alerts"`
	OpenSecretScanningAlerts int  `json:"open_secret_scanning_alerts"`
	Available                bool `json:"available"`
}

// EnterpriseSettings represents basic enterprise settings
type EnterpriseSettings struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	WebsiteURL  string `json:"website_url,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// EnterpriseAuditLogData holds a summary of recent audit log events.
type EnterpriseAuditLogData struct {
	TotalEventsScanned int                     `json:"total_events_scanned"`
	SuspiciousEvents   []*SuspiciousAuditEvent `json:"suspicious_events,omitempty"`
}

// SuspiciousAuditEvent represents a notable audit log entry.
type SuspiciousAuditEvent struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Org       string `json:"org,omitempty"`
	User      string `json:"user,omitempty"`
}

// EnterpriseGHASSettings holds the enterprise-wide GitHub Advanced Security defaults
// returned by GET /enterprises/{enterprise}/code_security/settings.
// These cascade to all organizations unless overridden at the org level.
// A nil pointer means the endpoint was not accessible (insufficient permissions).
type EnterpriseGHASSettings struct {
	AdvancedSecurity                  string `json:"advanced_security"`
	SecretScanning                    string `json:"secret_scanning"`
	SecretScanningPushProtection      string `json:"secret_scanning_push_protection"`
	DependabotAlerts                  string `json:"dependabot_alerts"`
	DependabotSecurityUpdates         string `json:"dependabot_security_updates"`
	DependencyGraph                   string `json:"dependency_graph"`
	SecretScanningNonProviderPatterns string `json:"secret_scanning_non_provider_patterns"`
}
