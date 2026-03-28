// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateEnterpriseAuditLog checks recent enterprise audit log events for suspicious activity.
func (e *Evaluator) EvaluateEnterpriseAuditLog(data *scanners.EnterpriseAuditLogData) *EvaluationResult {
	if data == nil {
		return noDataResult("No enterprise audit log data available")
	}

	var findings []Issue

	if len(data.SuspiciousEvents) > 0 {
		e.addFinding(&findings, "ent-log-001",
			fmt.Sprintf("%d suspicious audit log event(s) detected in the last %d events scanned: %s",
				len(data.SuspiciousEvents),
				data.TotalEventsScanned,
				summarizeSuspiciousEvents(data.SuspiciousEvents)))
	} else {
		addRecommendation(&findings, SeverityInfo, CategorySecurity,
			fmt.Sprintf("No suspicious audit log events detected in the last %d events scanned",
				data.TotalEventsScanned),
			"Continue monitoring the audit log regularly and configure audit log streaming to a SIEM",
			"https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise")
	}

	e.addFinding(&findings, "ent-log-002", "")

	return createResult(e, findings)
}

// EvaluateOrgSecurityDefaults checks org-wide security defaults applied to new repositories.
func (e *Evaluator) EvaluateOrgSecurityDefaults(settings *scanners.OrgSecurity) *EvaluationResult {
	if settings == nil {
		return noDataResult("No organization security settings available")
	}

	var findings []Issue

	if !settings.DependabotAlertsForNewRepos {
		e.addFinding(&findings, "org-def-001", "")
	}
	if !settings.DependabotSecurityUpdatesForNewRepos {
		e.addFinding(&findings, "org-def-002", "")
	}
	if !settings.DependencyGraphForNewRepos {
		e.addFinding(&findings, "org-def-003", "")
	}
	if !settings.SecretScanningForNewRepos {
		e.addFinding(&findings, "org-def-004", "")
	}
	if !settings.SecretScanningPushProtectionForNewRepos {
		e.addFinding(&findings, "org-def-005", "")
	}
	if !settings.AdvancedSecurityForNewRepos {
		e.addFinding(&findings, "org-def-006", "")
	}

	return createResult(e, findings)
}

func summarizeSuspiciousEvents(events []*scanners.SuspiciousAuditEvent) string {
	seen := map[string]int{}
	for _, e := range events {
		seen[e.Action]++
	}
	var parts []string
	for action, count := range seen {
		parts = append(parts, fmt.Sprintf("%s (x%d)", action, count))
	}
	return strings.Join(parts, ", ")
}

// EvaluateEnterpriseGHASSettings checks enterprise-wide GHAS policy defaults.
// Values are strings like "enabled", "disabled", or "not_set".
func (e *Evaluator) EvaluateEnterpriseGHASSettings(s *scanners.EnterpriseGHASSettings) *EvaluationResult {
	if s == nil {
		return noDataResult("Enterprise GHAS settings not available (requires enterprise admin token)")
	}

	var findings []Issue

	enabled := func(v string) bool { return strings.EqualFold(v, "enabled") }

	if !enabled(s.AdvancedSecurity) {
		e.addFinding(&findings, "ent-ghas-001", "")
	}
	if !enabled(s.SecretScanning) {
		e.addFinding(&findings, "ent-ghas-002", "")
	}
	if !enabled(s.SecretScanningPushProtection) {
		e.addFinding(&findings, "ent-ghas-003", "")
	}
	if !enabled(s.DependabotAlerts) {
		e.addFinding(&findings, "ent-ghas-004", "")
	}
	if !enabled(s.DependabotSecurityUpdates) {
		e.addFinding(&findings, "ent-ghas-005", "")
	}
	if !enabled(s.DependencyGraph) {
		e.addFinding(&findings, "ent-ghas-006", "")
	}
	if !enabled(s.SecretScanningNonProviderPatterns) {
		e.addFinding(&findings, "ent-ghas-007", "")
	}

	return createResult(e, findings)
}
