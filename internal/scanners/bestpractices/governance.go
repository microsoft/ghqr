// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateActionsPermissions checks GitHub Actions workflow permission settings.
func (e *Evaluator) EvaluateActionsPermissions(perms *scanners.OrgActionsPermissions) *EvaluationResult {
	if perms == nil {
		return noDataResult("Actions permissions data not available")
	}

	var findings []Issue

	if perms.DefaultWorkflowPermissions == "write" {
		e.addFinding(&findings, "org-act-001", "")
	}

	switch perms.AllowedActions {
	case "all":
		e.addFinding(&findings, "org-act-002", "")
	case "local_only":
		e.addFinding(&findings, "org-act-003", "")
	}

	return createResult(e, findings)
}

// EvaluateOrgSecurityAlerts evaluates aggregate open security alert counts for an org.
func (e *Evaluator) EvaluateOrgSecurityAlerts(alerts *scanners.OrgSecurityAlerts) *EvaluationResult {
	if alerts == nil || !alerts.Available {
		return noDataResult("Org-level security alerts not available (GHAS may not be licensed)")
	}

	var findings []Issue

	if alerts.CriticalDependabot > 0 {
		e.addFinding(&findings, "org-alert-001",
			fmt.Sprintf("%d critical Dependabot alerts open across the organization", alerts.CriticalDependabot))
	}
	if alerts.HighDependabot > 0 {
		e.addFinding(&findings, "org-alert-002",
			fmt.Sprintf("%d high-severity Dependabot alerts open across the organization", alerts.HighDependabot))
	}
	if alerts.OpenDependabotAlerts > 0 && alerts.CriticalDependabot == 0 && alerts.HighDependabot == 0 {
		e.addFinding(&findings, "org-alert-003",
			fmt.Sprintf("%d Dependabot alerts open across the organization (no critical/high)", alerts.OpenDependabotAlerts))
	}

	if alerts.OpenCodeScanningAlerts > 0 {
		e.addFinding(&findings, "org-alert-004",
			fmt.Sprintf("%d code scanning alerts open across the organization", alerts.OpenCodeScanningAlerts))
	}

	if alerts.OpenSecretScanningAlerts > 0 {
		e.addFinding(&findings, "org-alert-005",
			fmt.Sprintf("%d secret scanning alerts open across the organization", alerts.OpenSecretScanningAlerts))
	}

	return createResult(e, findings)
}

// EvaluateEnterpriseSecurityAlerts evaluates enterprise-wide aggregate security alerts.
func (e *Evaluator) EvaluateEnterpriseSecurityAlerts(alerts *scanners.EnterpriseSecurityAlerts) *EvaluationResult {
	if alerts == nil || !alerts.Available {
		return noDataResult("Enterprise-level security alerts not available (GHAS may not be licensed or lacks enterprise admin token)")
	}

	var findings []Issue

	if alerts.CriticalDependabot > 0 {
		e.addFinding(&findings, "ent-alert-001",
			fmt.Sprintf("%d critical Dependabot alerts open across the enterprise", alerts.CriticalDependabot))
	}
	if alerts.HighDependabot > 0 {
		e.addFinding(&findings, "ent-alert-002",
			fmt.Sprintf("%d high-severity Dependabot alerts open across the enterprise", alerts.HighDependabot))
	}
	if alerts.OpenCodeScanningAlerts > 0 {
		e.addFinding(&findings, "ent-alert-003",
			fmt.Sprintf("%d code scanning alerts open across the enterprise", alerts.OpenCodeScanningAlerts))
	}
	if alerts.OpenSecretScanningAlerts > 0 {
		e.addFinding(&findings, "ent-alert-004",
			fmt.Sprintf("%d secret scanning alerts open across the enterprise", alerts.OpenSecretScanningAlerts))
	}

	return createResult(e, findings)
}

// EvaluateSecurityManagers checks whether a security manager team is assigned.
func (e *Evaluator) EvaluateSecurityManagers(mgrs *scanners.OrgSecurityManagers) *EvaluationResult {
	if mgrs == nil {
		return noDataResult("Security managers data not available")
	}

	var findings []Issue

	if !mgrs.HasSecurityManager {
		e.addFinding(&findings, "org-sec-005", "")
	}

	return createResult(e, findings)
}
