// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
)

// EvaluateGHESServerInfo checks GHES server version and basic server configuration.
func (e *Evaluator) EvaluateGHESServerInfo(info *scanners.GHESServerInfo) *EvaluationResult {
	if info == nil {
		return noDataResult("GHES server info not available")
	}

	var issues []Issue
	var recommendations []Issue

	// Check for password authentication being available (security risk)
	if info.VerifiablePasswordAuthentication {
		addIssue(&issues, SeverityHigh, CategoryGHESAuth,
			"Password authentication is enabled on the GHES instance",
			"Consider disabling password authentication in favor of SSO (SAML/LDAP) to enforce stronger authentication controls",
			"https://docs.github.com/en/enterprise-server/admin/managing-iam/using-saml-for-enterprise-iam/configuring-saml-single-sign-on-for-your-enterprise")
	}

	// Check version is present
	if info.InstalledVersion == "" {
		addIssue(&issues, SeverityMedium, CategoryGHESServer,
			"Unable to determine GHES server version",
			"Ensure the token has sufficient permissions to read server metadata",
			"https://docs.github.com/en/enterprise-server/rest/meta/meta")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategoryGHESServer,
			fmt.Sprintf("GHES instance is running version %s", info.InstalledVersion),
			"Keep your GHES instance up-to-date with the latest patch release to receive security fixes and improvements",
			"https://docs.github.com/en/enterprise-server/admin/upgrading-your-instance/preparing-to-upgrade/overview-of-the-upgrade-process")

		// Check for seriously outdated versions (basic heuristic based on major.minor)
		addRecommendation(&recommendations, SeverityHigh, CategoryGHESServer,
			"Verify your GHES version is a supported release (check GitHub's supported versions page)",
			"GitHub only provides security patches for the latest 3 releases. Running an unsupported version exposes you to unpatched vulnerabilities",
			"https://docs.github.com/en/enterprise-server/admin/all-releases")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateGHESLicense checks GHES license status and seat utilization.
func (e *Evaluator) EvaluateGHESLicense(license *scanners.GHESLicense) *EvaluationResult {
	if license == nil {
		return noDataResult("GHES license data not available (requires site admin token)")
	}

	var issues []Issue
	var recommendations []Issue

	// Check license expiration
	if license.DaysUntilExpiration > 0 && license.DaysUntilExpiration <= 30 {
		addIssue(&issues, SeverityCritical, CategoryGHESLicense,
			fmt.Sprintf("GHES license expires in %d days (expires: %s)", license.DaysUntilExpiration, license.ExpireAt),
			"Renew your GitHub Enterprise Server license immediately to avoid service interruption",
			"https://docs.github.com/en/enterprise-server/billing/managing-your-license-for-github-enterprise/about-licenses-for-github-enterprise")
	} else if license.DaysUntilExpiration > 30 && license.DaysUntilExpiration <= 90 {
		addIssue(&issues, SeverityHigh, CategoryGHESLicense,
			fmt.Sprintf("GHES license expires in %d days (expires: %s)", license.DaysUntilExpiration, license.ExpireAt),
			"Plan your GHES license renewal — contact GitHub Sales",
			"https://docs.github.com/en/enterprise-server/billing/managing-your-license-for-github-enterprise/about-licenses-for-github-enterprise")
	}

	// Check seat utilization
	if license.Seats > 0 {
		utilization := float64(license.SeatsUsed) / float64(license.Seats) * 100
		if utilization > 90 {
			addIssue(&issues, SeverityHigh, CategoryGHESLicense,
				fmt.Sprintf("GHES license seat utilization is at %.0f%% (%d/%d seats used)",
					utilization, license.SeatsUsed, license.Seats),
				"You are approaching your license seat limit. Consider purchasing additional seats or reviewing inactive users",
				"https://docs.github.com/en/enterprise-server/billing/managing-your-license-for-github-enterprise/about-licenses-for-github-enterprise")
		} else {
			addRecommendation(&recommendations, SeverityInfo, CategoryGHESLicense,
				fmt.Sprintf("GHES license: %d/%d seats used (%.0f%% utilization)",
					license.SeatsUsed, license.Seats, utilization),
				"Monitor seat utilization regularly",
				"https://docs.github.com/en/enterprise-server/billing/managing-your-license-for-github-enterprise/about-licenses-for-github-enterprise")
		}
	}

	return createResult(e, issues, recommendations)
}

// EvaluateGHESSettings checks GHES instance security and configuration settings.
func (e *Evaluator) EvaluateGHESSettings(settings *scanners.GHESSettings) *EvaluationResult {
	if settings == nil {
		return noDataResult("GHES settings data not available")
	}

	var issues []Issue
	var recommendations []Issue

	// --- Authentication ---

	// Check authentication mode
	if settings.AuthMode == "" || strings.EqualFold(settings.AuthMode, "default") || strings.EqualFold(settings.AuthMode, "built-in") {
		addIssue(&issues, SeverityCritical, CategoryGHESAuth,
			"GHES is using built-in authentication instead of external identity provider",
			"Configure SAML SSO or LDAP authentication to integrate with your enterprise identity provider. Built-in authentication lacks centralized user lifecycle management",
			"https://docs.github.com/en/enterprise-server/admin/managing-iam/understanding-iam-for-your-enterprise/about-authentication-for-your-enterprise")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategoryGHESAuth,
			fmt.Sprintf("Authentication mode: %s", settings.AuthMode),
			"External authentication provider is configured",
			"https://docs.github.com/en/enterprise-server/admin/managing-iam/understanding-iam-for-your-enterprise/about-authentication-for-your-enterprise")
	}

	// Check if signup is enabled (should be disabled in enterprise)
	if settings.SignupEnabled {
		addIssue(&issues, SeverityHigh, CategoryGHESAuth,
			"Open signup is enabled on the GHES instance",
			"Disable open signup to prevent unauthorized users from creating accounts. Use your identity provider for user provisioning",
			"https://docs.github.com/en/enterprise-server/admin/managing-iam/managing-your-enterprise-users-with-your-identity-provider/configuring-scim-provisioning-for-users")
	}

	// --- Networking / TLS ---

	if !settings.SubdomainIsolation {
		addIssue(&issues, SeverityCritical, CategoryGHESNetworking,
			"Subdomain isolation is not enabled",
			"Enable subdomain isolation to prevent cross-site scripting attacks. This is critical for security and should always be enabled in production",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/configuring-network-settings/enabling-subdomain-isolation")
	}

	if !settings.PrivateMode {
		addRecommendation(&recommendations, SeverityMedium, CategoryGHESNetworking,
			"GHES instance is not in private mode",
			"Consider enabling private mode if the instance should not be accessible by unauthenticated users. Private mode requires authentication for all access",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/configuring-your-enterprise/enabling-private-mode")
	}

	// --- GitHub Advanced Security ---

	if !settings.GHASEnabled {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"GitHub Advanced Security (GHAS) is not enabled on the GHES instance",
			"Enable GHAS to unlock code scanning, secret scanning, and dependency review across all organizations",
			"https://docs.github.com/en/enterprise-server/admin/code-security/managing-github-advanced-security-for-your-enterprise/enabling-github-advanced-security-for-your-enterprise")
	}

	if !settings.SecretScanningEnabled {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning is not enabled on the GHES instance",
			"Enable secret scanning to detect leaked credentials in repositories",
			"https://docs.github.com/en/enterprise-server/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-secret-scanning-for-your-appliance")
	}

	if !settings.SecretScanningPushProtection {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			"Secret scanning push protection is not enabled",
			"Enable push protection to block commits containing secrets before they reach the repository",
			"https://docs.github.com/en/enterprise-server/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-secret-scanning-for-your-appliance")
	}

	if !settings.CodeScanningEnabled {
		addRecommendation(&recommendations, SeverityHigh, CategorySecurity,
			"Code scanning is not enabled on the GHES instance",
			"Enable code scanning (CodeQL) to automatically find security vulnerabilities in code",
			"https://docs.github.com/en/enterprise-server/admin/code-security/managing-github-advanced-security-for-your-enterprise/configuring-code-scanning-for-your-appliance")
	}

	if !settings.DependabotAlertsEnabled {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			"Dependabot alerts are not enabled on the GHES instance",
			"Enable Dependabot alerts to receive notifications about vulnerable dependencies",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/configuring-github-connect/enabling-dependabot-for-your-enterprise")
	}

	if !settings.DependabotUpdatesEnabled {
		addRecommendation(&recommendations, SeverityMedium, CategoryDependencies,
			"Dependabot security updates are not enabled on the GHES instance",
			"Enable Dependabot security updates to automatically create PRs that fix vulnerable dependencies",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/configuring-github-connect/enabling-dependabot-for-your-enterprise")
	}

	// --- GitHub Actions ---

	if !settings.ActionsEnabled {
		addRecommendation(&recommendations, SeverityMedium, CategoryActions,
			"GitHub Actions is not enabled on the GHES instance",
			"Consider enabling GitHub Actions for CI/CD workflows. Ensure self-hosted runners are properly secured",
			"https://docs.github.com/en/enterprise-server/admin/managing-github-actions-for-your-enterprise/getting-started-with-github-actions-for-your-enterprise/getting-started-with-github-actions-for-github-enterprise-server")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategoryActions,
			"GitHub Actions is enabled",
			"Ensure self-hosted runners are isolated, hardened, and do not run on the GHES appliance itself. Use ephemeral runners where possible",
			"https://docs.github.com/en/enterprise-server/admin/managing-github-actions-for-your-enterprise/getting-started-with-github-actions-for-your-enterprise/getting-started-with-github-actions-for-github-enterprise-server")
	}

	// --- GitHub Pages ---

	if settings.PagesEnabled && settings.PagesPublicPagesEnabled {
		addRecommendation(&recommendations, SeverityMedium, CategoryGHESNetworking,
			"Public GitHub Pages are enabled on the GHES instance",
			"Consider disabling public Pages if the instance is internal-only to prevent accidental content exposure",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/configuring-github-pages-for-your-enterprise")
	}

	// --- Maintenance ---

	if settings.MaintenanceMode {
		addIssue(&issues, SeverityHigh, CategoryGHESServer,
			"GHES instance is currently in maintenance mode",
			"Maintenance mode prevents user access. Ensure this is intentional and plan to disable it after maintenance is complete",
			"https://docs.github.com/en/enterprise-server/admin/configuring-settings/enabling-and-scheduling-maintenance-mode")
	}

	// --- SSH Admin Access ---

	if settings.AdminSSHEnabled {
		addRecommendation(&recommendations, SeverityMedium, CategoryGHESInfra,
			"Administrative SSH access is enabled on the GHES instance",
			"Review SSH access policies. Consider restricting SSH access to specific IP ranges and ensure SSH keys are regularly rotated",
			"https://docs.github.com/en/enterprise-server/admin/administering-your-instance/configuring-ssh-access-to-your-instance")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateGHESAdminStats checks admin statistics for potential issues.
func (e *Evaluator) EvaluateGHESAdminStats(stats *scanners.GHESAdminStats) *EvaluationResult {
	if stats == nil {
		return noDataResult("GHES admin stats not available (requires site admin token)")
	}

	var issues []Issue
	var recommendations []Issue

	// Check for suspended users ratio
	if stats.Users != nil && stats.Users.TotalUsers > 0 {
		suspendedPct := float64(stats.Users.SuspendedUsers) / float64(stats.Users.TotalUsers) * 100
		if suspendedPct > 20 {
			addRecommendation(&recommendations, SeverityMedium, CategoryGHESAuth,
				fmt.Sprintf("%.0f%% of users are suspended (%d/%d)", suspendedPct, stats.Users.SuspendedUsers, stats.Users.TotalUsers),
				"Consider removing suspended user accounts to free up license seats and maintain a clean user directory",
				"https://docs.github.com/en/enterprise-server/admin/managing-accounts-and-repositories/managing-users-in-your-enterprise/suspending-and-unsuspending-users")
		}

		// Check admin user count
		if stats.Users.AdminUsers > 5 {
			addIssue(&issues, SeverityHigh, CategoryAccessControl,
				fmt.Sprintf("%d users have site admin access on the GHES instance", stats.Users.AdminUsers),
				"Limit site admin access to the minimum number of trusted administrators. Follow the principle of least privilege",
				"https://docs.github.com/en/enterprise-server/admin/managing-accounts-and-repositories/managing-users-in-your-enterprise/promoting-or-demoting-a-site-administrator")
		}

		addRecommendation(&recommendations, SeverityInfo, CategoryGHESServer,
			fmt.Sprintf("GHES instance has %d total users (%d admins, %d suspended)",
				stats.Users.TotalUsers, stats.Users.AdminUsers, stats.Users.SuspendedUsers),
			"Regularly audit user accounts and admin access",
			"https://docs.github.com/en/enterprise-server/admin/managing-accounts-and-repositories/managing-users-in-your-enterprise/auditing-users-across-your-enterprise")
	}

	// Report org and repo counts
	if stats.Orgs != nil {
		addRecommendation(&recommendations, SeverityInfo, CategoryGHESServer,
			fmt.Sprintf("GHES instance has %d organizations and %d teams",
				stats.Orgs.TotalOrgs, stats.Orgs.TotalTeams),
			"Monitor organization growth and ensure governance policies are enforced",
			"https://docs.github.com/en/enterprise-server/admin/managing-accounts-and-repositories/managing-organizations-in-your-enterprise")

		if stats.Orgs.DisabledOrgs > 0 {
			addRecommendation(&recommendations, SeverityLow, CategoryGHESServer,
				fmt.Sprintf("%d disabled organizations found on the GHES instance", stats.Orgs.DisabledOrgs),
				"Review disabled organizations and consider removing them if no longer needed",
				"https://docs.github.com/en/enterprise-server/admin/managing-accounts-and-repositories/managing-organizations-in-your-enterprise")
		}
	}

	if stats.Repos != nil {
		addRecommendation(&recommendations, SeverityInfo, CategoryGHESServer,
			fmt.Sprintf("GHES instance has %d total repositories (%d root, %d forks)",
				stats.Repos.TotalRepos, stats.Repos.RootRepos, stats.Repos.ForkRepos),
			"Monitor repository growth and storage consumption",
			"https://docs.github.com/en/enterprise-server/admin/monitoring-and-managing-your-instance/monitoring-your-instance/about-the-monitor-dashboard")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateGHESSecurityAlerts evaluates GHES instance-wide security alerts.
func (e *Evaluator) EvaluateGHESSecurityAlerts(alerts *scanners.GHESSecurityAlerts) *EvaluationResult {
	if alerts == nil || !alerts.Available {
		return noDataResult("GHES security alerts not available (GHAS may not be enabled or token lacks admin scope)")
	}

	var issues []Issue
	var recommendations []Issue

	if alerts.CriticalDependabot > 0 {
		addIssue(&issues, SeverityCritical, CategoryDependencies,
			fmt.Sprintf("%d critical Dependabot alerts open across the GHES instance", alerts.CriticalDependabot),
			"Immediately remediate critical dependency vulnerabilities across all organizations",
			"https://docs.github.com/en/enterprise-server/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.HighDependabot > 0 {
		addIssue(&issues, SeverityHigh, CategoryDependencies,
			fmt.Sprintf("%d high-severity Dependabot alerts open across the GHES instance", alerts.HighDependabot),
			"Prioritize fixing high-severity dependency vulnerabilities",
			"https://docs.github.com/en/enterprise-server/code-security/dependabot/dependabot-alerts/about-dependabot-alerts")
	}
	if alerts.OpenCodeScanningAlerts > 0 {
		addIssue(&issues, SeverityHigh, CategorySecurity,
			fmt.Sprintf("%d code scanning alerts open across the GHES instance", alerts.OpenCodeScanningAlerts),
			"Review and address open code scanning findings",
			"https://docs.github.com/en/enterprise-server/code-security/code-scanning")
	}
	if alerts.OpenSecretScanningAlerts > 0 {
		addIssue(&issues, SeverityCritical, CategorySecurity,
			fmt.Sprintf("%d secret scanning alerts open across the GHES instance", alerts.OpenSecretScanningAlerts),
			"Immediately revoke and rotate any exposed secrets",
			"https://docs.github.com/en/enterprise-server/code-security/secret-scanning")
	}

	return createResult(e, issues, recommendations)
}

// EvaluateGHESAuditLog checks recent GHES audit log events for suspicious activity.
func (e *Evaluator) EvaluateGHESAuditLog(data *scanners.GHESAuditLogData) *EvaluationResult {
	if data == nil {
		return noDataResult("GHES audit log data not available")
	}

	var issues []Issue
	var recommendations []Issue

	if len(data.SuspiciousEvents) > 0 {
		addIssue(&issues, SeverityCritical, CategorySecurity,
			fmt.Sprintf("%d suspicious audit log event(s) detected in the last %d events scanned: %s",
				len(data.SuspiciousEvents),
				data.TotalEventsScanned,
				summarizeGHESSuspiciousEvents(data.SuspiciousEvents)),
			"Review these events in the GHES site admin audit log immediately. "+
				"Actions like repo.destroy, staff.fake_login, and staff.set_site_admin can indicate account compromise or insider threats",
			"https://docs.github.com/en/enterprise-server/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise")
	} else {
		addRecommendation(&recommendations, SeverityInfo, CategorySecurity,
			fmt.Sprintf("No suspicious audit log events detected in the last %d events scanned",
				data.TotalEventsScanned),
			"Continue monitoring the audit log regularly. Configure log forwarding to a SIEM for centralized monitoring",
			"https://docs.github.com/en/enterprise-server/admin/monitoring-activity-in-your-enterprise/exploring-user-activity-in-your-enterprise/log-forwarding")
	}

	// GHES-specific: recommend log forwarding
	addRecommendation(&recommendations, SeverityHigh, CategorySecurity,
		"Audit log forwarding configuration cannot be verified automatically",
		"Manually verify that audit log forwarding (syslog) is enabled and targeting a SIEM or secure log aggregation service (Site Admin → Monitoring → Log forwarding)",
		"https://docs.github.com/en/enterprise-server/admin/monitoring-activity-in-your-enterprise/exploring-user-activity-in-your-enterprise/log-forwarding")

	// GHES-specific: recommend backup verification
	addRecommendation(&recommendations, SeverityHigh, CategoryGHESInfra,
		"GHES backup configuration cannot be verified automatically",
		"Manually verify that GitHub Enterprise Server Backup Utilities (backup-utils) are configured, run on a schedule, and tested regularly for restoration",
		"https://docs.github.com/en/enterprise-server/admin/backing-up-and-restoring-your-instance/configuring-backups-on-your-instance")

	// GHES-specific: recommend HA verification
	addRecommendation(&recommendations, SeverityMedium, CategoryGHESInfra,
		"High availability (HA) replica configuration cannot be verified automatically",
		"Manually verify that a replica is configured for failover if high availability is required for your deployment",
		"https://docs.github.com/en/enterprise-server/admin/monitoring-and-managing-your-instance/configuring-high-availability/about-high-availability-configuration")

	return createResult(e, issues, recommendations)
}

// EvaluateGHESInstance runs all GHES-specific evaluations and returns a combined result.
func (e *Evaluator) EvaluateGHESInstance(data *scanners.GHESData) *EvaluationResult {
	if data == nil {
		return noDataResult("No GHES data available")
	}

	var allFindings []Issue

	// Collect findings from each sub-evaluation
	subResults := []*EvaluationResult{
		e.EvaluateGHESServerInfo(data.ServerInfo),
		e.EvaluateGHESLicense(data.License),
		e.EvaluateGHESSettings(data.Settings),
		e.EvaluateGHESAdminStats(data.AdminStats),
		e.EvaluateGHESSecurityAlerts(data.SecurityAlerts),
		e.EvaluateGHESAuditLog(data.AuditLog),
	}

	for _, r := range subResults {
		if r != nil {
			allFindings = append(allFindings, r.Recommendations...)
		}
	}

	return &EvaluationResult{
		Recommendations: allFindings,
		Summary:         e.createSummary(allFindings),
	}
}

func summarizeGHESSuspiciousEvents(events []*scanners.SuspiciousAuditEvent) string {
	seen := map[string]int{}
	for _, ev := range events {
		seen[ev.Action]++
	}
	var parts []string
	for action, count := range seen {
		parts = append(parts, fmt.Sprintf("%s (x%d)", action, count))
	}
	return strings.Join(parts, ", ")
}
