// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/microsoft/ghqr/internal/scanners"
)

// GHES maintenance window: GitHub provides security patches for the latest
// three minor releases. Bump this constant on each GHES minor GA so the
// evaluator only flags versions that are genuinely out of support.
// Current latest minor as of this build is 3.21, so 3.19, 3.20 and 3.21 are
// in support.
const (
	minSupportedGHESMajor = 3
	minSupportedGHESMinor = 19
)

// parseGHESVersion extracts major and minor numbers from an installed_version
// string like "3.20.1" or "3.21.0.rc1". It returns ok=false if the version
// cannot be parsed.
func parseGHESVersion(v string) (major, minor int, ok bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return maj, min, true
}

// isSupportedGHESVersion reports whether the given parsed major/minor falls
// within the documented supported window.
func isSupportedGHESVersion(major, minor int) bool {
	if major != minSupportedGHESMajor {
		return major > minSupportedGHESMajor
	}
	return minor >= minSupportedGHESMinor
}

// ghesVersionBefore reports whether the GHES instance version recorded in
// serverInfo is strictly before the given major.minor threshold. When the
// version cannot be determined (nil serverInfo, empty string, or unparseable
// value) it returns true so callers err on the side of emitting the finding.
func ghesVersionBefore(serverInfo *scanners.GHESServerInfo, major, minor int) bool {
	if serverInfo == nil || serverInfo.InstalledVersion == "" {
		return true
	}
	maj, min, ok := parseGHESVersion(serverInfo.InstalledVersion)
	if !ok {
		return true
	}
	if maj != major {
		return maj < major
	}
	return min < minor
}

// KnownDisabled reports true only when the pointer is non-nil and points to
// false — i.e. the scanner observed the setting and confirmed it is
// disabled. A nil pointer means "could not observe" and MUST NOT generate
// a finding that assumes a disabled state.
func KnownDisabled(p *bool) bool {
	return p != nil && !*p
}

// KnownEnabled reports true only when the pointer is non-nil and points to
// true — i.e. the scanner observed the setting and confirmed it is enabled.
func KnownEnabled(p *bool) bool {
	return p != nil && *p
}

// maybeDisabledFinding emits the "feature observed disabled" rule when the
// setting is known-disabled AND its API endpoint responded; when the API did
// not respond it emits the paired "status could not be confirmed" rule
// instead. Both rule IDs come from the YAML registry, so severity / category /
// remediation copy are governed centrally rather than hard-coded here.
//
// When the setting itself was not observed (pointer is nil) nothing is
// emitted — that is the false-positive class the tri-state model exists to
// suppress.
func (e *Evaluator) maybeDisabledFinding(
	findings *[]Issue,
	value *bool,
	apiUnavailable bool,
	disabledRuleID, unconfirmedRuleID string,
) {
	if !KnownDisabled(value) {
		return
	}
	if apiUnavailable {
		e.addFinding(findings, unconfirmedRuleID, "")
		return
	}
	e.addFinding(findings, disabledRuleID, "")
}

// EvaluateGHESServerInfo checks GHES server version and basic server configuration.
func (e *Evaluator) EvaluateGHESServerInfo(info *scanners.GHESServerInfo) *EvaluationResult {
	if info == nil {
		return noDataResult("GHES server info not available")
	}

	var findings []Issue

	if info.VerifiablePasswordAuthentication {
		e.addFinding(&findings, "ghes-auth-001", "")
	}

	if info.InstalledVersion == "" {
		e.addFinding(&findings, "ghes-server-005", "")
	} else {
		major, minor, ok := parseGHESVersion(info.InstalledVersion)
		switch {
		case !ok:
			e.addFinding(&findings, "ghes-server-004",
				fmt.Sprintf("Unable to parse GHES version string %q", info.InstalledVersion))
		case !isSupportedGHESVersion(major, minor):
			e.addFinding(&findings, "ghes-server-003",
				fmt.Sprintf("GHES %d.%d is no longer in support (current supported minimum is %d.%d)",
					major, minor, minSupportedGHESMajor, minSupportedGHESMinor))
		default:
			e.addFinding(&findings, "ghes-server-002",
				fmt.Sprintf("GHES %d.%d is within the supported release window (minimum supported: %d.%d)",
					major, minor, minSupportedGHESMajor, minSupportedGHESMinor))
		}

		e.addFinding(&findings, "ghes-server-001",
			fmt.Sprintf("GHES instance is running version %s", info.InstalledVersion))
	}

	return createResult(e, findings)
}

// EvaluateGHESLicense checks GHES license status and seat utilization.
func (e *Evaluator) EvaluateGHESLicense(license *scanners.GHESLicense) *EvaluationResult {
	if license == nil {
		return noDataResult("GHES license data not available (requires site admin token)")
	}

	var findings []Issue

	switch {
	case license.DaysUntilExpiration > 0 && license.DaysUntilExpiration <= 30:
		e.addFinding(&findings, "ghes-license-005",
			fmt.Sprintf("GHES license expires in %d days (expires: %s)", license.DaysUntilExpiration, license.ExpireAt))
	case license.DaysUntilExpiration > 30 && license.DaysUntilExpiration <= 90:
		e.addFinding(&findings, "ghes-license-001",
			fmt.Sprintf("GHES license expires in %d days (expires: %s)", license.DaysUntilExpiration, license.ExpireAt))
	}

	switch {
	case license.Seats.Count > 0 && !license.Seats.Unlimited:
		utilization := float64(license.SeatsUsed) / float64(license.Seats.Count) * 100
		if utilization > 90 {
			e.addFinding(&findings, "ghes-license-002",
				fmt.Sprintf("GHES license seat utilization is at %.0f%% (%d/%d seats used)",
					utilization, license.SeatsUsed, license.Seats.Count))
		} else {
			e.addFinding(&findings, "ghes-license-003",
				fmt.Sprintf("GHES license: %d/%d seats used (%.0f%% utilization)",
					license.SeatsUsed, license.Seats.Count, utilization))
		}
	case license.Seats.Unlimited:
		e.addFinding(&findings, "ghes-license-004",
			fmt.Sprintf("GHES license: %d seats used (unlimited license)", license.SeatsUsed))
	}

	return createResult(e, findings)
}

// EvaluateGHESSettings checks GHES instance security and configuration settings.
//
// When the management API was unreachable (settings.Source ==
// SettingsSourceUnavailable, all boolean fields are nil), this evaluator
// only emits a single Info finding explaining that settings-based checks
// were skipped. It deliberately does NOT fabricate Critical/High findings
// for fields it could not observe — that was the false-positive class
// raised in PR review.
//
// The optional support parameter (may be nil) lets the evaluator avoid
// flagging a feature as "disabled — fix it" when the corresponding API is
// not present on this appliance at all. In that case the finding is
// downgraded to an Info "status could not be confirmed" message via the
// paired rule ID so operators can tell "supported but turned off" apart
// from "API did not respond, reason unclear".
func (e *Evaluator) EvaluateGHESSettings(serverInfo *scanners.GHESServerInfo, settings *scanners.GHESSettings, support *scanners.GHESFeatureSupport) *EvaluationResult {
	if settings == nil {
		return noDataResult("GHES settings data not available")
	}

	var findings []Issue

	if settings.Source == scanners.SettingsSourceUnavailable {
		e.addFinding(&findings, "ghes-infra-002", "")
		return createResult(e, findings)
	}

	// --- Authentication ---

	// Built-in authentication is only flagged when the field was observed.
	// We treat both an explicit empty string and "default"/"built-in" as
	// built-in auth, matching the documented values.
	if settings.AuthMode != nil {
		mode := *settings.AuthMode
		if mode == "" || strings.EqualFold(mode, "default") || strings.EqualFold(mode, "built-in") {
			// ghes-auth-002 is only relevant for GHES < 3.26. From 3.26 onward
			// LDAP and CAS are deprecated in favour of SAML + SCIM, so
			// built-in auth is no longer the worst-practice concern — a
			// separate deprecation finding covers that path instead.
			if ghesVersionBefore(serverInfo, 3, 26) {
				e.addFinding(&findings, "ghes-auth-002", "")
			}
		} else {
			e.addFinding(&findings, "ghes-auth-003",
				fmt.Sprintf("Authentication mode: %s", mode))
		}
	}

	if KnownEnabled(settings.SignupEnabled) {
		e.addFinding(&findings, "ghes-auth-004", "")
	}

	// --- Networking / TLS ---

	if KnownDisabled(settings.SubdomainIsolation) {
		e.addFinding(&findings, "ghes-net-001", "")
	}

	if KnownDisabled(settings.PrivateMode) {
		// The static title in the registry (ghes-net-002) intentionally
		// describes what private mode controls without claiming specific
		// data has already leaked. See the rule definition for the full
		// rationale and doc link.
		e.addFinding(&findings, "ghes-net-002", "")
	}

	// --- GitHub Advanced Security ---

	if KnownDisabled(settings.GHASEnabled) {
		e.addFinding(&findings, "ghes-sec-001", "")
	}

	e.maybeDisabledFinding(&findings, settings.SecretScanningEnabled,
		support != nil && !support.SecretScanningAPIAvailable,
		"ghes-sec-002", "ghes-sec-003")

	if KnownDisabled(settings.SecretScanningPushProtection) {
		e.addFinding(&findings, "ghes-sec-004", "")
	}

	e.maybeDisabledFinding(&findings, settings.CodeScanningEnabled,
		support != nil && !support.CodeScanningAPIAvailable,
		"ghes-sec-005", "ghes-sec-006")

	e.maybeDisabledFinding(&findings, settings.DependabotAlertsEnabled,
		support != nil && !support.DependabotAPIAvailable,
		"ghes-sec-011", "ghes-sec-012")

	if KnownDisabled(settings.DependabotUpdatesEnabled) {
		e.addFinding(&findings, "ghes-sec-013", "")
	}

	// --- GitHub Actions ---

	switch {
	case KnownDisabled(settings.ActionsEnabled) && support != nil && !support.ActionsAPIAvailable:
		e.addFinding(&findings, "ghes-actions-003", "")
	case KnownDisabled(settings.ActionsEnabled):
		e.addFinding(&findings, "ghes-actions-001", "")
	case KnownEnabled(settings.ActionsEnabled):
		e.addFinding(&findings, "ghes-actions-002", "")
	}

	// --- GitHub Pages ---

	// Pages on the appliance origin without subdomain isolation is the
	// canonical XSS / cookie-theft scenario. Emit this BEFORE the
	// public-pages check so the more severe finding leads the report.
	if KnownEnabled(settings.PagesEnabled) && KnownDisabled(settings.SubdomainIsolation) {
		e.addFinding(&findings, "ghes-net-004", "")
	}

	if KnownEnabled(settings.PagesEnabled) && KnownEnabled(settings.PagesPublicPagesEnabled) {
		e.addFinding(&findings, "ghes-net-003", "")
	}

	// --- Maintenance ---

	if KnownEnabled(settings.MaintenanceMode) {
		e.addFinding(&findings, "ghes-server-006", "")
	}

	// --- SSH Admin Access ---

	if KnownEnabled(settings.AdminSSHEnabled) {
		e.addFinding(&findings, "ghes-infra-001", "")
	}

	return createResult(e, findings)
}

// EvaluateGHESAdminStats checks admin statistics for potential issues.
func (e *Evaluator) EvaluateGHESAdminStats(stats *scanners.GHESAdminStats) *EvaluationResult {
	if stats == nil {
		return noDataResult("GHES admin stats not available (requires site admin token)")
	}

	var findings []Issue

	if stats.Users != nil && stats.Users.TotalUsers > 0 {
		suspendedPct := float64(stats.Users.SuspendedUsers) / float64(stats.Users.TotalUsers) * 100
		if suspendedPct > 20 {
			e.addFinding(&findings, "ghes-auth-005",
				fmt.Sprintf("%.0f%% of users are suspended (%d/%d)", suspendedPct, stats.Users.SuspendedUsers, stats.Users.TotalUsers))
		}

		if stats.Users.AdminUsers > 5 {
			e.addFinding(&findings, "ghes-stats-005",
				fmt.Sprintf("%d users have site admin access on the GHES instance", stats.Users.AdminUsers))
		}

		e.addFinding(&findings, "ghes-stats-001",
			fmt.Sprintf("GHES instance has %d total users (%d admins, %d suspended)",
				stats.Users.TotalUsers, stats.Users.AdminUsers, stats.Users.SuspendedUsers))
	}

	if stats.Orgs != nil {
		e.addFinding(&findings, "ghes-stats-002",
			fmt.Sprintf("GHES instance has %d organizations and %d teams",
				stats.Orgs.TotalOrgs, stats.Orgs.TotalTeams))

		if stats.Orgs.DisabledOrgs > 0 {
			e.addFinding(&findings, "ghes-stats-004",
				fmt.Sprintf("%d disabled organizations found on the GHES instance", stats.Orgs.DisabledOrgs))
		}
	}

	if stats.Repos != nil {
		e.addFinding(&findings, "ghes-stats-003",
			fmt.Sprintf("GHES instance has %d total repositories (%d root, %d forks)",
				stats.Repos.TotalRepos, stats.Repos.RootRepos, stats.Repos.ForkRepos))
	}

	return createResult(e, findings)
}

// EvaluateGHESSecurityAlerts evaluates GHES instance-wide security alerts.
//
// The optional support parameter (may be nil) tells the evaluator which
// security-alert APIs are actually present on this appliance. Endpoints
// that returned non-2xx (recorded as *APIAvailable=false) yield an Info
// "API could not be confirmed" finding instead of being silently ignored —
// that way an operator can distinguish "feature endpoint missing on this
// GHES version" from "feature is enabled and has zero alerts".
func (e *Evaluator) EvaluateGHESSecurityAlerts(alerts *scanners.GHESSecurityAlerts, support *scanners.GHESFeatureSupport) *EvaluationResult {
	var findings []Issue

	if support != nil {
		if !support.DependabotAPIAvailable {
			e.addFinding(&findings, "ghes-sec-014", "")
		}
		if !support.CodeScanningAPIAvailable {
			e.addFinding(&findings, "ghes-sec-015", "")
		}
		if !support.SecretScanningAPIAvailable {
			e.addFinding(&findings, "ghes-sec-016", "")
		}
	}

	if alerts == nil || !alerts.Available {
		if len(findings) == 0 {
			return noDataResult("GHES security alerts not available (GHAS may not be enabled or token lacks admin scope)")
		}
		return createResult(e, findings)
	}

	if alerts.CriticalDependabot > 0 {
		e.addFinding(&findings, "ghes-sec-007",
			fmt.Sprintf("%d critical Dependabot alerts open across the GHES instance", alerts.CriticalDependabot))
	}
	if alerts.HighDependabot > 0 {
		e.addFinding(&findings, "ghes-sec-008",
			fmt.Sprintf("%d high-severity Dependabot alerts open across the GHES instance", alerts.HighDependabot))
	}
	if alerts.OpenCodeScanningAlerts > 0 {
		e.addFinding(&findings, "ghes-sec-009",
			fmt.Sprintf("%d code scanning alerts open across the GHES instance", alerts.OpenCodeScanningAlerts))
	}
	if alerts.OpenSecretScanningAlerts > 0 {
		e.addFinding(&findings, "ghes-sec-010",
			fmt.Sprintf("%d secret scanning alerts open across the GHES instance", alerts.OpenSecretScanningAlerts))
	}

	return createResult(e, findings)
}

// EvaluateGHESAuditLog checks recent GHES audit log events for suspicious activity.
func (e *Evaluator) EvaluateGHESAuditLog(data *scanners.GHESAuditLogData) *EvaluationResult {
	if data == nil {
		return noDataResult("GHES audit log data not available")
	}

	var findings []Issue

	if len(data.SuspiciousEvents) > 0 {
		e.addFinding(&findings, "ghes-audit-001",
			fmt.Sprintf("%d suspicious audit log event(s) detected in the last %d events scanned: %s",
				len(data.SuspiciousEvents),
				data.TotalEventsScanned,
				summarizeGHESSuspiciousEvents(data.SuspiciousEvents)))
	} else {
		e.addFinding(&findings, "ghes-audit-002",
			fmt.Sprintf("No suspicious audit log events detected in the last %d events scanned",
				data.TotalEventsScanned))
	}

	// GHES-specific manual-check reminders. These rules are always emitted
	// because the underlying state (syslog forwarding, backup-utils, HA
	// replica, and trusted update-signing key rotation status) is not
	// observable through the REST API.
	e.addFinding(&findings, "ghes-infra-003", "")
	e.addFinding(&findings, "ghes-infra-004", "")
	e.addFinding(&findings, "ghes-infra-005", "")
	e.addFinding(&findings, "ghes-infra-006", "")

	return createResult(e, findings)
}

// EvaluateGHESInstance runs all GHES-specific evaluations and returns a combined result.
func (e *Evaluator) EvaluateGHESInstance(data *scanners.GHESData) *EvaluationResult {
	if data == nil {
		return noDataResult("No GHES data available")
	}

	var allFindings []Issue

	// Collect findings from each sub-evaluation. FeatureSupport is threaded
	// through so settings / security-alerts evaluators can downgrade
	// "disabled" findings to Info "could not be confirmed" when the relevant
	// endpoint is simply not present on this appliance.
	subResults := []*EvaluationResult{
		e.EvaluateGHESServerInfo(data.ServerInfo),
		e.EvaluateGHESLicense(data.License),
		e.EvaluateGHESSettings(data.ServerInfo, data.Settings, data.FeatureSupport),
		e.EvaluateGHESAdminStats(data.AdminStats),
		e.EvaluateGHESSecurityAlerts(data.SecurityAlerts, data.FeatureSupport),
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
