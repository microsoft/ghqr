// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// GHESLicenseSeats represents a seat count that GHES may return as either an
// integer or the string "unlimited" (or other non-numeric values). It serialises
// out as the numeric count when bounded, and as null when unlimited so JSON
// consumers can distinguish the two cases.
type GHESLicenseSeats struct {
	Count     int
	Unlimited bool
}

// UnmarshalJSON accepts either a JSON number or a string. The literal string
// "unlimited" (case-insensitive) is mapped to Unlimited=true; numeric strings
// are parsed as integers; other strings leave Count=0 with Unlimited=false to
// avoid masking unexpected values.
func (s *GHESLicenseSeats) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var str string
		if err := json.Unmarshal(trimmed, &str); err != nil {
			return fmt.Errorf("GHESLicenseSeats: %w", err)
		}
		if strings.EqualFold(str, "unlimited") {
			s.Unlimited = true
			return nil
		}
		n, err := strconv.Atoi(str)
		if err != nil {
			return nil
		}
		s.Count = n
		return nil
	}
	var n int
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return fmt.Errorf("GHESLicenseSeats: %w", err)
	}
	s.Count = n
	return nil
}

// MarshalJSON emits the literal string "unlimited" when the seats are
// unlimited, and the integer count otherwise. Emitting a string (rather
// than null) means the value round-trips losslessly through the replay
// loader — UnmarshalJSON above recognises "unlimited" and rebuilds the
// Unlimited=true state — while still mirroring the shape GHES itself
// returns from /enterprise/settings/license.
func (s GHESLicenseSeats) MarshalJSON() ([]byte, error) {
	if s.Unlimited {
		return []byte(`"unlimited"`), nil
	}
	return json.Marshal(s.Count)
}

// GHESData holds all GitHub Enterprise Server instance scan results.
type GHESData struct {
	ServerInfo     *GHESServerInfo     `json:"server_info,omitempty"`
	License        *GHESLicense        `json:"license,omitempty"`
	Settings       *GHESSettings       `json:"settings,omitempty"`
	FeatureSupport *GHESFeatureSupport `json:"feature_support,omitempty"`
	AdminStats     *GHESAdminStats     `json:"admin_stats,omitempty"`
	SecurityAlerts *GHESSecurityAlerts `json:"security_alerts,omitempty"`
	AuditLog       *GHESAuditLogData   `json:"audit_log,omitempty"`
	Organizations  []string            `json:"organizations,omitempty"`
}

// GHESServerInfo holds metadata returned by GET /api/v3/meta.
type GHESServerInfo struct {
	InstalledVersion                 string            `json:"installed_version,omitempty"`
	VerifiablePasswordAuthentication bool              `json:"verifiable_password_authentication"`
	SSHKeyFingerprints               map[string]string `json:"ssh_key_fingerprints,omitempty"`
	Hostname                         string            `json:"hostname,omitempty"`
	// Features detected from API responses.
	GHASEnabled             bool `json:"ghas_enabled"`
	ActionsEnabled          bool `json:"actions_enabled"`
	PackagesEnabled         bool `json:"packages_enabled"`
	PagesEnabled            bool `json:"pages_enabled"`
	DependabotEnabled       bool `json:"dependabot_enabled"`
	CodeScanningEnabled     bool `json:"code_scanning_enabled"`
	SecretScanningEnabled   bool `json:"secret_scanning_enabled"`
	AdvancedSecurityEnabled bool `json:"advanced_security_enabled"`
}

// GHESLicense holds enterprise license information from GET /api/v3/enterprise/settings/license.
//
// GHES returns "seats" and "seats_available" as either a JSON number or the
// string "unlimited" depending on the license kind, so those two fields use a
// tolerant type. "seats_used" is always numeric.
type GHESLicense struct {
	Seats               GHESLicenseSeats `json:"seats"`
	SeatsUsed           int              `json:"seats_used"`
	SeatsAvailable      GHESLicenseSeats `json:"seats_available"`
	Kind                string           `json:"kind,omitempty"`
	DaysUntilExpiration int              `json:"days_until_expiration"`
	ExpireAt            string           `json:"expire_at,omitempty"`
	// ClusterSupport indicates whether clustering is part of the license.
	ClusterSupport bool `json:"cluster_support"`
}

// SettingsSource indicates how a GHESSettings struct was populated.
//
//   - SettingsSourceManageAPI: values were read from /manage/v1/config/settings.
//     Fields read from the response are populated; fields absent from the
//     response remain nil ("unknown"), which evaluators must treat as
//     "do not flag".
//   - SettingsSourceUnavailable: the management API was unreachable for this
//     instance (network error, 401/403/404/5xx). All boolean enablement fields
//     are nil. Evaluators must not emit findings that assume a known-disabled
//     state for fields populated from the management API.
const (
	SettingsSourceManageAPI   = "manage_api"
	SettingsSourceUnavailable = "unavailable"
)

// GHESSettings holds GHES site admin configuration retrieved via REST API.
//
// Boolean enablement fields use *bool tri-state semantics:
//
//   - non-nil true   -> setting is observed and enabled
//   - non-nil false  -> setting is observed and disabled
//   - nil            -> setting could not be observed (management API
//     inaccessible or field absent from the response)
//
// Evaluators MUST distinguish nil ("unknown") from false ("known disabled")
// to avoid fabricating findings on instances where the management API is
// unreachable. The companion helpers KnownEnabled / KnownDisabled in the
// bestpractices package handle the common cases.
type GHESSettings struct {
	// Source records where the field values came from. Consumers can use this
	// to caveat reports when the management API was unreachable.
	Source string `json:"source,omitempty"`

	// Authentication
	AuthMode            *string `json:"auth_mode,omitempty"`
	BuiltinAuthFallback *bool   `json:"builtin_auth_fallback,omitempty"`
	SAMLEnabled         *bool   `json:"saml_enabled,omitempty"`
	LDAPEnabled         *bool   `json:"ldap_enabled,omitempty"`
	CASEnabled          *bool   `json:"cas_enabled,omitempty"`
	// TLS / Networking
	SubdomainIsolation *bool `json:"subdomain_isolation,omitempty"`
	TLSEnforced        *bool `json:"tls_enforced,omitempty"`
	PrivateMode        *bool `json:"private_mode,omitempty"`
	// GitHub Actions
	ActionsEnabled     *bool   `json:"actions_enabled,omitempty"`
	ActionsStorageType *string `json:"actions_storage_type,omitempty"`
	// GitHub Packages
	PackagesEnabled *bool `json:"packages_enabled,omitempty"`
	// GitHub Pages
	PagesEnabled            *bool `json:"pages_enabled,omitempty"`
	PagesPublicPagesEnabled *bool `json:"pages_public_pages_enabled,omitempty"`
	// GitHub Advanced Security
	GHASEnabled                  *bool `json:"ghas_enabled,omitempty"`
	SecretScanningEnabled        *bool `json:"secret_scanning_enabled,omitempty"`
	SecretScanningPushProtection *bool `json:"secret_scanning_push_protection,omitempty"`
	DependabotAlertsEnabled      *bool `json:"dependabot_alerts_enabled,omitempty"`
	DependabotUpdatesEnabled     *bool `json:"dependabot_updates_enabled,omitempty"`
	CodeScanningEnabled          *bool `json:"code_scanning_enabled,omitempty"`
	// Maintenance
	MaintenanceMode *bool `json:"maintenance_mode,omitempty"`
	// SSH access
	AdminSSHEnabled *bool `json:"admin_ssh_enabled,omitempty"`
	// Signup
	SignupEnabled *bool `json:"signup_enabled,omitempty"`
	// Collect stats
	CollectStatsEnabled *bool `json:"collect_stats_enabled,omitempty"`
}

// GHESFeatureSupport records which feature *APIs* responded on this GHES
// instance. These signals say "the endpoint exists on this appliance and the
// token can see it" (probe = HTTP 200/204). They do NOT prove the feature is
// enabled or configured for any specific organisation — that requires reading
// the management settings or the per-org GHAS API.
//
// Use these to gate findings that would otherwise be invalid on appliances
// where the underlying API simply does not exist (e.g. older GHES versions or
// disabled subsystems).
type GHESFeatureSupport struct {
	// ActionsAPIAvailable is true when GET /enterprises/actions/permissions
	// returned a 2xx/204 response.
	ActionsAPIAvailable bool `json:"actions_api_available"`
	// DependabotAPIAvailable is true when GET /enterprises/dependabot/alerts
	// returned a 2xx/204 response.
	DependabotAPIAvailable bool `json:"dependabot_api_available"`
	// CodeScanningAPIAvailable is true when GET /enterprises/code-scanning/alerts
	// returned a 2xx/204 response.
	CodeScanningAPIAvailable bool `json:"code_scanning_api_available"`
	// SecretScanningAPIAvailable is true when GET /enterprises/secret-scanning/alerts
	// returned a 2xx/204 response.
	SecretScanningAPIAvailable bool `json:"secret_scanning_api_available"`
}

// GHESAdminStats holds aggregate statistics from GET /api/v3/enterprise/stats/all.
type GHESAdminStats struct {
	Repos  *GHESRepoStats  `json:"repos,omitempty"`
	Hooks  *GHESHookStats  `json:"hooks,omitempty"`
	Pages  *GHESPageStats  `json:"pages,omitempty"`
	Orgs   *GHESOrgStats   `json:"orgs,omitempty"`
	Users  *GHESUserStats  `json:"users,omitempty"`
	Pulls  *GHESPullStats  `json:"pulls,omitempty"`
	Issues *GHESIssueStats `json:"issues,omitempty"`
	Gists  *GHESGistStats  `json:"gists,omitempty"`
}

// GHESRepoStats holds repository statistics.
type GHESRepoStats struct {
	TotalRepos  int `json:"total_repos"`
	RootRepos   int `json:"root_repos"`
	ForkRepos   int `json:"fork_repos"`
	OrgRepos    int `json:"org_repos"`
	TotalPushes int `json:"total_pushes"`
	TotalWikis  int `json:"total_wikis"`
}

// GHESHookStats holds webhook statistics.
type GHESHookStats struct {
	TotalHooks    int `json:"total_hooks"`
	ActiveHooks   int `json:"active_hooks"`
	InactiveHooks int `json:"inactive_hooks"`
}

// GHESPageStats holds GitHub Pages statistics.
type GHESPageStats struct {
	TotalPages int `json:"total_pages"`
}

// GHESOrgStats holds organization statistics.
type GHESOrgStats struct {
	TotalOrgs        int `json:"total_orgs"`
	DisabledOrgs     int `json:"disabled_orgs"`
	TotalTeams       int `json:"total_teams"`
	TotalTeamMembers int `json:"total_team_members"`
}

// GHESUserStats holds user statistics.
type GHESUserStats struct {
	TotalUsers     int `json:"total_users"`
	AdminUsers     int `json:"admin_users"`
	SuspendedUsers int `json:"suspended_users"`
}

// GHESPullStats holds pull request statistics.
type GHESPullStats struct {
	TotalPulls       int `json:"total_pulls"`
	MergedPulls      int `json:"merged_pulls"`
	MergeablePulls   int `json:"mergeable_pulls"`
	UnmergeablePulls int `json:"unmergeable_pulls"`
}

// GHESIssueStats holds issue statistics.
type GHESIssueStats struct {
	TotalIssues  int `json:"total_issues"`
	OpenIssues   int `json:"open_issues"`
	ClosedIssues int `json:"closed_issues"`
}

// GHESGistStats holds gist statistics.
type GHESGistStats struct {
	TotalGists   int `json:"total_gists"`
	PrivateGists int `json:"private_gists"`
	PublicGists  int `json:"public_gists"`
}

// GHESSecurityAlerts holds aggregate security alert counts for a GHES instance.
type GHESSecurityAlerts struct {
	Available                bool `json:"available"`
	OpenDependabotAlerts     int  `json:"open_dependabot_alerts"`
	CriticalDependabot       int  `json:"critical_dependabot"`
	HighDependabot           int  `json:"high_dependabot"`
	OpenCodeScanningAlerts   int  `json:"open_code_scanning_alerts"`
	OpenSecretScanningAlerts int  `json:"open_secret_scanning_alerts"`
}

// GHESAuditLogData holds a summary of recent site admin audit log events.
type GHESAuditLogData struct {
	TotalEventsScanned int                     `json:"total_events_scanned"`
	SuspiciousEvents   []*SuspiciousAuditEvent `json:"suspicious_events,omitempty"`
}
