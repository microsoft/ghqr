// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

// GHESData holds all GitHub Enterprise Server instance scan results.
type GHESData struct {
	ServerInfo     *GHESServerInfo     `json:"server_info,omitempty"`
	License        *GHESLicense        `json:"license,omitempty"`
	Settings       *GHESSettings       `json:"settings,omitempty"`
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
type GHESLicense struct {
	Seats               int    `json:"seats"`
	SeatsUsed           int    `json:"seats_used"`
	SeatsAvailable      int    `json:"seats_available"`
	Kind                string `json:"kind,omitempty"`
	DaysUntilExpiration int    `json:"days_until_expiration"`
	ExpireAt            string `json:"expire_at,omitempty"`
	// ClusterSupport indicates whether clustering is part of the license.
	ClusterSupport bool `json:"cluster_support"`
}

// GHESSettings holds GHES site admin configuration retrieved via REST API.
type GHESSettings struct {
	// Authentication
	AuthMode            string `json:"auth_mode,omitempty"`
	BuiltinAuthFallback bool   `json:"builtin_auth_fallback"`
	SAMLEnabled         bool   `json:"saml_enabled"`
	LDAPEnabled         bool   `json:"ldap_enabled"`
	CASEnabled          bool   `json:"cas_enabled"`
	// TLS / Networking
	SubdomainIsolation bool `json:"subdomain_isolation"`
	TLSEnforced        bool `json:"tls_enforced"`
	PrivateMode        bool `json:"private_mode"`
	// GitHub Actions
	ActionsEnabled     bool   `json:"actions_enabled"`
	ActionsStorageType string `json:"actions_storage_type,omitempty"`
	// GitHub Packages
	PackagesEnabled bool `json:"packages_enabled"`
	// GitHub Pages
	PagesEnabled            bool `json:"pages_enabled"`
	PagesPublicPagesEnabled bool `json:"pages_public_pages_enabled"`
	// GitHub Advanced Security
	GHASEnabled                  bool `json:"ghas_enabled"`
	SecretScanningEnabled        bool `json:"secret_scanning_enabled"`
	SecretScanningPushProtection bool `json:"secret_scanning_push_protection"`
	DependabotAlertsEnabled      bool `json:"dependabot_alerts_enabled"`
	DependabotUpdatesEnabled     bool `json:"dependabot_updates_enabled"`
	CodeScanningEnabled          bool `json:"code_scanning_enabled"`
	// Maintenance
	MaintenanceMode bool `json:"maintenance_mode"`
	// SSH access
	AdminSSHEnabled bool `json:"admin_ssh_enabled"`
	// Signup
	SignupEnabled bool `json:"signup_enabled"`
	// Collect stats
	CollectStatsEnabled bool `json:"collect_stats_enabled"`
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
