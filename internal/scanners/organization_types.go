// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import "github.com/google/go-github/v83/github"

// OrganizationData holds organization information
type OrganizationData struct {
	Enterprise         string                 `json:"enterprise,omitempty"`
	Settings           *OrgSettings           `json:"settings,omitempty"`
	Copilot            *OrgCopilotData        `json:"copilot,omitempty"`
	ActionsPermissions *OrgActionsPermissions `json:"actions_permissions,omitempty"`
	SecurityAlerts     *OrgSecurityAlerts     `json:"security_alerts,omitempty"`
	SecurityManagers   *OrgSecurityManagers   `json:"security_managers,omitempty"`
}

// OrgSettings represents organization settings
type OrgSettings struct {
	Visibility OrgVisibility `json:"visibility"`
	Security   OrgSecurity   `json:"security"`
}

// OrgVisibility represents organization visibility settings
type OrgVisibility struct {
	DefaultRepositoryPermission        string `json:"default_repository_permission,omitempty"`
	MembersCanCreatePublicRepositories bool   `json:"members_can_create_public_repositories"`
}

// OrgSecurity represents organization security settings
type OrgSecurity struct {
	TwoFactorRequirementEnabled bool `json:"two_factor_requirement_enabled"`
	WebCommitSignoffRequired    bool `json:"web_commit_signoff_required"`
	// EMUEnabled is true when the parent enterprise uses Enterprise Managed Users.
	// When EMU is active, 2FA is managed by the identity provider, not GitHub.
	EMUEnabled bool `json:"emu_enabled"`

	// Org-wide defaults applied to new repositories.
	//
	// The six *ForNewRepos fields below (all except PrivateVulnerabilityReportingForNewRepos)
	// are read from organization API fields that GitHub has deprecated in favour of
	// code security configurations. An organization that sets its defaults through a
	// default code security configuration can report false here; see
	// CodeSecurityConfigurations for the declared new-repository defaults.
	AdvancedSecurityForNewRepos              bool `json:"advanced_security_enabled_for_new_repos"`
	DependabotAlertsForNewRepos              bool `json:"dependabot_alerts_enabled_for_new_repos"`
	DependabotSecurityUpdatesForNewRepos     bool `json:"dependabot_security_updates_enabled_for_new_repos"`
	DependencyGraphForNewRepos               bool `json:"dependency_graph_enabled_for_new_repos"`
	SecretScanningForNewRepos                bool `json:"secret_scanning_enabled_for_new_repos"`
	SecretScanningPushProtectionForNewRepos  bool `json:"secret_scanning_push_protection_enabled_for_new_repos"`
	PrivateVulnerabilityReportingForNewRepos bool `json:"private_vulnerability_reporting_enabled_for_new_repos"`

	// CodeSecurityConfigurations holds the organization's code security configurations
	// and the defaults applied to new repositories. It is nil when the data was not
	// collected (for example, a report produced by an older ghqr version).
	CodeSecurityConfigurations *OrgCodeSecurityConfigurations `json:"code_security_configurations,omitempty"`
}

// Reasons reported when code security configuration data could not be read.
const (
	// CodeSecurityConfigUnavailableForbidden means the API returned 403; the token user
	// must be an organization owner or security manager and the token needs read:org.
	CodeSecurityConfigUnavailableForbidden = "forbidden"
	// CodeSecurityConfigUnavailableNotFound means the API returned 404; the endpoint is
	// unavailable (for example, an older GHES version) or access is masked.
	CodeSecurityConfigUnavailableNotFound = "not_found"
	// CodeSecurityConfigUnavailableError means the request failed for any other reason.
	CodeSecurityConfigUnavailableError = "error"
)

// OrgCodeSecurityConfigurations holds organization code security configurations and
// which of them are the defaults for new repositories.
//
// The two endpoints are read independently. When an endpoint is readable its slice is
// non-nil (an empty array means "readable, none present"); when it is not readable the
// slice is nil and the matching *UnavailableReason explains why.
type OrgCodeSecurityConfigurations struct {
	// ConfigurationsReadable is true when GET /orgs/{org}/code-security/configurations succeeded.
	ConfigurationsReadable bool `json:"configurations_readable"`
	// ConfigurationsUnavailableReason is one of the CodeSecurityConfigUnavailable* constants.
	ConfigurationsUnavailableReason string `json:"configurations_unavailable_reason,omitempty"`
	// Configurations lists every configuration available to the organization
	// (organization-owned plus GitHub/enterprise-provided ones).
	Configurations []*github.CodeSecurityConfiguration `json:"configurations"`

	// DefaultsReadable is true when GET /orgs/{org}/code-security/configurations/defaults succeeded.
	DefaultsReadable bool `json:"defaults_readable"`
	// DefaultsUnavailableReason is one of the CodeSecurityConfigUnavailable* constants.
	DefaultsUnavailableReason string `json:"defaults_unavailable_reason,omitempty"`
	// DefaultConfigurations lists the configurations applied by default to new repositories.
	// DefaultForNewRepos is "public", "private_and_internal", or "all".
	DefaultConfigurations []*github.CodeSecurityConfigurationWithDefaultForNewRepos `json:"default_configurations"`
}

// OrgCopilotData holds GitHub Copilot billing and policy information for an org.
type OrgCopilotData struct {
	// BillingEnabled is false when GetCopilotBilling returns a 404 (no Copilot subscription).
	BillingEnabled        bool   `json:"billing_enabled"`
	SeatManagementSetting string `json:"seat_management_setting,omitempty"`
	PublicCodeSuggestions  string `json:"public_code_suggestions,omitempty"`
	CopilotChat           string `json:"copilot_chat,omitempty"`
	// IDEChat controls whether Copilot Chat is available in IDEs (e.g. VS Code, JetBrains).
	IDEChat string `json:"ide_chat,omitempty"`
	// PlatformChat controls whether Copilot Chat is available on GitHub.com / mobile.
	PlatformChat string `json:"platform_chat,omitempty"`
	// CLI controls whether Copilot is available in the CLI (gh copilot).
	CLI string `json:"cli,omitempty"`
	TotalSeats    int `json:"total_seats"`
	ActiveThisCycle   int `json:"active_this_cycle"`
	InactiveThisCycle int `json:"inactive_this_cycle"`
}

// OrgActionsPermissions holds GitHub Actions workflow permission settings.
type OrgActionsPermissions struct {
	// AllowedActions is "all", "local_only", or "selected".
	AllowedActions string `json:"allowed_actions,omitempty"`
	// DefaultWorkflowPermissions is "read" or "write".
	DefaultWorkflowPermissions string `json:"default_workflow_permissions,omitempty"`
	// CanApprovePullRequestReviews indicates whether Actions can approve PRs.
	CanApprovePullRequestReviews bool `json:"can_approve_pull_request_reviews"`
}

// OrgSecurityAlerts holds aggregate open security alert counts for an org.
type OrgSecurityAlerts struct {
	OpenDependabotAlerts     int `json:"open_dependabot_alerts"`
	CriticalDependabot       int `json:"critical_dependabot"`
	HighDependabot           int `json:"high_dependabot"`
	OpenCodeScanningAlerts   int `json:"open_code_scanning_alerts"`
	OpenSecretScanningAlerts int `json:"open_secret_scanning_alerts"`
	// Available is false when GHAS is not licensed (API returns 404/403).
	Available bool `json:"available"`
}

// OrgSecurityManagers holds whether a security manager team is configured.
type OrgSecurityManagers struct {
	HasSecurityManager bool `json:"has_security_manager"`
}
