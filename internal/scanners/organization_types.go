// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

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

	// Org-wide defaults applied to new repositories
	AdvancedSecurityForNewRepos             bool `json:"advanced_security_enabled_for_new_repos"`
	DependabotAlertsForNewRepos             bool `json:"dependabot_alerts_enabled_for_new_repos"`
	DependabotSecurityUpdatesForNewRepos    bool `json:"dependabot_security_updates_enabled_for_new_repos"`
	DependencyGraphForNewRepos              bool `json:"dependency_graph_enabled_for_new_repos"`
	SecretScanningForNewRepos               bool `json:"secret_scanning_enabled_for_new_repos"`
	SecretScanningPushProtectionForNewRepos bool `json:"secret_scanning_push_protection_enabled_for_new_repos"`
}

// OrgCopilotData holds GitHub Copilot billing and policy information for an org.
type OrgCopilotData struct {
	// BillingEnabled is false when GetCopilotBilling returns a 404 (no Copilot subscription).
	BillingEnabled        bool   `json:"billing_enabled"`
	SeatManagementSetting string `json:"seat_management_setting,omitempty"`
	PublicCodeSuggestions string `json:"public_code_suggestions,omitempty"`
	CopilotChat           string `json:"copilot_chat,omitempty"`
	TotalSeats            int    `json:"total_seats"`
	ActiveThisCycle       int    `json:"active_this_cycle"`
	InactiveThisCycle     int    `json:"inactive_this_cycle"`
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
