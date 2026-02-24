// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

// RepositoryData holds all repository information
type RepositoryData struct {
	Organization       string                  `json:"organization,omitempty"`
	Enterprise         string                  `json:"enterprise,omitempty"`
	Name               string                  `json:"name,omitempty"`
	Description        string                  `json:"description,omitempty"`
	PushedAt           string                  `json:"pushed_at,omitempty"`
	BasicFeatures      *RepoBasicFeatures      `json:"basic_features,omitempty"`
	Access             *RepoAccessConfig       `json:"access,omitempty"`
	Security           *RepoSecurityFeatures   `json:"security,omitempty"`
	BranchProtection   *BranchProtectionDetail `json:"branch_protection,omitempty"`
	Metadata           *RepoMetadata           `json:"metadata,omitempty"`
	Collaborators      []*CollaboratorInfo     `json:"collaborators,omitempty"`
	DeployKeys         []*DeployKeyInfo        `json:"deploy_keys,omitempty"`
	DependabotConfig   *DependabotConfigInfo   `json:"dependabot_config,omitempty"`
	CodeScanningConfig *CodeScanningConfigInfo `json:"code_scanning_config,omitempty"`
	DiscussionSettings *DiscussionSettings     `json:"discussion_settings,omitempty"`
}

// RepoBasicFeatures represents basic repository features
type RepoBasicFeatures struct {
	HasIssues      bool `json:"has_issues"`
	HasProjects    bool `json:"has_projects"`
	HasWiki        bool `json:"has_wiki"`
	HasDiscussions bool `json:"has_discussions"`
}

// RepoAccessConfig represents repository access configuration
type RepoAccessConfig struct {
	Visibility          string `json:"visibility,omitempty"`
	Private             bool   `json:"private"`
	IsTemplate          bool   `json:"is_template"`
	Archived            bool   `json:"archived"`
	Fork                bool   `json:"fork"`
	DeleteBranchOnMerge bool   `json:"delete_branch_on_merge"`
}

// RepoSecurityFeatures represents repository security features available via GraphQL
type RepoSecurityFeatures struct {
	VulnerabilityAlerts *SecurityFeature `json:"vulnerability_alerts,omitempty"`
	DependabotAlerts    *DependabotInfo  `json:"dependabot_alerts,omitempty"`
	SecurityPolicy      *SecurityFeature `json:"security_policy,omitempty"`
	CodeOwnersFile      *CodeOwnersInfo  `json:"codeowners_file,omitempty"`
}

// SecurityFeature represents a generic security feature
type SecurityFeature struct {
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}

// DependabotInfo represents Dependabot alert information from GraphQL vulnerabilityAlerts
type DependabotInfo struct {
	Enabled         bool           `json:"enabled"`
	TotalOpenAlerts int            `json:"total_open_alerts"`
	BySeverity      map[string]int `json:"by_severity,omitempty"`
}

// CodeOwnersInfo represents CODEOWNERS file information
type CodeOwnersInfo struct {
	Exists bool   `json:"exists"`
	Path   string `json:"path,omitempty"`
}

// RepoMetadata represents repository metadata
type RepoMetadata struct {
	Topics        []string `json:"topics,omitempty"`
	Language      string   `json:"language,omitempty"`
	DefaultBranch string   `json:"default_branch,omitempty"`
	License       string   `json:"license,omitempty"`
}

// BranchProtectionDetail represents branch protection from GraphQL defaultBranchRef.branchProtectionRule
type BranchProtectionDetail struct {
	Protected                  bool                  `json:"protected"`
	Branch                     string                `json:"branch"`
	RequiredPullRequestReviews *RequiredPRReviews    `json:"required_pull_request_reviews,omitempty"`
	RequiredStatusChecks       *RequiredStatusChecks `json:"required_status_checks,omitempty"`
	RequiredLinearHistory      bool                  `json:"required_linear_history"`
	AllowForcePushes           bool                  `json:"allow_force_pushes"`
	AllowDeletions             bool                  `json:"allow_deletions"`
	RequiredSignatures         bool                  `json:"required_signatures"`
}

// RequiredPRReviews represents required pull request review settings
type RequiredPRReviews struct {
	RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
	DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
	RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
}

// RequiredStatusChecks represents required status check settings
type RequiredStatusChecks struct {
	Strict   bool     `json:"strict"`
	Contexts []string `json:"contexts,omitempty"`
}

// CollaboratorInfo represents repository collaborator information
type CollaboratorInfo struct {
	Login       string `json:"login"`
	Permissions string `json:"permissions"`
}

// DeployKeyInfo represents deploy key information
type DeployKeyInfo struct {
	Title    string `json:"title"`
	ReadOnly bool   `json:"read_only"`
	Verified bool   `json:"verified"`
}

// DependabotConfigInfo represents Dependabot configuration file information
type DependabotConfigInfo struct {
	Exists bool   `json:"exists"`
	Path   string `json:"path,omitempty"`
}

// CodeScanningConfigInfo represents CodeQL configuration file information
type CodeScanningConfigInfo struct {
	CodeQLConfigExists bool   `json:"codeql_config_exists"`
	CodeQLConfigPath   string `json:"codeql_config_path,omitempty"`
}

// DiscussionSettings represents discussion settings
type DiscussionSettings struct {
	Enabled bool `json:"enabled"`
}
