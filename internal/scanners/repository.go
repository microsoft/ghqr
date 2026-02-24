// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"strings"
)

// RepositoryScanner handles scanning repository-level data
type RepositoryScanner struct{}

// MapNodeToData converts a RepositoryNode (from the GitHub GraphQL API) into RepositoryData.
// This is the single authoritative conversion used by both the single-repo (ScanAll) and
// batch (FetchRepositoriesBatch) scan paths.
func MapNodeToData(gql RepositoryNode) *RepositoryData {
	data := &RepositoryData{}

	// Name, description, and last push timestamp
	data.Name = string(gql.Name)
	data.Description = string(gql.Description)
	data.PushedAt = string(gql.PushedAt)

	// Basic features
	data.BasicFeatures = &RepoBasicFeatures{
		HasIssues:      bool(gql.HasIssuesEnabled),
		HasProjects:    bool(gql.HasProjectsEnabled),
		HasWiki:        bool(gql.HasWikiEnabled),
		HasDiscussions: bool(gql.HasDiscussionsEnabled),
	}

	// Access configuration
	data.Access = &RepoAccessConfig{
		Visibility:          string(gql.Visibility),
		Private:             bool(gql.IsPrivate),
		IsTemplate:          bool(gql.IsTemplate),
		Archived:            bool(gql.IsArchived),
		Fork:                bool(gql.IsFork),
		DeleteBranchOnMerge: bool(gql.DeleteBranchOnMerge),
	}

	// Security features — entirely from GraphQL
	security := &RepoSecurityFeatures{}

	security.VulnerabilityAlerts = &SecurityFeature{
		Enabled: bool(gql.HasVulnerabilityAlertsEnabled),
	}

	bySeverity := make(map[string]int)
	total := 0
	for _, node := range gql.VulnerabilityAlerts.Nodes {
		if node.DismissedAt == nil {
			sev := strings.ToLower(string(node.SecurityVulnerability.Severity))
			bySeverity[sev]++
			total++
		}
	}
	security.DependabotAlerts = &DependabotInfo{
		Enabled:         bool(gql.HasVulnerabilityAlertsEnabled),
		TotalOpenAlerts: total,
		BySeverity:      bySeverity,
	}

	// File existence: check oid (non-empty = file exists), not full text content.
	security.SecurityPolicy = &SecurityFeature{
		Enabled: gql.SecurityMdFile.Blob.Oid != "",
	}

	codeownersPath := ""
	if gql.CodeownersFile.Blob.Oid != "" {
		codeownersPath = "CODEOWNERS"
	} else if gql.GithubCodeownersFile.Blob.Oid != "" {
		codeownersPath = ".github/CODEOWNERS"
	} else if gql.DocsCodeownersFile.Blob.Oid != "" {
		codeownersPath = "docs/CODEOWNERS"
	}
	security.CodeOwnersFile = &CodeOwnersInfo{
		Exists: codeownersPath != "",
		Path:   codeownersPath,
	}

	data.Security = security

	// Branch protection — from GraphQL defaultBranchRef
	bpr := gql.DefaultBranchRef.BranchProtectionRule
	if bpr.Pattern == "" {
		data.BranchProtection = &BranchProtectionDetail{Protected: false}
	} else {
		var statusChecks *RequiredStatusChecks
		if bool(bpr.RequiresStatusChecks) {
			contexts := make([]string, 0, len(bpr.RequiredStatusChecks))
			for _, sc := range bpr.RequiredStatusChecks {
				contexts = append(contexts, string(sc.Context))
			}
			statusChecks = &RequiredStatusChecks{
				Strict:   bool(bpr.RequiresStrictStatusChecks),
				Contexts: contexts,
			}
		}
		data.BranchProtection = &BranchProtectionDetail{
			Protected:             true,
			Branch:                string(gql.DefaultBranchRef.Name),
			RequiredLinearHistory: bool(bpr.RequiresLinearHistory),
			AllowForcePushes:      bool(bpr.AllowsForcePushes),
			AllowDeletions:        bool(bpr.AllowsDeletions),
			RequiredSignatures:    bool(bpr.RequiresCommitSignatures),
			RequiredStatusChecks:  statusChecks,
			RequiredPullRequestReviews: &RequiredPRReviews{
				RequiredApprovingReviewCount: int(bpr.RequiredApprovingReviewCount),
				DismissStaleReviews:          bool(bpr.DismissesStaleReviews),
				RequireCodeOwnerReviews:      bool(bpr.RequiresCodeOwnerReviews),
			},
		}
	}

	// Metadata
	license := ""
	if gql.LicenseInfo.Name != "" {
		license = string(gql.LicenseInfo.Name)
	}
	topics := make([]string, 0, len(gql.RepositoryTopics.Nodes))
	for _, node := range gql.RepositoryTopics.Nodes {
		topics = append(topics, string(node.Topic.Name))
	}
	data.Metadata = &RepoMetadata{
		Topics:        topics,
		Language:      string(gql.PrimaryLanguage.Name),
		DefaultBranch: string(gql.DefaultBranchRef.Name),
		License:       license,
	}

	// Collaborators
	collaborators := make([]*CollaboratorInfo, 0, len(gql.Collaborators.Edges))
	for _, edge := range gql.Collaborators.Edges {
		collaborators = append(collaborators, &CollaboratorInfo{
			Login:       string(edge.Node.Login),
			Permissions: string(edge.Permission),
		})
	}
	data.Collaborators = collaborators

	// Deploy keys
	deployKeys := make([]*DeployKeyInfo, 0, len(gql.DeployKeys.Nodes))
	for _, node := range gql.DeployKeys.Nodes {
		deployKeys = append(deployKeys, &DeployKeyInfo{
			Title:    string(node.Title),
			ReadOnly: bool(node.ReadOnly),
			Verified: bool(node.Verified),
		})
	}
	data.DeployKeys = deployKeys

	// Dependabot config file (existence check via oid)
	data.DependabotConfig = &DependabotConfigInfo{
		Exists: gql.DependabotYmlFile.Blob.Oid != "" || gql.DependabotYamlFile.Blob.Oid != "",
	}
	if data.DependabotConfig.Exists {
		if gql.DependabotYmlFile.Blob.Oid != "" {
			data.DependabotConfig.Path = ".github/dependabot.yml"
		} else {
			data.DependabotConfig.Path = ".github/dependabot.yaml"
		}
	}

	// CodeQL config file (existence check via oid)
	if gql.CodeqlConfigFile.Blob.Oid != "" || gql.CodeqlAltConfigFile.Blob.Oid != "" {
		path := ".github/codeql-config.yml"
		if gql.CodeqlConfigFile.Blob.Oid != "" {
			path = ".github/codeql/config.yml"
		}
		data.CodeScanningConfig = &CodeScanningConfigInfo{
			CodeQLConfigExists: true,
			CodeQLConfigPath:   path,
		}
	}

	// Discussion settings
	data.DiscussionSettings = &DiscussionSettings{
		Enabled: bool(gql.HasDiscussionsEnabled),
	}

	return data
}
