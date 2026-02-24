// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog/log"
)

// OrganizationScanner handles scanning organization-level data
type OrganizationScanner struct {
	client *github.Client
	org    string
}

// NewOrganizationScanner creates a new organization scanner
func NewOrganizationScanner(client *github.Client, org string) *OrganizationScanner {
	return &OrganizationScanner{
		client: client,
		org:    org,
	}
}

// extractSettings extracts organization settings from REST org data
func (o *OrganizationScanner) extractSettings(org *github.Organization) *OrgSettings {
	return &OrgSettings{
		Visibility: OrgVisibility{
			DefaultRepositoryPermission:        org.GetDefaultRepoPermission(),
			MembersCanCreatePublicRepositories: org.GetMembersCanCreatePublicRepos(),
		},
		Security: OrgSecurity{
			TwoFactorRequirementEnabled:             org.GetTwoFactorRequirementEnabled(),
			WebCommitSignoffRequired:                org.GetWebCommitSignoffRequired(),
			AdvancedSecurityForNewRepos:             org.GetAdvancedSecurityEnabledForNewRepos(),
			DependabotAlertsForNewRepos:             org.GetDependabotAlertsEnabledForNewRepos(),
			DependabotSecurityUpdatesForNewRepos:    org.GetDependabotSecurityUpdatesEnabledForNewRepos(),
			DependencyGraphForNewRepos:              org.GetDependencyGraphEnabledForNewRepos(),
			SecretScanningForNewRepos:               org.GetSecretScanningEnabledForNewRepos(),
			SecretScanningPushProtectionForNewRepos: org.GetSecretScanningPushProtectionEnabledForNewRepos(),
		},
	}
}

// scanCopilot fetches Copilot billing settings for the org.
// Returns nil (no error) when Copilot is not enabled for the org.
func (o *OrganizationScanner) scanCopilot(ctx context.Context) (*OrgCopilotData, error) {
	billing, resp, err := o.client.Copilot.GetCopilotBilling(ctx, o.org)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			log.Debug().Str("organization", o.org).Msg("Copilot billing not found (not enabled)")
			return &OrgCopilotData{BillingEnabled: false}, nil
		}
		return nil, fmt.Errorf("failed to get copilot billing: %w", err)
	}

	data := &OrgCopilotData{
		BillingEnabled:        true,
		SeatManagementSetting: billing.SeatManagementSetting,
		PublicCodeSuggestions: billing.PublicCodeSuggestions,
		CopilotChat:           billing.CopilotChat,
	}
	if sb := billing.SeatBreakdown; sb != nil {
		data.TotalSeats = sb.Total
		data.ActiveThisCycle = sb.ActiveThisCycle
		data.InactiveThisCycle = sb.InactiveThisCycle
	}
	return data, nil
}

// scanActionsPermissions fetches org-level GitHub Actions workflow permissions.
func (o *OrganizationScanner) scanActionsPermissions(ctx context.Context) (*OrgActionsPermissions, error) {
	type actionsPermissionsResponse struct {
		AllowedActions               string `json:"allowed_actions"`
		DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
		CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	}

	// GET /orgs/{org}/actions/permissions
	req, err := o.client.NewRequest("GET", fmt.Sprintf("orgs/%s/actions/permissions", o.org), nil)
	if err != nil {
		return nil, err
	}
	var perms actionsPermissionsResponse
	resp, err := o.client.Do(ctx, req, &perms)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden) {
			log.Debug().Str("organization", o.org).Msg("Actions permissions not accessible")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get actions permissions: %w", err)
	}

	// GET /orgs/{org}/actions/permissions/workflow
	type workflowPermissionsResponse struct {
		DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
		CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	}
	wfReq, err := o.client.NewRequest("GET", fmt.Sprintf("orgs/%s/actions/permissions/workflow", o.org), nil)
	if err != nil {
		return nil, err
	}
	var wfPerms workflowPermissionsResponse
	if _, err2 := o.client.Do(ctx, wfReq, &wfPerms); err2 == nil {
		perms.DefaultWorkflowPermissions = wfPerms.DefaultWorkflowPermissions
		perms.CanApprovePullRequestReviews = wfPerms.CanApprovePullRequestReviews
	}

	return &OrgActionsPermissions{
		AllowedActions:               perms.AllowedActions,
		DefaultWorkflowPermissions:   perms.DefaultWorkflowPermissions,
		CanApprovePullRequestReviews: perms.CanApprovePullRequestReviews,
	}, nil
}

// scanSecurityAlerts fetches aggregate open security alert counts for the org.
func (o *OrganizationScanner) scanSecurityAlerts(ctx context.Context) (*OrgSecurityAlerts, error) {
	result := &OrgSecurityAlerts{}

	// Dependabot alerts — may return 404/403 when GHAS not licensed.
	type dependabotAlert struct {
		SecurityAdvisory struct {
			Severity string `json:"severity"`
		} `json:"security_advisory"`
	}

	var dependabotAlerts []dependabotAlert
	depReq, err := o.client.NewRequest("GET",
		fmt.Sprintf("orgs/%s/dependabot/alerts?state=open&per_page=100", o.org), nil)
	if err == nil {
		depResp, depErr := o.client.Do(ctx, depReq, &dependabotAlerts)
		if depErr == nil {
			result.Available = true
			result.OpenDependabotAlerts = len(dependabotAlerts)
			for _, a := range dependabotAlerts {
				switch strings.ToLower(a.SecurityAdvisory.Severity) {
				case "critical":
					result.CriticalDependabot++
				case "high":
					result.HighDependabot++
				}
			}
		} else if depResp != nil && (depResp.StatusCode == http.StatusNotFound || depResp.StatusCode == http.StatusForbidden) {
			log.Debug().Str("organization", o.org).Msg("Dependabot org alerts not accessible (GHAS may not be licensed)")
		} else {
			log.Warn().Err(depErr).Str("organization", o.org).Msg("Failed to fetch dependabot org alerts")
		}
	}

	// Code scanning alerts.
	type codeScanningAlert struct{}
	var csAlerts []codeScanningAlert
	csReq, err2 := o.client.NewRequest("GET",
		fmt.Sprintf("orgs/%s/code-scanning/alerts?state=open&per_page=100", o.org), nil)
	if err2 == nil {
		csResp, csErr := o.client.Do(ctx, csReq, &csAlerts)
		if csErr == nil {
			result.Available = true
			result.OpenCodeScanningAlerts = len(csAlerts)
		} else if csResp != nil && (csResp.StatusCode == http.StatusNotFound || csResp.StatusCode == http.StatusForbidden) {
			log.Debug().Str("organization", o.org).Msg("Code scanning org alerts not accessible")
		}
	}

	// Secret scanning alerts.
	type secretAlert struct{}
	var ssAlerts []secretAlert
	ssReq, err3 := o.client.NewRequest("GET",
		fmt.Sprintf("orgs/%s/secret-scanning/alerts?state=open&per_page=100", o.org), nil)
	if err3 == nil {
		ssResp, ssErr := o.client.Do(ctx, ssReq, &ssAlerts)
		if ssErr == nil {
			result.Available = true
			result.OpenSecretScanningAlerts = len(ssAlerts)
		} else if ssResp != nil && (ssResp.StatusCode == http.StatusNotFound || ssResp.StatusCode == http.StatusForbidden) {
			log.Debug().Str("organization", o.org).Msg("Secret scanning org alerts not accessible")
		}
	}

	return result, nil
}

// scanSecurityManagers checks whether a security manager team is configured.
func (o *OrganizationScanner) scanSecurityManagers(ctx context.Context) (*OrgSecurityManagers, error) {
	type secMgrTeam struct {
		Slug string `json:"slug"`
	}
	var teams []secMgrTeam
	req, err := o.client.NewRequest("GET", fmt.Sprintf("orgs/%s/security-managers", o.org), nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(ctx, req, &teams)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden) {
			log.Debug().Str("organization", o.org).Msg("Security managers endpoint not accessible")
			return &OrgSecurityManagers{}, nil
		}
		return nil, fmt.Errorf("failed to get security managers: %w", err)
	}
	return &OrgSecurityManagers{HasSecurityManager: len(teams) > 0}, nil
}

// ScanAll retrieves organization settings and Copilot info.
func (o *OrganizationScanner) ScanAll(ctx context.Context) (*OrganizationData, error) {
	log.Info().Str("organization", o.org).Msg("Starting organization scan")

	data := &OrganizationData{}

	org, _, err := o.client.Organizations.Get(ctx, o.org)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	data.Settings = o.extractSettings(org)

	copilot, err := o.scanCopilot(ctx)
	if err != nil {
		log.Warn().Err(err).Str("organization", o.org).Msg("Failed to scan Copilot settings")
	} else {
		data.Copilot = copilot
	}

	actionsPerms, err := o.scanActionsPermissions(ctx)
	if err != nil {
		log.Warn().Err(err).Str("organization", o.org).Msg("Failed to scan Actions permissions")
	} else {
		data.ActionsPermissions = actionsPerms
	}

	secAlerts, err := o.scanSecurityAlerts(ctx)
	if err != nil {
		log.Warn().Err(err).Str("organization", o.org).Msg("Failed to scan security alerts")
	} else {
		data.SecurityAlerts = secAlerts
	}

	secMgrs, err := o.scanSecurityManagers(ctx)
	if err != nil {
		log.Warn().Err(err).Str("organization", o.org).Msg("Failed to scan security managers")
	} else {
		data.SecurityManagers = secMgrs
	}

	log.Info().
		Str("organization", o.org).
		Msg("Organization scan completed")

	return data, nil
}
