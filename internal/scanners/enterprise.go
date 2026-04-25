// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
)

// EnterpriseScanner handles scanning enterprise-level data
type EnterpriseScanner struct {
	graphqlClient *githubv4.Client
	restClient    *github.Client
	enterprise    string
}

// NewEnterpriseScanner creates a new enterprise scanner with both REST and GraphQL clients.
func NewEnterpriseScanner(graphqlClient *githubv4.Client, restClient *github.Client, enterprise string) *EnterpriseScanner {
	return &EnterpriseScanner{
		graphqlClient: graphqlClient,
		restClient:    restClient,
		enterprise:    enterprise,
	}
}

// getSettings retrieves enterprise settings via GraphQL. Hard-fails if GraphQL is unavailable.
func (e *EnterpriseScanner) getSettings(ctx context.Context) (*EnterpriseSettings, error) {
	log.Debug().Str("enterprise", e.enterprise).Msg("Fetching enterprise settings via GraphQL")

	var query struct {
		Enterprise struct {
			ID          githubv4.String
			Name        githubv4.String
			Slug        githubv4.String
			Description githubv4.String
			URL         githubv4.String
			WebsiteURL  githubv4.String
			CreatedAt   githubv4.DateTime
		} `graphql:"enterprise(slug: $slug)"`
	}

	variables := map[string]interface{}{
		"slug": githubv4.String(e.enterprise),
	}

	if err := e.graphqlClient.Query(ctx, &query, variables); err != nil {
		return nil, fmt.Errorf("failed to query enterprise settings: %w", err)
	}

	return &EnterpriseSettings{
		ID:          string(query.Enterprise.ID),
		Name:        string(query.Enterprise.Name),
		Slug:        string(query.Enterprise.Slug),
		Description: string(query.Enterprise.Description),
		URL:         string(query.Enterprise.URL),
		WebsiteURL:  string(query.Enterprise.WebsiteURL),
		CreatedAt:   query.Enterprise.CreatedAt.String(),
	}, nil
}

// getEMUStatus checks whether the enterprise uses Enterprise Managed Users (EMU)
// by querying the enterprise-level identity provider via GraphQL.
// When an IdP is configured at the enterprise level, the enterprise is EMU-enabled
// and authentication (including 2FA) is managed by the external identity provider.
// Returns false (no error) if the query fails due to insufficient permissions.
func (e *EnterpriseScanner) getEMUStatus(ctx context.Context) (bool, error) {
	log.Debug().Str("enterprise", e.enterprise).Msg("Checking enterprise EMU status via GraphQL")

	var query struct {
		Enterprise struct {
			OwnerInfo struct {
				// IdentityProvider is non-nil for any enterprise-level IdP (SAML or OIDC); the GraphQL field name "samlIdentityProvider" is a historical misnomer.
				IdentityProvider *struct {
					ID githubv4.ID
				} `graphql:"samlIdentityProvider"`
			}
		} `graphql:"enterprise(slug: $slug)"`
	}

	variables := map[string]interface{}{
		"slug": githubv4.String(e.enterprise),
	}

	if err := e.graphqlClient.Query(ctx, &query, variables); err != nil {
		log.Debug().Err(err).Str("enterprise", e.enterprise).
			Msg("Failed to query enterprise EMU status (may require admin:enterprise scope)")
		return false, nil
	}

	emuEnabled := query.Enterprise.OwnerInfo.IdentityProvider != nil
	if emuEnabled {
		log.Info().Str("enterprise", e.enterprise).Msg("Enterprise Managed Users (EMU) detected")
	}
	return emuEnabled, nil
}

// getOrganizations retrieves all organizations in the enterprise via GraphQL, paginating
// through all pages so enterprises with >100 orgs are fully discovered.
func (e *EnterpriseScanner) getOrganizations(ctx context.Context) ([]*github.Organization, error) {
	log.Debug().Str("enterprise", e.enterprise).Msg("Fetching enterprise organizations via GraphQL")

	var query struct {
		Enterprise struct {
			Slug          githubv4.String
			Organizations struct {
				Nodes []struct {
					Login       githubv4.String
					Name        githubv4.String
					Description githubv4.String
					URL         githubv4.String
					CreatedAt   githubv4.DateTime
				}
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage githubv4.Boolean
				}
			} `graphql:"organizations(first: $first, after: $after)"`
		} `graphql:"enterprise(slug: $slug)"`
	}

	var (
		orgs   []*github.Organization
		cursor *githubv4.String
	)
	for {
		variables := map[string]interface{}{
			"slug":  githubv4.String(e.enterprise),
			"first": githubv4.Int(100),
			"after": cursor,
		}

		if err := e.graphqlClient.Query(ctx, &query, variables); err != nil {
			return nil, fmt.Errorf("failed to query enterprise organizations: %w", err)
		}

		for _, node := range query.Enterprise.Organizations.Nodes {
			login := string(node.Login)
			name := string(node.Name)
			description := string(node.Description)
			url := string(node.URL)
			orgs = append(orgs, &github.Organization{
				Login:       &login,
				Name:        &name,
				Description: &description,
				URL:         &url,
			})
		}

		if !bool(query.Enterprise.Organizations.PageInfo.HasNextPage) {
			break
		}
		cursor = &query.Enterprise.Organizations.PageInfo.EndCursor
	}

	log.Info().Int("count", len(orgs)).Msg("Successfully fetched enterprise organizations")
	return orgs, nil
}

// suspiciousActions are audit log action strings that warrant a security flag.
var suspiciousActions = map[string]bool{
	"repo.destroy":                 true,
	"org.remove_member":            true,
	"oauth_access.revoke":          true,
	"org.delete":                   true,
	"business.remove_organization": true,
	"org.transfer":                 true,
}

// rawAuditEntry is a local type for deserializing enterprise audit log entries.
// The GitHub API can return "org" as either a string or an array of strings depending
// on the event type. go-github's AuditEntry.Org is *string and fails on the array case,
// so we decode into this flexible struct instead.
type rawAuditEntry struct {
	Action    string          `json:"action"`
	Actor     string          `json:"actor"`
	Org       json.RawMessage `json:"org"`
	User      string          `json:"user"`
	CreatedAt int64           `json:"created_at"`
}

// orgFromRaw extracts the first org name from a JSON value that may be a string or array.
func orgFromRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fall back to array — take first element.
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}
	return ""
}

// getAuditLog fetches recent enterprise audit log events and extracts suspicious ones.
func (e *EnterpriseScanner) getAuditLog(ctx context.Context) (*EnterpriseAuditLogData, error) {
	if e.restClient == nil {
		return nil, fmt.Errorf("REST client required for enterprise audit log")
	}

	u := fmt.Sprintf("enterprises/%s/audit-log?include=all&order=desc&per_page=100", e.enterprise)
	req, err := e.restClient.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build audit log request: %w", err)
	}

	var raw []json.RawMessage
	if _, err := e.restClient.Do(ctx, req, &raw); err != nil {
		return nil, fmt.Errorf("failed to get enterprise audit log: %w", err)
	}

	data := &EnterpriseAuditLogData{TotalEventsScanned: len(raw)}
	for _, entryBytes := range raw {
		var entry rawAuditEntry
		if err := json.Unmarshal(entryBytes, &entry); err != nil {
			log.Debug().Err(err).Msg("Skipping unparsable audit log entry")
			continue
		}
		if suspiciousActions[entry.Action] {
			data.SuspiciousEvents = append(data.SuspiciousEvents, &SuspiciousAuditEvent{
				Action: entry.Action,
				Actor:  entry.Actor,
				Org:    orgFromRaw(entry.Org),
				User:   entry.User,
			})
		}
	}
	return data, nil
}

// getSecurityAlerts fetches enterprise-wide open security alert counts.
func (e *EnterpriseScanner) getSecurityAlerts(ctx context.Context) (*EnterpriseSecurityAlerts, error) {
	if e.restClient == nil {
		return nil, fmt.Errorf("REST client required for enterprise security alerts")
	}

	result := &EnterpriseSecurityAlerts{}

	type dependabotAlert struct {
		SecurityAdvisory struct {
			Severity string `json:"severity"`
		} `json:"security_advisory"`
	}
	var depAlerts []dependabotAlert
	depReq, err := e.restClient.NewRequest("GET",
		fmt.Sprintf("enterprises/%s/dependabot/alerts?state=open&per_page=100", e.enterprise), nil)
	if err == nil {
		depResp, depErr := e.restClient.Do(ctx, depReq, &depAlerts)
		if depErr == nil {
			result.Available = true
			result.OpenDependabotAlerts = len(depAlerts)
			for _, a := range depAlerts {
				switch strings.ToLower(a.SecurityAdvisory.Severity) {
				case "critical":
					result.CriticalDependabot++
				case "high":
					result.HighDependabot++
				}
			}
		} else if depResp != nil {
			log.Debug().Int("status", depResp.StatusCode).Str("enterprise", e.enterprise).
				Msg("Enterprise dependabot alerts not accessible")
		}
	}

	type codeAlert struct{}
	var csAlerts []codeAlert
	csReq, _ := e.restClient.NewRequest("GET",
		fmt.Sprintf("enterprises/%s/code-scanning/alerts?state=open&per_page=100", e.enterprise), nil)
	if csReq != nil {
		csResp, csErr := e.restClient.Do(ctx, csReq, &csAlerts)
		if csErr == nil {
			result.Available = true
			result.OpenCodeScanningAlerts = len(csAlerts)
		} else if csResp != nil {
			log.Debug().Int("status", csResp.StatusCode).Str("enterprise", e.enterprise).
				Msg("Enterprise code scanning alerts not accessible")
		}
	}

	type secretAlert struct{}
	var ssAlerts []secretAlert
	ssReq, _ := e.restClient.NewRequest("GET",
		fmt.Sprintf("enterprises/%s/secret-scanning/alerts?state=open&per_page=100", e.enterprise), nil)
	if ssReq != nil {
		ssResp, ssErr := e.restClient.Do(ctx, ssReq, &ssAlerts)
		if ssErr == nil {
			result.Available = true
			result.OpenSecretScanningAlerts = len(ssAlerts)
		} else if ssResp != nil {
			log.Debug().Int("status", ssResp.StatusCode).Str("enterprise", e.enterprise).
				Msg("Enterprise secret scanning alerts not accessible")
		}
	}

	return result, nil
}

// getGHASSettings fetches enterprise-wide GitHub Advanced Security defaults via REST.
// GET /enterprises/{enterprise}/code_security/settings returns the enterprise-level
// GHAS policy defaults that cascade to all organizations.
// Returns nil (no error) when the endpoint is inaccessible (token lacks enterprise admin scope).
func (e *EnterpriseScanner) getGHASSettings(ctx context.Context) (*EnterpriseGHASSettings, error) {
	if e.restClient == nil {
		return nil, nil
	}
	u := fmt.Sprintf("enterprises/%s/code_security/settings", e.enterprise)
	req, err := e.restClient.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build GHAS settings request: %w", err)
	}
	var settings EnterpriseGHASSettings
	resp, err := e.restClient.Do(ctx, req, &settings)
	if err != nil {
		if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 403) {
			log.Debug().Str("enterprise", e.enterprise).Msg("Enterprise GHAS settings not accessible (insufficient permissions)")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get enterprise GHAS settings: %w", err)
	}
	return &settings, nil
}

// ScanAll retrieves enterprise settings, organization list, and audit log.
func (e *EnterpriseScanner) ScanAll(ctx context.Context) (*EnterpriseData, error) {
	log.Info().Str("enterprise", e.enterprise).Msg("Starting enterprise scan")

	if e.graphqlClient == nil {
		return nil, fmt.Errorf("GraphQL client required for enterprise scanning")
	}

	data := &EnterpriseData{}

	settings, err := e.getSettings(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get enterprise settings")
		return nil, err
	}
	data.Settings = settings

	emuEnabled, err := e.getEMUStatus(ctx)
	if err != nil {
		log.Warn().Err(err).Str("enterprise", e.enterprise).Msg("Failed to check EMU status")
	} else if data.Settings != nil {
		data.Settings.EMUEnabled = emuEnabled
	}

	orgs, err := e.getOrganizations(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get enterprise organizations")
		return nil, err
	}
	data.Organizations = orgs

	auditLog, err := e.getAuditLog(ctx)
	if err != nil {
		log.Warn().Err(err).Str("enterprise", e.enterprise).Msg("Failed to fetch enterprise audit log")
	} else {
		data.AuditLog = auditLog
	}

	secAlerts, err := e.getSecurityAlerts(ctx)
	if err != nil {
		log.Warn().Err(err).Str("enterprise", e.enterprise).Msg("Failed to fetch enterprise security alerts")
	} else {
		data.SecurityAlerts = secAlerts
	}

	ghasSettings, err := e.getGHASSettings(ctx)
	if err != nil {
		log.Warn().Err(err).Str("enterprise", e.enterprise).Msg("Failed to fetch enterprise GHAS settings")
	} else {
		data.GHASSettings = ghasSettings
	}

	log.Info().
		Str("enterprise", e.enterprise).
		Int("organizations", len(data.Organizations)).
		Msg("Enterprise scan completed")

	return data, nil
}
