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
)

// GHESScanner handles scanning a GitHub Enterprise Server instance via the REST API.
type GHESScanner struct {
	client   *github.Client
	hostname string
}

// NewGHESScanner creates a new GHES scanner.
func NewGHESScanner(client *github.Client, hostname string) *GHESScanner {
	return &GHESScanner{
		client:   client,
		hostname: hostname,
	}
}

// getServerInfo retrieves server metadata from GET /meta.
func (s *GHESScanner) getServerInfo(ctx context.Context) (*GHESServerInfo, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES server info via /meta")

	req, err := s.client.NewRequest("GET", "meta", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build /meta request: %w", err)
	}

	var meta struct {
		InstalledVersion                 string            `json:"installed_version"`
		VerifiablePasswordAuthentication bool              `json:"verifiable_password_authentication"`
		SSHKeyFingerprints               map[string]string `json:"ssh_key_fingerprints"`
	}
	if _, err := s.client.Do(ctx, req, &meta); err != nil {
		return nil, fmt.Errorf("failed to get GHES server info: %w", err)
	}

	info := &GHESServerInfo{
		InstalledVersion:                 meta.InstalledVersion,
		VerifiablePasswordAuthentication: meta.VerifiablePasswordAuthentication,
		SSHKeyFingerprints:               meta.SSHKeyFingerprints,
		Hostname:                         s.hostname,
	}

	return info, nil
}

// getLicense retrieves enterprise license information from GET /enterprise/settings/license.
func (s *GHESScanner) getLicense(ctx context.Context) (*GHESLicense, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES license info")

	req, err := s.client.NewRequest("GET", "enterprise/settings/license", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build license request: %w", err)
	}

	var license GHESLicense
	resp, err := s.client.Do(ctx, req, &license)
	if err != nil {
		if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 403) {
			log.Debug().Str("hostname", s.hostname).Msg("GHES license endpoint not accessible (requires site admin)")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get GHES license: %w", err)
	}

	return &license, nil
}

// getSettings retrieves GHES site admin settings from GET /manage/v1/config/settings.
// Falls back to extracting what we can from other endpoints if management console is inaccessible.
func (s *GHESScanner) getSettings(ctx context.Context, serverInfo *GHESServerInfo) (*GHESSettings, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES settings")

	settings := &GHESSettings{}

	// Try to get settings from the management config API.
	req, err := s.client.NewRequest("GET", "manage/v1/config/settings", nil)
	if err == nil {
		var rawSettings map[string]interface{}
		resp, doErr := s.client.Do(ctx, req, &rawSettings)
		if doErr == nil {
			s.parseRawSettings(rawSettings, settings)
			return settings, nil
		}
		if resp != nil {
			log.Debug().
				Int("status", resp.StatusCode).
				Str("hostname", s.hostname).
				Msg("Management config API not accessible, inferring settings from available data")
		}
	}

	// Infer settings from server info and feature probing.
	s.probeFeatures(ctx, settings, serverInfo)

	return settings, nil
}

// probeFeatures detects GHES feature availability by probing specific API endpoints.
func (s *GHESScanner) probeFeatures(ctx context.Context, settings *GHESSettings, serverInfo *GHESServerInfo) {
	// Probe GitHub Actions
	actionsReq, err := s.client.NewRequest("GET", "enterprises/actions/permissions", nil)
	if err == nil {
		resp, _ := s.client.Do(ctx, actionsReq, nil)
		if resp != nil {
			settings.ActionsEnabled = resp.StatusCode != 404
		}
	}

	// Probe GHAS / Secret scanning / Code scanning via supported features
	if serverInfo != nil && serverInfo.InstalledVersion != "" {
		// GHES 3.0+ supports GHAS features
		settings.GHASEnabled = true
	}

	// Probe Dependabot
	depReq, err := s.client.NewRequest("GET", "enterprises/dependabot/alerts?per_page=1", nil)
	if err == nil {
		resp, _ := s.client.Do(ctx, depReq, nil)
		if resp != nil {
			settings.DependabotAlertsEnabled = resp.StatusCode != 404
		}
	}
}

// parseRawSettings extracts known fields from the management config API response.
func (s *GHESScanner) parseRawSettings(raw map[string]interface{}, settings *GHESSettings) {
	getBool := func(key string) bool {
		if v, ok := raw[key]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return false
	}
	getString := func(key string) string {
		if v, ok := raw[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	settings.PrivateMode = getBool("private_mode")
	settings.SubdomainIsolation = getBool("subdomain_isolation")
	settings.SignupEnabled = getBool("signup_enabled")
	settings.MaintenanceMode = getBool("maintenance_mode")
	settings.CollectStatsEnabled = getBool("collect_stats")
	settings.PagesEnabled = getBool("pages_enabled")
	settings.GHASEnabled = getBool("advanced_security_enabled")
	settings.ActionsEnabled = getBool("actions_enabled")
	settings.PackagesEnabled = getBool("packages_enabled")

	authMode := getString("auth_mode")
	if authMode != "" {
		settings.AuthMode = authMode
		settings.LDAPEnabled = strings.EqualFold(authMode, "ldap")
		settings.SAMLEnabled = strings.EqualFold(authMode, "saml")
		settings.CASEnabled = strings.EqualFold(authMode, "cas")
	}
}

// getAdminStats retrieves aggregate statistics from GET /enterprise/stats/all.
func (s *GHESScanner) getAdminStats(ctx context.Context) (*GHESAdminStats, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES admin stats")

	req, err := s.client.NewRequest("GET", "enterprise/stats/all", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build admin stats request: %w", err)
	}

	var stats GHESAdminStats
	resp, err := s.client.Do(ctx, req, &stats)
	if err != nil {
		if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 403) {
			log.Debug().Str("hostname", s.hostname).Msg("GHES admin stats endpoint not accessible")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get GHES admin stats: %w", err)
	}

	return &stats, nil
}

// ghesSuspiciousActions are audit log actions that warrant a security flag on GHES.
var ghesSuspiciousActions = map[string]bool{
	"repo.destroy":                 true,
	"org.remove_member":            true,
	"oauth_access.revoke":          true,
	"org.delete":                   true,
	"staff.fake_login":             true,
	"staff.unlock":                 true,
	"staff.set_site_admin":         true,
	"user.suspend":                 true,
	"user.unsuspend":               true,
	"business.remove_organization": true,
	"org.transfer":                 true,
}

// getAuditLog fetches recent site admin audit log events.
func (s *GHESScanner) getAuditLog(ctx context.Context) (*GHESAuditLogData, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES audit log")

	req, err := s.client.NewRequest("GET", "enterprises/audit-log?include=all&order=desc&per_page=100", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build audit log request: %w", err)
	}

	var raw []json.RawMessage
	resp, err := s.client.Do(ctx, req, &raw)
	if err != nil {
		if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 403) {
			log.Debug().Str("hostname", s.hostname).Msg("GHES audit log endpoint not accessible")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get GHES audit log: %w", err)
	}

	data := &GHESAuditLogData{TotalEventsScanned: len(raw)}
	for _, entryBytes := range raw {
		var entry rawAuditEntry
		if err := json.Unmarshal(entryBytes, &entry); err != nil {
			log.Debug().Err(err).Msg("Skipping unparseable GHES audit log entry")
			continue
		}
		if ghesSuspiciousActions[entry.Action] {
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

// getOrganizations lists all organizations on the GHES instance.
func (s *GHESScanner) getOrganizations(ctx context.Context) ([]string, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES organizations")

	var allOrgs []string
	opts := &github.OrganizationsListOptions{PerPage: 100}
	for {
		orgs, _, err := s.client.Organizations.ListAll(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list GHES organizations: %w", err)
		}
		if len(orgs) == 0 {
			break
		}
		for _, org := range orgs {
			if org.GetLogin() != "" {
				allOrgs = append(allOrgs, org.GetLogin())
			}
		}
		// Use the ID of the last org as the "since" cursor for next page.
		opts.Since = orgs[len(orgs)-1].GetID()
	}

	return allOrgs, nil
}

// getSecurityAlerts fetches aggregate security alerts across the GHES instance.
func (s *GHESScanner) getSecurityAlerts(ctx context.Context) (*GHESSecurityAlerts, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES security alerts")

	result := &GHESSecurityAlerts{}

	// Dependabot alerts
	type dependabotAlert struct {
		SecurityAdvisory struct {
			Severity string `json:"severity"`
		} `json:"security_advisory"`
	}
	var depAlerts []dependabotAlert
	depReq, err := s.client.NewRequest("GET", "enterprises/dependabot/alerts?state=open&per_page=100", nil)
	if err == nil {
		depResp, depErr := s.client.Do(ctx, depReq, &depAlerts)
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
			log.Debug().Int("status", depResp.StatusCode).Msg("GHES dependabot alerts not accessible")
		}
	}

	// Code scanning alerts
	type codeAlert struct{}
	var csAlerts []codeAlert
	csReq, _ := s.client.NewRequest("GET", "enterprises/code-scanning/alerts?state=open&per_page=100", nil)
	if csReq != nil {
		csResp, csErr := s.client.Do(ctx, csReq, &csAlerts)
		if csErr == nil {
			result.Available = true
			result.OpenCodeScanningAlerts = len(csAlerts)
		} else if csResp != nil {
			log.Debug().Int("status", csResp.StatusCode).Msg("GHES code scanning alerts not accessible")
		}
	}

	// Secret scanning alerts
	type secretAlert struct{}
	var ssAlerts []secretAlert
	ssReq, _ := s.client.NewRequest("GET", "enterprises/secret-scanning/alerts?state=open&per_page=100", nil)
	if ssReq != nil {
		ssResp, ssErr := s.client.Do(ctx, ssReq, &ssAlerts)
		if ssErr == nil {
			result.Available = true
			result.OpenSecretScanningAlerts = len(ssAlerts)
		} else if ssResp != nil {
			log.Debug().Int("status", ssResp.StatusCode).Msg("GHES secret scanning alerts not accessible")
		}
	}

	return result, nil
}

// ScanAll performs a comprehensive scan of the GHES instance.
func (s *GHESScanner) ScanAll(ctx context.Context) (*GHESData, error) {
	log.Info().Str("hostname", s.hostname).Msg("Starting GHES instance scan")

	data := &GHESData{}

	// 1. Server info (required — validates connectivity)
	serverInfo, err := s.getServerInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get GHES server info (check URL and token): %w", err)
	}
	data.ServerInfo = serverInfo
	log.Info().
		Str("hostname", s.hostname).
		Str("version", serverInfo.InstalledVersion).
		Msg("Connected to GHES instance")

	// 2. License info
	license, err := s.getLicense(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES license")
	} else {
		data.License = license
	}

	// 3. Settings
	settings, err := s.getSettings(ctx, serverInfo)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES settings")
	} else {
		data.Settings = settings
	}

	// 4. Admin stats
	stats, err := s.getAdminStats(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES admin stats")
	} else {
		data.AdminStats = stats
	}

	// 5. Security alerts
	secAlerts, err := s.getSecurityAlerts(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES security alerts")
	} else {
		data.SecurityAlerts = secAlerts
	}

	// 6. Audit log
	auditLog, err := s.getAuditLog(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES audit log")
	} else {
		data.AuditLog = auditLog
	}

	// 7. Organizations
	orgs, err := s.getOrganizations(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list GHES organizations")
	} else {
		data.Organizations = orgs
	}

	log.Info().
		Str("hostname", s.hostname).
		Str("version", serverInfo.InstalledVersion).
		Int("organizations", len(data.Organizations)).
		Msg("GHES instance scan completed")

	return data, nil
}
