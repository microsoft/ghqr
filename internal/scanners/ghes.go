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
// Returns settings with Source=SettingsSourceManageAPI when readable, or
// Source=SettingsSourceUnavailable with all boolean fields nil when the
// management API is inaccessible. Callers MUST NOT treat nil booleans as
// "disabled"; the bestpractices.KnownDisabled / KnownEnabled helpers encode
// the right semantics.
func (s *GHESScanner) getSettings(ctx context.Context) (*GHESSettings, error) {
	log.Debug().Str("hostname", s.hostname).Msg("Fetching GHES settings")

	req, err := s.client.NewRequest("GET", "manage/v1/config/settings", nil)
	if err != nil {
		return &GHESSettings{Source: SettingsSourceUnavailable}, nil
	}

	var rawSettings map[string]interface{}
	resp, doErr := s.client.Do(ctx, req, &rawSettings)
	if doErr != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		log.Debug().
			Int("status", status).
			Err(doErr).
			Str("hostname", s.hostname).
			Msg("Management config API not accessible; settings will be reported as unknown")
		return &GHESSettings{Source: SettingsSourceUnavailable}, nil
	}

	settings := &GHESSettings{Source: SettingsSourceManageAPI}
	parseRawSettings(rawSettings, settings)
	return settings, nil
}

// probeFeatures detects which GHES feature APIs are reachable on this
// instance. The result describes endpoint availability only — never feature
// enablement — and is exposed via GHESData.FeatureSupport so evaluators can
// gate findings that only make sense when the relevant API exists.
//
// Probe semantics:
//   - 2xx / 204 -> endpoint available -> available = true
//   - 404       -> endpoint not present on this appliance -> available = false
//   - any other status (401, 403, 5xx, 429) -> support unknown -> available = false
//     (we deliberately under-report rather than assume).
func (s *GHESScanner) probeFeatures(ctx context.Context) *GHESFeatureSupport {
	support := &GHESFeatureSupport{}
	support.ActionsAPIAvailable = s.probeEndpoint(ctx, "enterprises/actions/permissions")
	support.DependabotAPIAvailable = s.probeEndpoint(ctx, "enterprises/dependabot/alerts?per_page=1")
	support.CodeScanningAPIAvailable = s.probeEndpoint(ctx, "enterprises/code-scanning/alerts?per_page=1")
	support.SecretScanningAPIAvailable = s.probeEndpoint(ctx, "enterprises/secret-scanning/alerts?per_page=1")
	return support
}

// probeEndpoint issues a single GET against the given REST path and returns
// true only when the appliance responds with a 2xx/204. Any non-success
// status — including 401/403 — yields false: we have not confirmed support,
// so we must not claim it.
func (s *GHESScanner) probeEndpoint(ctx context.Context, path string) bool {
	req, err := s.client.NewRequest("GET", path, nil)
	if err != nil {
		return false
	}
	resp, _ := s.client.Do(ctx, req, nil)
	if resp == nil {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// parseRawSettings extracts known fields from the management config API
// response. Boolean fields use pointer helpers so absent keys remain nil
// ("unknown") rather than collapsing to false ("known disabled").
func parseRawSettings(raw map[string]interface{}, settings *GHESSettings) {
	settings.PrivateMode = boolPtr(raw, "private_mode")
	settings.SubdomainIsolation = boolPtr(raw, "subdomain_isolation")
	settings.TLSEnforced = boolPtr(raw, "tls_enforced")
	settings.SignupEnabled = boolPtr(raw, "signup_enabled")
	settings.MaintenanceMode = boolPtr(raw, "maintenance_mode")
	settings.CollectStatsEnabled = boolPtr(raw, "collect_stats")
	settings.PagesEnabled = boolPtr(raw, "pages_enabled")
	settings.PagesPublicPagesEnabled = boolPtr(raw, "pages_public_pages_enabled")
	settings.GHASEnabled = boolPtr(raw, "advanced_security_enabled")
	settings.SecretScanningEnabled = boolPtr(raw, "secret_scanning_enabled")
	settings.SecretScanningPushProtection = boolPtr(raw, "secret_scanning_push_protection")
	settings.DependabotAlertsEnabled = boolPtr(raw, "dependabot_alerts_enabled")
	settings.DependabotUpdatesEnabled = boolPtr(raw, "dependabot_updates_enabled")
	settings.CodeScanningEnabled = boolPtr(raw, "code_scanning_enabled")
	settings.ActionsEnabled = boolPtr(raw, "actions_enabled")
	settings.PackagesEnabled = boolPtr(raw, "packages_enabled")
	settings.AdminSSHEnabled = boolPtr(raw, "admin_ssh_enabled")
	settings.BuiltinAuthFallback = boolPtr(raw, "builtin_auth_fallback")

	if storage := stringPtr(raw, "actions_storage_type"); storage != nil {
		settings.ActionsStorageType = storage
	}

	authMode := stringPtr(raw, "auth_mode")
	settings.AuthMode = authMode
	if authMode != nil {
		samlBool := strings.EqualFold(*authMode, "saml")
		ldapBool := strings.EqualFold(*authMode, "ldap")
		casBool := strings.EqualFold(*authMode, "cas")
		settings.SAMLEnabled = &samlBool
		settings.LDAPEnabled = &ldapBool
		settings.CASEnabled = &casBool
	}
}

// boolPtr returns a pointer to the bool stored under key in raw, or nil if
// the key is absent or holds a non-bool value.
func boolPtr(raw map[string]interface{}, key string) *bool {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

// stringPtr returns a pointer to the string stored under key in raw, or nil
// if the key is absent or holds a non-string value.
func stringPtr(raw map[string]interface{}, key string) *string {
	v, ok := raw[key]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
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
				switch strings.ToUpper(a.SecurityAdvisory.Severity) {
				case "CRITICAL":
					result.CriticalDependabot++
				case "HIGH":
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

	// 3. Settings (best-effort; missing fields are reported as unknown, not disabled).
	settings, err := s.getSettings(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch GHES settings")
	} else {
		data.Settings = settings
	}

	// 3b. Probe which feature APIs the appliance exposes. This is endpoint
	//     availability — not enablement — and is used to gate downstream
	//     findings that only make sense when the API exists.
	data.FeatureSupport = s.probeFeatures(ctx)

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
