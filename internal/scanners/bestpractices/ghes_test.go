// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"testing"

	"github.com/microsoft/ghqr/internal/recommendations"
	"github.com/microsoft/ghqr/internal/scanners"
)

// boolPtr returns a pointer to b. Local helper to keep test cases concise.
func boolPtr(b bool) *bool { return &b }

// strPtr returns a pointer to s. Local helper to keep test cases concise.
func strPtr(s string) *string { return &s }

// loadedEvaluator returns an Evaluator backed by the real embedded rule
// registry. Tests use this so they assert on rule IDs rather than copy that
// is now owned by the YAML files.
func loadedEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load: %v", err)
	}
	return NewEvaluator(reg)
}

// hasFinding returns true when result contains a finding with the given
// rule ID. Test assertions key on rule IDs so changing the rule copy in
// YAML does not break tests.
func hasFinding(result *EvaluationResult, ruleID string) bool {
	if result == nil {
		return false
	}
	for _, r := range result.Recommendations {
		if r.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingSeverity(result *EvaluationResult, ruleID string) string {
	if result == nil {
		return ""
	}
	for _, r := range result.Recommendations {
		if r.RuleID == ruleID {
			return r.Severity
		}
	}
	return ""
}

func TestParseGHESVersion(t *testing.T) {
	cases := []struct {
		in    string
		major int
		minor int
		ok    bool
	}{
		{"3.20.1", 3, 20, true},
		{"3.21.0", 3, 21, true},
		{"3.21.0.rc1", 3, 21, true},
		{"3.20", 3, 20, true},
		{"4.0.0", 4, 0, true},
		{"", 0, 0, false},
		{"latest", 0, 0, false},
		{"3", 0, 0, false},
		{"3.x.y", 0, 0, false},
	}
	for _, c := range cases {
		maj, min, ok := parseGHESVersion(c.in)
		if ok != c.ok || maj != c.major || min != c.minor {
			t.Errorf("parseGHESVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				c.in, maj, min, ok, c.major, c.minor, c.ok)
		}
	}
}

func TestIsSupportedGHESVersion(t *testing.T) {
	cases := []struct {
		major, minor int
		want         bool
	}{
		{3, 19, true},
		{3, 20, true},
		{3, 21, true},
		{3, 18, false},
		{3, 0, false},
		{4, 0, true},
		{4, 5, true},
		{2, 99, false},
	}
	for _, c := range cases {
		got := isSupportedGHESVersion(c.major, c.minor)
		if got != c.want {
			t.Errorf("isSupportedGHESVersion(%d, %d) = %v, want %v",
				c.major, c.minor, got, c.want)
		}
	}
}

// TestEvaluateGHESSettings_UnavailableNoFalsePositives is the regression
// test for the false-positive class raised in PR #84 review. When the
// management API is unavailable, every boolean setting is nil and AuthMode
// is nil; the evaluator must NOT emit Critical/High findings asserting
// that those settings are disabled. It should emit exactly one Info
// finding (ghes-infra-002) explaining that settings-based checks were
// skipped.
func TestEvaluateGHESSettings_UnavailableNoFalsePositives(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{Source: scanners.SettingsSourceUnavailable}

	result := e.EvaluateGHESSettings(nil, settings, nil)
	if result == nil {
		t.Fatal("EvaluateGHESSettings returned nil")
	}
	for _, r := range result.Recommendations {
		if r.Severity == SeverityCritical || r.Severity == SeverityHigh || r.Severity == SeverityMedium {
			t.Errorf("unexpected %s finding when management API is unavailable: rule=%s issue=%q",
				r.Severity, r.RuleID, r.Issue)
		}
	}
	if len(result.Recommendations) != 1 {
		t.Errorf("expected exactly 1 finding (settings unavailable), got %d", len(result.Recommendations))
	}
	if !hasFinding(result, "ghes-infra-002") {
		t.Error("expected ghes-infra-002 (settings unavailable) finding to be emitted")
	}
}

// TestEvaluateGHESSettings_KnownDisabledStillFires verifies the inverse:
// when settings ARE observed and explicitly disabled, the evaluator must
// still surface the corresponding Critical/High findings via their YAML
// rule IDs. Catches the case where someone over-corrects the tri-state
// fix and silences real problems.
func TestEvaluateGHESSettings_KnownDisabledStillFires(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:                       scanners.SettingsSourceManageAPI,
		AuthMode:                     strPtr("built-in"),
		PrivateMode:                  boolPtr(false),
		SubdomainIsolation:           boolPtr(false),
		GHASEnabled:                  boolPtr(false),
		SecretScanningEnabled:        boolPtr(false),
		SecretScanningPushProtection: boolPtr(false),
		CodeScanningEnabled:          boolPtr(false),
		DependabotAlertsEnabled:      boolPtr(false),
		ActionsEnabled:               boolPtr(true),
		SignupEnabled:                boolPtr(false),
	}
	// Feature APIs available so the "disabled" rules fire (rather than
	// the "could not be confirmed" rules).
	support := &scanners.GHESFeatureSupport{
		ActionsAPIAvailable:        true,
		DependabotAPIAvailable:     true,
		CodeScanningAPIAvailable:   true,
		SecretScanningAPIAvailable: true,
	}

	result := e.EvaluateGHESSettings(nil, settings, support)
	if result == nil {
		t.Fatal("nil result")
	}

	wantRules := map[string]string{
		"ghes-auth-002": SeverityCritical, // built-in auth
		"ghes-net-001":  SeverityCritical, // subdomain isolation
		"ghes-net-002":  SeverityCritical, // private mode
		"ghes-sec-001":  SeverityHigh,     // GHAS off
		"ghes-sec-002":  SeverityHigh,     // secret scanning off
		"ghes-sec-004":  SeverityHigh,     // push protection off
		"ghes-sec-005":  SeverityHigh,     // code scanning off
		"ghes-sec-011":  SeverityHigh,     // dependabot off
	}
	for ruleID, sev := range wantRules {
		got := findingSeverity(result, ruleID)
		if got == "" {
			t.Errorf("expected rule %s to fire on known-disabled settings", ruleID)
			continue
		}
		if got != sev {
			t.Errorf("rule %s severity = %q, want %q", ruleID, got, sev)
		}
	}
}

// TestEvaluateGHESSettings_KnownEnabledStaysQuiet ensures that observed-
// as-enabled security settings do NOT trigger the "disabled" rule IDs.
// Only Info-level rules (the "Actions is enabled" status, the auth-mode
// info) may fire.
func TestEvaluateGHESSettings_KnownEnabledStaysQuiet(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:                       scanners.SettingsSourceManageAPI,
		AuthMode:                     strPtr("saml"),
		PrivateMode:                  boolPtr(true),
		SubdomainIsolation:           boolPtr(true),
		GHASEnabled:                  boolPtr(true),
		SecretScanningEnabled:        boolPtr(true),
		SecretScanningPushProtection: boolPtr(true),
		CodeScanningEnabled:          boolPtr(true),
		DependabotAlertsEnabled:      boolPtr(true),
		DependabotUpdatesEnabled:     boolPtr(true),
		ActionsEnabled:               boolPtr(true),
		SignupEnabled:                boolPtr(false),
		MaintenanceMode:              boolPtr(false),
		AdminSSHEnabled:              boolPtr(false),
	}

	result := e.EvaluateGHESSettings(nil, settings, nil)
	for _, r := range result.Recommendations {
		if r.Severity != SeverityInfo {
			t.Errorf("unexpected %s finding on a fully-hardened instance: rule=%s issue=%q",
				r.Severity, r.RuleID, r.Issue)
		}
	}

	// None of the "disabled" rule IDs should be present.
	forbidden := []string{
		"ghes-auth-002", "ghes-net-001", "ghes-net-002",
		"ghes-sec-001", "ghes-sec-002", "ghes-sec-004",
		"ghes-sec-005", "ghes-sec-011", "ghes-sec-013",
	}
	for _, ruleID := range forbidden {
		if hasFinding(result, ruleID) {
			t.Errorf("rule %s should NOT fire on a fully-hardened instance", ruleID)
		}
	}
}

// TestEvaluateGHESSettings_FeatureUnsupportedDowngrades verifies that
// when the management API observes a feature as disabled BUT the
// corresponding API endpoint is not reachable on this GHES instance,
// the evaluator emits the paired "could not be confirmed" Info rule
// instead of the High "feature is disabled" rule. This is the wiring
// Copilot's follow-up review asked for: distinguishing "supported but
// turned off" from "API did not respond — reason unclear".
func TestEvaluateGHESSettings_FeatureUnsupportedDowngrades(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:                  scanners.SettingsSourceManageAPI,
		AuthMode:                strPtr("saml"),
		SecretScanningEnabled:   boolPtr(false),
		CodeScanningEnabled:     boolPtr(false),
		DependabotAlertsEnabled: boolPtr(false),
		ActionsEnabled:          boolPtr(false),
	}
	support := &scanners.GHESFeatureSupport{
		ActionsAPIAvailable:        false,
		DependabotAPIAvailable:     false,
		CodeScanningAPIAvailable:   false,
		SecretScanningAPIAvailable: false,
	}

	result := e.EvaluateGHESSettings(nil, settings, support)
	if result == nil {
		t.Fatal("nil result")
	}
	for _, r := range result.Recommendations {
		if r.Severity == SeverityCritical || r.Severity == SeverityHigh || r.Severity == SeverityMedium {
			t.Errorf("unexpected %s finding when feature APIs are unavailable: rule=%s issue=%q",
				r.Severity, r.RuleID, r.Issue)
		}
	}

	// Each disabled-but-unconfirmed feature should fire its paired Info rule.
	wantInfo := []string{"ghes-sec-003", "ghes-sec-006", "ghes-sec-012", "ghes-actions-003"}
	for _, ruleID := range wantInfo {
		got := findingSeverity(result, ruleID)
		if got != SeverityInfo {
			t.Errorf("expected Info rule %s to fire when API is unavailable, got severity=%q", ruleID, got)
		}
	}

	// The "disabled" rule IDs must NOT fire.
	forbidden := []string{"ghes-sec-002", "ghes-sec-005", "ghes-sec-011", "ghes-actions-001"}
	for _, ruleID := range forbidden {
		if hasFinding(result, ruleID) {
			t.Errorf("rule %s should NOT fire when API endpoint is unavailable", ruleID)
		}
	}
}

// TestEvaluateGHESSettings_FeatureAvailableKeepsHigh ensures the downgrade
// only fires when the API is unavailable — if the endpoint is reachable,
// disabled settings still produce High findings.
func TestEvaluateGHESSettings_FeatureAvailableKeepsHigh(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:                scanners.SettingsSourceManageAPI,
		AuthMode:              strPtr("saml"),
		SecretScanningEnabled: boolPtr(false),
	}
	support := &scanners.GHESFeatureSupport{SecretScanningAPIAvailable: true}

	result := e.EvaluateGHESSettings(nil, settings, support)
	if findingSeverity(result, "ghes-sec-002") != SeverityHigh {
		t.Error("ghes-sec-002 (secret scanning disabled) should fire at High when API is observed-available")
	}
	if hasFinding(result, "ghes-sec-003") {
		t.Error("ghes-sec-003 (secret scanning unconfirmed) must NOT fire when API is observed-available")
	}
}

// TestEvaluateGHESSettings_WithServerInfo verifies that passing a non-nil
// serverInfo with a SAML auth mode (not built-in) does not affect settings
// evaluation output — no High/Critical findings on a fully-hardened instance.
func TestEvaluateGHESSettings_WithServerInfo(t *testing.T) {
	e := loadedEvaluator(t)
	serverInfo := &scanners.GHESServerInfo{InstalledVersion: "3.20.1"}
	settings := &scanners.GHESSettings{
		Source:                       scanners.SettingsSourceManageAPI,
		AuthMode:                     strPtr("saml"),
		PrivateMode:                  boolPtr(true),
		SubdomainIsolation:           boolPtr(true),
		GHASEnabled:                  boolPtr(true),
		SecretScanningEnabled:        boolPtr(true),
		SecretScanningPushProtection: boolPtr(true),
		CodeScanningEnabled:          boolPtr(true),
		DependabotAlertsEnabled:      boolPtr(true),
		ActionsEnabled:               boolPtr(true),
	}
	support := &scanners.GHESFeatureSupport{
		ActionsAPIAvailable:        true,
		DependabotAPIAvailable:     true,
		CodeScanningAPIAvailable:   true,
		SecretScanningAPIAvailable: true,
	}

	result := e.EvaluateGHESSettings(serverInfo, settings, support)
	if result == nil {
		t.Fatal("nil result")
	}
	for _, r := range result.Recommendations {
		if r.Severity == SeverityCritical || r.Severity == SeverityHigh {
			t.Errorf("unexpected %s finding with serverInfo present: rule=%s", r.Severity, r.RuleID)
		}
	}
}

// TestEvaluateGHESSettings_BuiltInAuth_VersionGated verifies that
// ghes-auth-002 (built-in auth) is only emitted for GHES versions strictly
// before 3.26 — the release where LDAP and CAS are deprecated.
func TestEvaluateGHESSettings_BuiltInAuth_VersionGated(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:   scanners.SettingsSourceManageAPI,
		AuthMode: strPtr("built-in"),
	}
	cases := []struct {
		version string
		want    bool
		desc    string
	}{
		{"3.25.0", true, "3.25 is below the deprecation threshold"},
		{"3.25.9", true, "3.25.9 is still below 3.26"},
		{"3.26.0", false, "3.26 is the deprecation boundary — finding must not fire"},
		{"3.27.0", false, "3.27 is past the deprecation boundary"},
		{"4.0.0", false, "major version 4 is past 3.26"},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			serverInfo := &scanners.GHESServerInfo{InstalledVersion: c.version}
			result := e.EvaluateGHESSettings(serverInfo, settings, nil)
			got := hasFinding(result, "ghes-auth-002")
			if got != c.want {
				t.Errorf("ghes-auth-002 fired=%v, want=%v", got, c.want)
			}
		})
	}
}

// TestEvaluateGHESSettings_BuiltInAuth_NilServerInfoConservative verifies
// that when serverInfo is nil or the version string is unparseable, the
// evaluator conservatively still emits ghes-auth-002 rather than silently
// suppressing it.
func TestEvaluateGHESSettings_BuiltInAuth_NilServerInfoConservative(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:   scanners.SettingsSourceManageAPI,
		AuthMode: strPtr("built-in"),
	}
	cases := []struct {
		name       string
		serverInfo *scanners.GHESServerInfo
	}{
		{"nil serverInfo", nil},
		{"empty version", &scanners.GHESServerInfo{InstalledVersion: ""}},
		{"unparseable version", &scanners.GHESServerInfo{InstalledVersion: "latest"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := e.EvaluateGHESSettings(c.serverInfo, settings, nil)
			if !hasFinding(result, "ghes-auth-002") {
				t.Error("ghes-auth-002 should fire when version is unknown (conservative approach)")
			}
		})
	}
}

// TestEvaluateGHESSecurityAlerts_UnavailableAPIs surfaces Info findings
// for each missing security-alert endpoint via the YAML rule IDs.
func TestEvaluateGHESSecurityAlerts_UnavailableAPIs(t *testing.T) {
	e := loadedEvaluator(t)
	support := &scanners.GHESFeatureSupport{
		DependabotAPIAvailable:     false,
		CodeScanningAPIAvailable:   false,
		SecretScanningAPIAvailable: false,
	}
	result := e.EvaluateGHESSecurityAlerts(nil, support)
	if result == nil {
		t.Fatal("nil result")
	}

	wantRules := []string{"ghes-sec-014", "ghes-sec-015", "ghes-sec-016"}
	for _, ruleID := range wantRules {
		if findingSeverity(result, ruleID) != SeverityInfo {
			t.Errorf("expected Info rule %s to fire for unavailable alerts API", ruleID)
		}
	}
}

// TestEvaluateGHESSettings_PagesWithoutSubdomainIsolation locks in the
// Pages-on-appliance-origin XSS finding. The combination must fire
// Critical even when each setting on its own would only emit a lower-
// severity finding (or no finding at all, in the case of private Pages).
func TestEvaluateGHESSettings_PagesWithoutSubdomainIsolation(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:                  scanners.SettingsSourceManageAPI,
		AuthMode:                strPtr("saml"),
		SubdomainIsolation:      boolPtr(false),
		PagesEnabled:            boolPtr(true),
		PagesPublicPagesEnabled: boolPtr(false), // private Pages still vulnerable
	}
	result := e.EvaluateGHESSettings(nil, settings, nil)
	if findingSeverity(result, "ghes-net-004") != SeverityCritical {
		t.Error("ghes-net-004 should fire Critical when Pages is enabled and subdomain isolation is off")
	}
}

// TestEvaluateGHESSettings_PagesWithSubdomainIsolation verifies the
// combined rule does NOT fire when the prerequisite (subdomain
// isolation) is in place — that's the supported configuration.
func TestEvaluateGHESSettings_PagesWithSubdomainIsolation(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:             scanners.SettingsSourceManageAPI,
		AuthMode:           strPtr("saml"),
		SubdomainIsolation: boolPtr(true),
		PagesEnabled:       boolPtr(true),
	}
	result := e.EvaluateGHESSettings(nil, settings, nil)
	if hasFinding(result, "ghes-net-004") {
		t.Error("ghes-net-004 must NOT fire when subdomain isolation is enabled")
	}
}

// TestEvaluateGHESSettings_PagesUnknownSubdomainStaysQuiet ensures the
// combined rule respects the unavailable-management-API contract: when
// SubdomainIsolation is nil we cannot claim the unsafe combination.
func TestEvaluateGHESSettings_PagesUnknownSubdomainStaysQuiet(t *testing.T) {
	e := loadedEvaluator(t)
	settings := &scanners.GHESSettings{
		Source:       scanners.SettingsSourceManageAPI,
		AuthMode:     strPtr("saml"),
		PagesEnabled: boolPtr(true),
		// SubdomainIsolation deliberately nil.
	}
	result := e.EvaluateGHESSettings(nil, settings, nil)
	if hasFinding(result, "ghes-net-004") {
		t.Error("ghes-net-004 must not fire when SubdomainIsolation is unknown")
	}
}

// TestGHESRuleRegistryCoverage ensures every rule ID referenced from the
// evaluator exists in the embedded YAML registry. This is a guard so a
// future refactor cannot silently emit findings whose copy / severity is
// missing.
func TestGHESRuleRegistryCoverage(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load: %v", err)
	}

	// Every rule the evaluator might emit. Keep in sync with bestpractices/ghes.go.
	required := []string{
		"ghes-server-001", "ghes-server-002", "ghes-server-003",
		"ghes-server-004", "ghes-server-005", "ghes-server-006",
		"ghes-license-001", "ghes-license-002", "ghes-license-003",
		"ghes-license-004", "ghes-license-005",
		"ghes-auth-001", "ghes-auth-002", "ghes-auth-003",
		"ghes-auth-004", "ghes-auth-005",
		"ghes-net-001", "ghes-net-002", "ghes-net-003", "ghes-net-004",
		"ghes-sec-001", "ghes-sec-002", "ghes-sec-003",
		"ghes-sec-004", "ghes-sec-005", "ghes-sec-006",
		"ghes-sec-007", "ghes-sec-008", "ghes-sec-009",
		"ghes-sec-010", "ghes-sec-011", "ghes-sec-012",
		"ghes-sec-013", "ghes-sec-014", "ghes-sec-015",
		"ghes-sec-016",
		"ghes-actions-001", "ghes-actions-002", "ghes-actions-003",
		"ghes-infra-001", "ghes-infra-002", "ghes-infra-003",
		"ghes-infra-004", "ghes-infra-005",
		"ghes-stats-001", "ghes-stats-002", "ghes-stats-003",
		"ghes-stats-004", "ghes-stats-005",
		"ghes-audit-001", "ghes-audit-002",
	}
	for _, ruleID := range required {
		def, ok := reg.Get(ruleID)
		if !ok {
			t.Errorf("rule %s referenced from evaluator is missing from the YAML registry", ruleID)
			continue
		}
		if def.Scope != recommendations.ScopeGHES {
			t.Errorf("rule %s should have scope=ghes, got %q", ruleID, def.Scope)
		}
	}
}
