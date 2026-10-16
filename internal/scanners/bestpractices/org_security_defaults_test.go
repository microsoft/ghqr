// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
)

var allOrgDefRules = []string{
	"org-def-001", "org-def-002", "org-def-003", "org-def-004",
	"org-def-005", "org-def-006", "org-def-007",
}

// enabledConfig returns a configuration with every org-def-* feature enabled.
func enabledConfig(name string) *github.CodeSecurityConfiguration {
	return &github.CodeSecurityConfiguration{
		Name:                          name,
		TargetType:                    github.Ptr("global"),
		AdvancedSecurity:              github.Ptr("enabled"),
		DependabotAlerts:              github.Ptr("enabled"),
		DependabotSecurityUpdates:     github.Ptr("enabled"),
		DependencyGraph:               github.Ptr("enabled"),
		SecretScanning:                github.Ptr("enabled"),
		SecretScanningPushProtection:  github.Ptr("enabled"),
		PrivateVulnerabilityReporting: github.Ptr("enabled"),
		Enforcement:                   github.Ptr("unenforced"),
	}
}

func withConfig(name string, mutate func(*github.CodeSecurityConfiguration)) *github.CodeSecurityConfiguration {
	c := enabledConfig(name)
	mutate(c)
	return c
}

func defaultFor(scope string, cfg *github.CodeSecurityConfiguration) *github.CodeSecurityConfigurationWithDefaultForNewRepos {
	return &github.CodeSecurityConfigurationWithDefaultForNewRepos{DefaultForNewRepos: github.Ptr(scope), Configuration: cfg}
}

func readableDefaults(defaults ...*github.CodeSecurityConfigurationWithDefaultForNewRepos) *scanners.OrgCodeSecurityConfigurations {
	if defaults == nil {
		defaults = []*github.CodeSecurityConfigurationWithDefaultForNewRepos{}
	}
	return &scanners.OrgCodeSecurityConfigurations{DefaultsReadable: true, DefaultConfigurations: defaults}
}

func legacyAll(enabled bool) scanners.OrgSecurity {
	return scanners.OrgSecurity{
		AdvancedSecurityForNewRepos:              enabled,
		DependabotAlertsForNewRepos:              enabled,
		DependabotSecurityUpdatesForNewRepos:     enabled,
		DependencyGraphForNewRepos:               enabled,
		SecretScanningForNewRepos:                enabled,
		SecretScanningPushProtectionForNewRepos:  enabled,
		PrivateVulnerabilityReportingForNewRepos: enabled,
	}
}

func TestEvaluateOrgSecurityDefaults_NilSettings(t *testing.T) {
	result := newEvaluator(t).EvaluateOrgSecurityDefaults(nil)
	if result == nil || result.Message == "" || len(result.Recommendations) != 0 {
		t.Fatalf("expected no-data result, got %+v", result)
	}
}

func TestEvaluateOrgSecurityDefaults(t *testing.T) {
	eval := newEvaluator(t)

	tests := []struct {
		name   string
		legacy bool
		csc    *scanners.OrgCodeSecurityConfigurations
		// wantRules lists the org-def-* rules expected to be raised.
		wantRules []string
		// wantContains maps a rule to substrings expected in its issue text.
		wantContains map[string][]string
		// wantExactTitle asserts raised findings use the unmodified registry title.
		wantExactTitle bool
	}{
		{
			name:           "older report without section, legacy disabled",
			wantRules:      allOrgDefRules,
			wantExactTitle: true,
		},
		{
			name:   "older report without section, legacy enabled",
			legacy: true,
		},
		{
			name:      "defaults forbidden, legacy disabled",
			csc:       &scanners.OrgCodeSecurityConfigurations{DefaultsUnavailableReason: scanners.CodeSecurityConfigUnavailableForbidden},
			wantRules: allOrgDefRules,
			wantContains: map[string][]string{
				"org-def-004": {"could not be read: forbidden", "deprecated organization setting"},
			},
		},
		{
			name:   "defaults not found, legacy enabled",
			legacy: true,
			csc:    &scanners.OrgCodeSecurityConfigurations{DefaultsUnavailableReason: scanners.CodeSecurityConfigUnavailableNotFound},
		},
		{
			name:         "defaults error, legacy disabled",
			csc:          &scanners.OrgCodeSecurityConfigurations{DefaultsUnavailableReason: scanners.CodeSecurityConfigUnavailableError},
			wantRules:    allOrgDefRules,
			wantContains: map[string][]string{"org-def-001": {"could not be read: error"}},
		},
		{
			name:         "defaults unreadable without reason",
			csc:          &scanners.OrgCodeSecurityConfigurations{},
			wantRules:    allOrgDefRules,
			wantContains: map[string][]string{"org-def-001": {"could not be read: unknown reason"}},
		},
		{
			name:      "readable, no default configured, legacy enabled is ignored",
			legacy:    true,
			csc:       readableDefaults(),
			wantRules: allOrgDefRules,
			wantContains: map[string][]string{
				"org-def-001": {"all new repositories - no default configuration"},
				"org-def-007": {"public new repositories - no default configuration"},
			},
		},
		{
			name: "fully covered via all scope, legacy disabled",
			csc:  readableDefaults(defaultFor("all", enabledConfig("GitHub recommended"))),
		},
		{
			name: "fully covered via both scopes",
			csc: readableDefaults(
				defaultFor("public", enabledConfig("Public baseline")),
				defaultFor("private_and_internal", enabledConfig("Private baseline")),
			),
		},
		{
			name:      "public only",
			csc:       readableDefaults(defaultFor("public", enabledConfig("GitHub recommended"))),
			wantRules: []string{"org-def-001", "org-def-002", "org-def-003", "org-def-004", "org-def-005", "org-def-006"},
			wantContains: map[string][]string{
				"org-def-004": {"private and internal new repositories - no default configuration", "covered for public new repositories"},
			},
		},
		{
			name:      "private and internal only",
			csc:       readableDefaults(defaultFor("private_and_internal", enabledConfig("Private baseline"))),
			wantRules: allOrgDefRules,
			wantContains: map[string][]string{
				"org-def-001": {"public new repositories - no default configuration", "covered for private and internal new repositories"},
				"org-def-007": {"public new repositories - no default configuration"},
			},
		},
		{
			name: "features disabled or not set in default configuration",
			csc: readableDefaults(defaultFor("all", withConfig("Custom", func(c *github.CodeSecurityConfiguration) {
				c.SecretScanning = github.Ptr("disabled")
				c.DependabotSecurityUpdates = github.Ptr("not_set")
				c.DependencyGraph = nil
				c.TargetType = github.Ptr("organization")
			}))),
			wantRules: []string{"org-def-002", "org-def-003", "org-def-004"},
			wantContains: map[string][]string{
				"org-def-002": {"all new repositories - not set in 'Custom'"},
				"org-def-003": {"all new repositories - not set in 'Custom'"},
				"org-def-004": {"all new repositories - disabled in 'Custom'"},
			},
		},
		{
			name: "different gaps per scope",
			csc: readableDefaults(
				defaultFor("public", withConfig("Public", func(c *github.CodeSecurityConfiguration) { c.SecretScanning = github.Ptr("disabled") })),
				defaultFor("private_and_internal", withConfig("Private", func(c *github.CodeSecurityConfiguration) { c.SecretScanning = github.Ptr("not_set") })),
			),
			wantRules: []string{"org-def-004"},
			wantContains: map[string][]string{
				"org-def-004": {"public new repositories - disabled in 'Public' (global)", "private and internal new repositories - not set in 'Private' (global)"},
			},
		},
		{
			name: "conflicting defaults for the same scope",
			csc: readableDefaults(
				defaultFor("all", enabledConfig("Org baseline")),
				defaultFor("public", withConfig("Public override", func(c *github.CodeSecurityConfiguration) { c.SecretScanning = github.Ptr("disabled") })),
			),
			wantRules: []string{"org-def-004"},
			wantContains: map[string][]string{
				"org-def-004": {"public new repositories - conflicting values across 'Org baseline' (global), 'Public override' (global)", "covered for private and internal new repositories"},
			},
		},
		{
			name:   "legacy enabled but default configuration disables feature",
			legacy: true,
			csc: readableDefaults(defaultFor("all", withConfig("Custom", func(c *github.CodeSecurityConfiguration) {
				c.SecretScanningPushProtection = github.Ptr("disabled")
			}))),
			wantRules:    []string{"org-def-005"},
			wantContains: map[string][]string{"org-def-005": {"disabled in 'Custom'"}},
		},
		{
			name:   "unrecognised scope fails closed even with legacy enabled",
			legacy: true,
			csc: readableDefaults(
				defaultFor("all", enabledConfig("GitHub recommended")),
				defaultFor("private", enabledConfig("Other")),
			),
			wantRules:    allOrgDefRules,
			wantContains: map[string][]string{"org-def-001": {"could not be interpreted", `"private"`}},
		},
		{
			name:         "default entry without configuration fails closed",
			legacy:       true,
			csc:          readableDefaults(&github.CodeSecurityConfigurationWithDefaultForNewRepos{DefaultForNewRepos: github.Ptr("all")}),
			wantRules:    allOrgDefRules,
			wantContains: map[string][]string{"org-def-006": {"could not be interpreted", "no configuration details"}},
		},
		{
			name: "enforcement and target type in wording",
			csc: readableDefaults(defaultFor("all", withConfig("Enterprise baseline", func(c *github.CodeSecurityConfiguration) {
				c.TargetType = github.Ptr("enterprise")
				c.Enforcement = github.Ptr("enforced")
				c.DependabotAlerts = github.Ptr("disabled")
			}))),
			wantRules:    []string{"org-def-001"},
			wantContains: map[string][]string{"org-def-001": {"'Enterprise baseline' (enterprise, enforced)"}},
		},
		{
			name:         "nil default entry fails closed",
			legacy:       true,
			csc:          readableDefaults((*github.CodeSecurityConfigurationWithDefaultForNewRepos)(nil)),
			wantRules:    allOrgDefRules,
			wantContains: map[string][]string{"org-def-001": {"could not be interpreted", "no configuration details"}},
		},
		{
			name: "enterprise-enforced configuration in wording",
			csc: readableDefaults(defaultFor("all", withConfig("Enterprise baseline", func(c *github.CodeSecurityConfiguration) {
				c.TargetType = github.Ptr("enterprise")
				c.Enforcement = github.Ptr("enterprise_enforced")
				c.SecretScanning = github.Ptr("disabled")
			}))),
			wantRules:    []string{"org-def-004"},
			wantContains: map[string][]string{"org-def-004": {"'Enterprise baseline' (enterprise, enforced by the enterprise)"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := legacyAll(tt.legacy)
			settings.CodeSecurityConfigurations = tt.csc

			result := eval.EvaluateOrgSecurityDefaults(&settings)
			assertRuleIDs(t, result.Recommendations, tt.wantRules)
			if result.Summary.TotalIssues != len(tt.wantRules) {
				t.Errorf("TotalIssues = %d, want %d", result.Summary.TotalIssues, len(tt.wantRules))
			}

			for ruleID, substrings := range tt.wantContains {
				issue := findRuleID(result, ruleID)
				if issue == nil {
					t.Fatalf("expected %s finding", ruleID)
				}
				for _, s := range substrings {
					if !strings.Contains(issue.Issue, s) {
						t.Errorf("%s issue = %q, want substring %q", ruleID, issue.Issue, s)
					}
				}
			}
			if tt.wantExactTitle {
				for _, issue := range result.Recommendations {
					if strings.Contains(issue.Issue, "(") {
						t.Errorf("%s issue = %q, want unmodified registry title", issue.RuleID, issue.Issue)
					}
				}
			}

			// --from-json replay deserialises the same JSON; results must be identical.
			replayed := eval.EvaluateOrgSecurityDefaults(jsonRoundTrip(t, &settings))
			if !reflect.DeepEqual(replayed.Recommendations, result.Recommendations) {
				t.Errorf("replay result differs from live result:\nlive:   %+v\nreplay: %+v", result.Recommendations, replayed.Recommendations)
			}
		})
	}
}

func TestEvaluateOrgSecurityDefaults_AdvancedSecurityProducts(t *testing.T) {
	eval := newEvaluator(t)

	tests := []struct {
		name             string
		advancedSecurity *string
		codeSecurity     *string
		secretProtection *string
		// wantDetail is empty when org-def-006 must not be raised.
		wantDetail string
	}{
		{name: "aggregate enabled", advancedSecurity: github.Ptr("enabled")},
		{name: "both products enabled", advancedSecurity: github.Ptr("disabled"), codeSecurity: github.Ptr("enabled"), secretProtection: github.Ptr("enabled")},
		{name: "aggregate code_security plus secret protection enabled", advancedSecurity: github.Ptr("code_security"), secretProtection: github.Ptr("enabled")},
		{
			name:             "aggregate code_security only",
			advancedSecurity: github.Ptr("code_security"),
			wantDetail:       "Code Security enabled, Secret Protection disabled in 'Custom'",
		},
		{
			name:             "secret protection only",
			secretProtection: github.Ptr("enabled"),
			wantDetail:       "Code Security not set, Secret Protection enabled in 'Custom'",
		},
		{
			name:             "explicit product disabled contradicts aggregate",
			advancedSecurity: github.Ptr("enabled"),
			secretProtection: github.Ptr("disabled"),
			wantDetail:       "conflicting values in 'Custom'",
		},
		{name: "everything not set", wantDetail: "not set in 'Custom'"},
		{name: "aggregate disabled", advancedSecurity: github.Ptr("disabled"), wantDetail: "disabled in 'Custom'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := withConfig("Custom", func(c *github.CodeSecurityConfiguration) {
				c.TargetType = nil
				c.AdvancedSecurity = tt.advancedSecurity
				c.CodeSecurity = tt.codeSecurity
				c.SecretProtection = tt.secretProtection
			})
			settings := &scanners.OrgSecurity{CodeSecurityConfigurations: readableDefaults(defaultFor("all", cfg))}

			issue := findRuleID(eval.EvaluateOrgSecurityDefaults(settings), "org-def-006")
			if tt.wantDetail == "" {
				if issue != nil {
					t.Fatalf("unexpected org-def-006 finding: %q", issue.Issue)
				}
				return
			}
			if issue == nil {
				t.Fatal("expected org-def-006 finding")
			}
			if !strings.Contains(issue.Issue, tt.wantDetail) {
				t.Errorf("org-def-006 issue = %q, want substring %q", issue.Issue, tt.wantDetail)
			}
		})
	}
}

func assertRuleIDs(t *testing.T, issues []bestpractices.Issue, want []string) {
	t.Helper()
	got := make([]string, 0, len(issues))
	for _, i := range issues {
		got = append(got, i.RuleID)
	}
	wantSorted := append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(wantSorted)
	if len(got) == 0 && len(wantSorted) == 0 {
		return
	}
	if !reflect.DeepEqual(got, wantSorted) {
		t.Errorf("rules = %v, want %v", got, wantSorted)
	}
}

func jsonRoundTrip(t *testing.T, in *scanners.OrgSecurity) *scanners.OrgSecurity {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out scanners.OrgSecurity
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &out
}
