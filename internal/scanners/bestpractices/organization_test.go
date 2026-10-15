// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices_test

import (
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/recommendations"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
)

func newEvaluator(t *testing.T) *bestpractices.Evaluator {
	t.Helper()
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}
	return bestpractices.NewEvaluator(reg)
}

func findRuleID(result *bestpractices.EvaluationResult, ruleID string) *bestpractices.Issue {
	for i := range result.Recommendations {
		if result.Recommendations[i].RuleID == ruleID {
			return &result.Recommendations[i]
		}
	}
	return nil
}

func TestEvaluateOrganizationSecurity_NilSettings(t *testing.T) {
	eval := newEvaluator(t)
	result := eval.EvaluateOrganizationSecurity(nil)
	if result == nil {
		t.Fatal("expected non-nil result for nil settings")
	}
	if result.Message == "" {
		t.Error("expected message for nil settings")
	}
}

func TestEvaluateOrganizationSecurity_2FA_NotRequired_NoEMU(t *testing.T) {
	eval := newEvaluator(t)
	settings := &scanners.OrgSettings{
		Security: scanners.OrgSecurity{
			TwoFactorRequirementEnabled: false,
			EMUEnabled:                  false,
		},
	}

	result := eval.EvaluateOrganizationSecurity(settings)

	issue := findRuleID(result, "org-sec-001")
	if issue == nil {
		t.Fatal("expected org-sec-001 finding when 2FA is not required and EMU is disabled")
	}
	if issue.Severity != "high" {
		t.Errorf("org-sec-001 severity = %s, want high", issue.Severity)
	}

	emuIssue := findRuleID(result, "org-sec-006")
	if emuIssue != nil {
		t.Error("unexpected org-sec-006 finding when EMU is disabled")
	}
}

func TestEvaluateOrganizationSecurity_2FA_NotRequired_EMU(t *testing.T) {
	eval := newEvaluator(t)
	settings := &scanners.OrgSettings{
		Security: scanners.OrgSecurity{
			TwoFactorRequirementEnabled: false,
			EMUEnabled:                  true,
		},
	}

	result := eval.EvaluateOrganizationSecurity(settings)

	emuIssue := findRuleID(result, "org-sec-006")
	if emuIssue == nil {
		t.Fatal("expected org-sec-006 finding when EMU is enabled")
	}
	if emuIssue.Severity != "info" {
		t.Errorf("org-sec-006 severity = %s, want info", emuIssue.Severity)
	}

	issue := findRuleID(result, "org-sec-001")
	if issue != nil {
		t.Error("unexpected org-sec-001 finding when EMU is enabled")
	}
}

func TestEvaluateOrganizationSecurity_2FA_Required(t *testing.T) {
	eval := newEvaluator(t)
	settings := &scanners.OrgSettings{
		Security: scanners.OrgSecurity{
			TwoFactorRequirementEnabled: true,
			WebCommitSignoffRequired:    true,
		},
	}

	result := eval.EvaluateOrganizationSecurity(settings)

	if findRuleID(result, "org-sec-001") != nil {
		t.Error("unexpected org-sec-001 finding when 2FA is required")
	}
	if findRuleID(result, "org-sec-006") != nil {
		t.Error("unexpected org-sec-006 finding when 2FA is required")
	}
}

// Code security configurations are collected for reporting only; they must not
// change org-def-* scoring, which still reflects the legacy organization fields.
func TestEvaluateOrgSecurityDefaults_IgnoresCodeSecurityConfigurations(t *testing.T) {
	eval := newEvaluator(t)

	tests := []struct {
		name string
		csc  *scanners.OrgCodeSecurityConfigurations
	}{
		{name: "not collected", csc: nil},
		{name: "default configuration for all new repos", csc: &scanners.OrgCodeSecurityConfigurations{
			DefaultsReadable: true,
			DefaultConfigurations: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{{
				DefaultForNewRepos: github.Ptr("all"),
				Configuration:      &github.CodeSecurityConfiguration{Name: "GitHub recommended"},
			}},
		}},
		{name: "not readable", csc: &scanners.OrgCodeSecurityConfigurations{
			DefaultsUnavailableReason: scanners.CodeSecurityConfigUnavailableForbidden,
		}},
	}

	baseline := eval.EvaluateOrgSecurityDefaults(&scanners.OrgSecurity{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eval.EvaluateOrgSecurityDefaults(&scanners.OrgSecurity{CodeSecurityConfigurations: tt.csc})
			if got.Summary.TotalIssues != baseline.Summary.TotalIssues {
				t.Fatalf("TotalIssues = %d, want %d", got.Summary.TotalIssues, baseline.Summary.TotalIssues)
			}
			for i := range baseline.Recommendations {
				if got.Recommendations[i].RuleID != baseline.Recommendations[i].RuleID {
					t.Errorf("rule[%d] = %s, want %s", i, got.Recommendations[i].RuleID, baseline.Recommendations[i].RuleID)
				}
			}
		})
	}
}
