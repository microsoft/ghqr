// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bestpractices

import (
	"fmt"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/scanners"
)

// Values of default_for_new_repos returned by
// GET /orgs/{org}/code-security/configurations/defaults.
const (
	newRepoScopeAll             = "all"
	newRepoScopePublic          = "public"
	newRepoScopePrivateInternal = "private_and_internal"
)

// Normalised feature states read from a code security configuration.
const (
	featureEnabled     = "enabled"
	featureDisabled    = "disabled"
	featureNotSet      = "not_set"
	featureConflicting = "conflicting"
	// featureNoDefault means no default configuration applies to the scope.
	featureNoDefault = "no_default"
)

// orgDefaultRule maps an org-def-* rule to its legacy organization field and
// to the matching feature of a code security configuration.
type orgDefaultRule struct {
	ruleID string
	legacy func(*scanners.OrgSecurity) bool
	state  func(*github.CodeSecurityConfiguration) string
	// scopes lists the new-repository scopes that must be covered.
	scopes []string
}

var allNewRepoScopes = []string{newRepoScopePublic, newRepoScopePrivateInternal}

var orgDefaultRules = []orgDefaultRule{
	{
		ruleID: "org-def-001",
		legacy: func(s *scanners.OrgSecurity) bool { return s.DependabotAlertsForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.DependabotAlerts) },
		scopes: allNewRepoScopes,
	},
	{
		ruleID: "org-def-002",
		legacy: func(s *scanners.OrgSecurity) bool { return s.DependabotSecurityUpdatesForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.DependabotSecurityUpdates) },
		scopes: allNewRepoScopes,
	},
	{
		ruleID: "org-def-003",
		legacy: func(s *scanners.OrgSecurity) bool { return s.DependencyGraphForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.DependencyGraph) },
		scopes: allNewRepoScopes,
	},
	{
		ruleID: "org-def-004",
		legacy: func(s *scanners.OrgSecurity) bool { return s.SecretScanningForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.SecretScanning) },
		scopes: allNewRepoScopes,
	},
	{
		ruleID: "org-def-005",
		legacy: func(s *scanners.OrgSecurity) bool { return s.SecretScanningPushProtectionForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.SecretScanningPushProtection) },
		scopes: allNewRepoScopes,
	},
	{
		ruleID: "org-def-006",
		legacy: func(s *scanners.OrgSecurity) bool { return s.AdvancedSecurityForNewRepos },
		state:  advancedSecurityState,
		scopes: allNewRepoScopes,
	},
	{
		// Private vulnerability reporting is only available for public repositories.
		ruleID: "org-def-007",
		legacy: func(s *scanners.OrgSecurity) bool { return s.PrivateVulnerabilityReportingForNewRepos },
		state:  func(c *github.CodeSecurityConfiguration) string { return featureState(c.PrivateVulnerabilityReporting) },
		scopes: []string{newRepoScopePublic},
	},
}

// EvaluateOrgSecurityDefaults checks org-wide security defaults applied to new repositories.
//
// When the organization's default code security configurations are readable they are
// authoritative, because GitHub ignores the deprecated *_enabled_for_new_repos fields.
// A rule passes only when its feature is enabled for every applicable scope (public and
// private/internal). Readable but uninterpretable or conflicting data keeps the finding.
// When the defaults were not collected (older report) or could not be read, the legacy
// fields are evaluated as before.
func (e *Evaluator) EvaluateOrgSecurityDefaults(settings *scanners.OrgSecurity) *EvaluationResult {
	if settings == nil {
		return noDataResult("No organization security settings available")
	}

	var findings []Issue
	csc := settings.CodeSecurityConfigurations

	switch {
	case csc == nil:
		for _, rule := range orgDefaultRules {
			if !rule.legacy(settings) {
				e.addFinding(&findings, rule.ruleID, "")
			}
		}
	case !csc.DefaultsReadable:
		detail := fmt.Sprintf("default code security configurations could not be read: %s; result based on the deprecated organization setting",
			unavailableReason(csc.DefaultsUnavailableReason))
		for _, rule := range orgDefaultRules {
			if !rule.legacy(settings) {
				e.addFindingWithDetail(&findings, rule.ruleID, detail)
			}
		}
	default:
		byScope, problem := defaultConfigurationsByScope(csc.DefaultConfigurations)
		if problem != "" {
			detail := "default code security configurations could not be interpreted: " + problem
			for _, rule := range orgDefaultRules {
				e.addFindingWithDetail(&findings, rule.ruleID, detail)
			}
			break
		}
		for _, rule := range orgDefaultRules {
			if detail, covered := evaluateDefaultCoverage(rule, byScope); !covered {
				e.addFindingWithDetail(&findings, rule.ruleID, detail)
			}
		}
	}

	return createResult(e, findings)
}

// defaultConfigurationsByScope groups the default configurations per new-repository
// scope. "all" applies to both public and private/internal repositories. A non-empty
// problem is returned when an entry cannot be interpreted.
func defaultConfigurationsByScope(defaults []*github.CodeSecurityConfigurationWithDefaultForNewRepos) (map[string][]*github.CodeSecurityConfiguration, string) {
	byScope := map[string][]*github.CodeSecurityConfiguration{}
	for _, d := range defaults {
		if d == nil || d.Configuration == nil {
			return nil, "a default entry has no configuration details"
		}
		switch scope := d.GetDefaultForNewRepos(); scope {
		case newRepoScopeAll:
			byScope[newRepoScopePublic] = append(byScope[newRepoScopePublic], d.Configuration)
			byScope[newRepoScopePrivateInternal] = append(byScope[newRepoScopePrivateInternal], d.Configuration)
		case newRepoScopePublic, newRepoScopePrivateInternal:
			byScope[scope] = append(byScope[scope], d.Configuration)
		default:
			return nil, fmt.Sprintf("unrecognised default_for_new_repos value %q for %s", scope, describeConfigurations([]*github.CodeSecurityConfiguration{d.Configuration}))
		}
	}
	return byScope, ""
}

// scopeGap describes why a scope is not covered by the default configuration.
type scopeGap struct {
	scope  string
	reason string
}

// evaluateDefaultCoverage reports whether the rule's feature is enabled for every
// applicable scope and, if not, a detail message naming the uncovered scopes.
func evaluateDefaultCoverage(rule orgDefaultRule, byScope map[string][]*github.CodeSecurityConfiguration) (string, bool) {
	var gaps []scopeGap
	var covered []string
	for _, scope := range rule.scopes {
		configs := byScope[scope]
		state := scopeFeatureState(configs, rule.state)
		if state == featureEnabled {
			covered = append(covered, scopeLabel(scope))
			continue
		}
		gaps = append(gaps, scopeGap{scope: scope, reason: describeGapReason(state, configs)})
	}
	if len(gaps) == 0 {
		return "", true
	}

	var parts []string
	if len(gaps) == len(allNewRepoScopes) && gaps[0].reason == gaps[1].reason {
		parts = append(parts, "all new repositories - "+gaps[0].reason)
	} else {
		for _, g := range gaps {
			parts = append(parts, scopeLabel(g.scope)+" new repositories - "+g.reason)
		}
	}
	detail := "not covered by the default code security configuration for " + strings.Join(parts, "; ")
	if len(covered) > 0 {
		detail += "; covered for " + strings.Join(covered, " and ") + " new repositories"
	}
	return detail, false
}

// scopeFeatureState returns the feature state for a scope. Several configurations
// that disagree yield featureConflicting rather than silently picking one.
func scopeFeatureState(configs []*github.CodeSecurityConfiguration, state func(*github.CodeSecurityConfiguration) string) string {
	if len(configs) == 0 {
		return featureNoDefault
	}
	first := state(configs[0])
	for _, c := range configs[1:] {
		if state(c) != first {
			return featureConflicting
		}
	}
	return first
}

func describeGapReason(state string, configs []*github.CodeSecurityConfiguration) string {
	names := describeConfigurations(configs)
	switch state {
	case featureNoDefault:
		return "no default configuration"
	case featureDisabled:
		return "disabled in " + names
	case featureNotSet:
		return "not set in " + names
	case featureConflicting:
		if len(configs) == 1 {
			return "conflicting values in " + names
		}
		return "conflicting values across " + names
	default:
		if strings.Contains(state, " ") {
			return state + " in " + names
		}
		return fmt.Sprintf("set to %q in %s", state, names)
	}
}

// describeConfigurations renders configuration names with their target type
// (when not organization-owned) and enforcement (when enforced).
func describeConfigurations(configs []*github.CodeSecurityConfiguration) string {
	names := make([]string, 0, len(configs))
	for _, c := range configs {
		name := c.Name
		if name == "" {
			name = "unnamed configuration"
		}
		var qualifiers []string
		if t := c.GetTargetType(); t != "" && t != "organization" {
			qualifiers = append(qualifiers, t)
		}
		switch strings.ToLower(c.GetEnforcement()) {
		case "enforced":
			qualifiers = append(qualifiers, "enforced")
		case "enterprise_enforced":
			qualifiers = append(qualifiers, "enforced by the enterprise")
		}
		desc := "'" + name + "'"
		if len(qualifiers) > 0 {
			desc += " (" + strings.Join(qualifiers, ", ") + ")"
		}
		names = append(names, desc)
	}
	return strings.Join(names, ", ")
}

func scopeLabel(scope string) string {
	if scope == newRepoScopePrivateInternal {
		return "private and internal"
	}
	return scope
}

func unavailableReason(reason string) string {
	if reason == "" {
		return "unknown reason"
	}
	return reason
}

// featureState normalises an enablement value; a missing value means "not_set".
func featureState(v *string) string {
	if v == nil {
		return featureNotSet
	}
	s := strings.ToLower(strings.TrimSpace(*v))
	if s == "" {
		return featureNotSet
	}
	return s
}

// advancedSecurityState evaluates GitHub Advanced Security as its two products,
// Code Security and Secret Protection, which must both be enabled. The deprecated
// advanced_security field ("enabled", "disabled", "code_security", "secret_protection")
// is used when the per-product field is not set.
func advancedSecurityState(c *github.CodeSecurityConfiguration) string {
	aggregate := featureState(c.AdvancedSecurity)
	codeSecurity := ghasProductState(featureState(c.CodeSecurity), aggregate, "code_security")
	secretProtection := ghasProductState(featureState(c.SecretProtection), aggregate, "secret_protection")

	switch {
	case codeSecurity == featureEnabled && secretProtection == featureEnabled:
		return featureEnabled
	case codeSecurity == featureConflicting || secretProtection == featureConflicting:
		return featureConflicting
	case codeSecurity == secretProtection:
		return codeSecurity
	default:
		return fmt.Sprintf("Code Security %s, Secret Protection %s", stateLabel(codeSecurity), stateLabel(secretProtection))
	}
}

// ghasProductState combines an explicit per-product value with the value implied by
// the deprecated advanced_security field. An explicit "disabled" contradicting an
// aggregate that enables the product is reported as conflicting.
func ghasProductState(explicit, aggregate, productValue string) string {
	implied := featureNotSet
	switch aggregate {
	case featureEnabled, productValue:
		implied = featureEnabled
	case featureDisabled, "code_security", "secret_protection":
		implied = featureDisabled
	case featureNotSet:
	default:
		implied = aggregate
	}

	switch {
	case explicit == featureNotSet:
		return implied
	case explicit == featureDisabled && implied == featureEnabled:
		return featureConflicting
	default:
		return explicit
	}
}

func stateLabel(state string) string {
	return strings.ReplaceAll(state, "_", " ")
}
