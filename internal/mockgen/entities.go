// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mockgen

import (
	"fmt"
	"math/rand"
	"time"
)

// chance returns true with probability p (clamped to [0,1]).
func chance(r *rand.Rand, p float64) bool {
	switch {
	case p <= 0:
		return false
	case p >= 1:
		return true
	}
	return r.Float64() < p
}

// pickString returns one of the provided options uniformly at random.
func pickString(r *rand.Rand, options ...string) string {
	if len(options) == 0 {
		return ""
	}
	return options[r.Intn(len(options))]
}

// buildEnterprise produces the raw fact map for one enterprise. It contains
// only fields the loader/evaluator consume; no `*_evaluation` blocks are added.
func buildEnterprise(r *rand.Rand, slug string, orgLogins []string, w profileWeights, now time.Time) map[string]interface{} {
	emuEnabled := chance(r, 0.2)

	orgs := make([]map[string]interface{}, 0, len(orgLogins))
	for _, login := range orgLogins {
		orgs = append(orgs, map[string]interface{}{
			"login":       login,
			"name":        login,
			"description": "",
			"url":         fmt.Sprintf("https://github.com/%s", login),
		})
	}

	return map[string]interface{}{
		"settings": map[string]interface{}{
			"id":          fmt.Sprintf("E_kgDO%08d", r.Intn(99_999_999)),
			"name":        slug,
			"slug":        slug,
			"url":         fmt.Sprintf("https://github.com/enterprises/%s", slug),
			"created_at":  now.AddDate(-2, 0, 0).Format("2006-01-02 15:04:05 +0000 UTC"),
			"emu_enabled": emuEnabled,
		},
		"organizations": orgs,
		"audit_log": map[string]interface{}{
			"total_events_scanned": 50 + r.Intn(500),
		},
		"security_alerts": map[string]interface{}{
			"available":                   true,
			"open_dependabot_alerts":      r.Intn(w.maxOpenAlerts + 1),
			"critical_dependabot":         r.Intn(3),
			"high_dependabot":             r.Intn(5),
			"open_code_scanning_alerts":   r.Intn(w.maxOpenAlerts + 1),
			"open_secret_scanning_alerts": r.Intn(w.maxOpenAlerts/2 + 1),
		},
	}
}

// buildOrganization produces the raw fact map for one organization.
func buildOrganization(r *rand.Rand, login, enterprise string, w profileWeights, emuEnabled bool) map[string]interface{} {
	twoFactor := chance(r, w.twoFactorRequired)
	// EMU orgs always report 2FA managed by the IdP — so we leave the flag false
	// but rely on the evaluator's EMU branch for the right rule. The fact stays raw.
	settings := map[string]interface{}{
		"visibility": map[string]interface{}{
			"default_repository_permission":          pickStringWeighted(r, w.restrictiveDefaultPerm, "read", "write"),
			"members_can_create_public_repositories": !chance(r, w.restrictPublicRepoCreate),
		},
		"security": map[string]interface{}{
			"two_factor_requirement_enabled":                        twoFactor,
			"web_commit_signoff_required":                           chance(r, w.webCommitSignoffRequired),
			"emu_enabled":                                           emuEnabled,
			"advanced_security_enabled_for_new_repos":               chance(r, w.advancedSecurityNewRepos),
			"dependabot_alerts_enabled_for_new_repos":               chance(r, w.dependabotAlertsNewRepos),
			"dependabot_security_updates_enabled_for_new_repos":     chance(r, w.dependabotAlertsNewRepos),
			"dependency_graph_enabled_for_new_repos":                chance(r, w.dependabotAlertsNewRepos),
			"secret_scanning_enabled_for_new_repos":                 chance(r, w.secretScanningNewRepos),
			"secret_scanning_push_protection_enabled_for_new_repos": chance(r, w.pushProtectionNewRepos),
		},
	}

	totalSeats := 1 + r.Intn(20)
	active := r.Intn(totalSeats + 1)
	copilot := map[string]interface{}{
		"billing_enabled":         true,
		"seat_management_setting": pickStringWeighted(r, w.copilotAssignSelected, "assign_selected", "assign_all"),
		"public_code_suggestions": pickStringWeighted(r, w.copilotPublicSuggBlocked, "block", "allow"),
		"total_seats":             totalSeats,
		"active_this_cycle":       active,
		"inactive_this_cycle":     totalSeats - active,
	}

	actions := map[string]interface{}{
		"allowed_actions":                  pickStringWeighted(r, w.actionsLocalOnly, "local_only", "all"),
		"default_workflow_permissions":     pickStringWeighted(r, 0.7, "read", "write"),
		"can_approve_pull_request_reviews": chance(r, 0.2),
	}

	securityAlerts := map[string]interface{}{
		"available":                   true,
		"open_dependabot_alerts":      r.Intn(w.maxOpenAlerts + 1),
		"critical_dependabot":         r.Intn(3),
		"high_dependabot":             r.Intn(5),
		"open_code_scanning_alerts":   r.Intn(w.maxOpenAlerts + 1),
		"open_secret_scanning_alerts": r.Intn(w.maxOpenAlerts/2 + 1),
	}

	out := map[string]interface{}{
		"settings":            settings,
		"copilot":             copilot,
		"actions_permissions": actions,
		"security_alerts":     securityAlerts,
		"security_managers": map[string]interface{}{
			"has_security_manager": chance(r, w.securityManagerAssigned),
		},
	}
	if enterprise != "" {
		out["enterprise"] = enterprise
	}
	return out
}

// buildRepository produces the raw fact map for one repository.
func buildRepository(r *rand.Rand, name, org, enterprise string, w profileWeights, now time.Time) map[string]interface{} {
	archived := chance(r, 0.05)
	dependabotEnabled := chance(r, w.dependabotAlertsEnabled)
	openAlerts := 0
	bySeverity := map[string]interface{}{}
	if dependabotEnabled {
		openAlerts = r.Intn(w.maxOpenAlerts + 1)
		if openAlerts > 0 {
			bySeverity = map[string]interface{}{
				"critical": r.Intn(2),
				"high":     r.Intn(3),
				"medium":   r.Intn(openAlerts + 1),
				"low":      r.Intn(openAlerts + 1),
			}
		}
	}

	branchProtected := chance(r, w.branchProtected) && !archived

	branchProtection := map[string]interface{}{
		"protected":               false,
		"branch":                  "",
		"required_linear_history": false,
		"allow_force_pushes":      false,
		"allow_deletions":         false,
		"required_signatures":     false,
	}
	if branchProtected {
		branchProtection = map[string]interface{}{
			"protected":               true,
			"branch":                  "main",
			"required_linear_history": chance(r, 0.6),
			"allow_force_pushes":      false,
			"allow_deletions":         false,
			"required_signatures":     chance(r, 0.5),
			"required_pull_request_reviews": map[string]interface{}{
				"required_approving_review_count": 1 + r.Intn(2),
				"dismiss_stale_reviews":           chance(r, 0.7),
				"require_code_owner_reviews":      chance(r, 0.6),
			},
			"required_status_checks": map[string]interface{}{
				"strict":   chance(r, 0.6),
				"contexts": []string{"build", "test"},
			},
		}
	}

	metadata := map[string]interface{}{
		"default_branch": "main",
		"language":       pickString(r, "Go", "Python", "TypeScript", "Java", "C#", "Rust", "Bicep", ""),
	}
	if chance(r, w.hasTopics) {
		metadata["topics"] = []string{
			pickString(r, "platform", "infra", "frontend", "backend", "ai", "cli"),
		}
	}

	repo := map[string]interface{}{
		"name":         name,
		"organization": org,
		"pushed_at":    now.AddDate(0, 0, -r.Intn(365)).Format(time.RFC3339),
		"access": map[string]interface{}{
			"visibility":             pickString(r, "PRIVATE", "INTERNAL", "PUBLIC"),
			"private":                true,
			"is_template":            false,
			"archived":               archived,
			"fork":                   chance(r, 0.05),
			"delete_branch_on_merge": chance(r, w.deleteBranchOnMerge),
		},
		"basic_features": map[string]interface{}{
			"has_issues":      chance(r, w.hasIssuesOrDiscussions),
			"has_projects":    true,
			"has_wiki":        chance(r, 0.7),
			"has_discussions": chance(r, 0.3),
		},
		"branch_protection": branchProtection,
		"dependabot_config": map[string]interface{}{
			"exists": chance(r, w.dependabotConfigExists),
		},
		"discussion_settings": map[string]interface{}{
			"enabled": chance(r, 0.3),
		},
		"metadata": metadata,
		"security": map[string]interface{}{
			"vulnerability_alerts": map[string]interface{}{
				"enabled": dependabotEnabled,
			},
			"dependabot_alerts": map[string]interface{}{
				"enabled":           dependabotEnabled,
				"total_open_alerts": openAlerts,
				"by_severity":       bySeverity,
			},
			"security_policy": map[string]interface{}{
				"enabled": chance(r, w.securityPolicyExists),
			},
			"codeowners_file": map[string]interface{}{
				"exists": chance(r, w.codeOwnersExists),
			},
		},
	}
	if chance(r, w.hasDescription) {
		repo["description"] = pickString(r,
			"Internal platform service",
			"Reference architecture",
			"CLI helper",
			"Reusable library",
		)
	}
	if enterprise != "" {
		repo["enterprise"] = enterprise
	}
	return repo
}

// pickStringWeighted returns the first string with probability p, else the second.
func pickStringWeighted(r *rand.Rand, p float64, ifTrue, ifFalse string) string {
	if chance(r, p) {
		return ifTrue
	}
	return ifFalse
}
