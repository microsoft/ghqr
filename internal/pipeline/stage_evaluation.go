// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"encoding/json"
	"strings"

	"github.com/microsoft/ghqr/internal/recommendations"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
	"github.com/rs/zerolog/log"
)

// EvaluationStage runs best-practice evaluations against all scanned results.
// Evaluation results are stored in ctx.Results under "evaluation:<original-key>".
type EvaluationStage struct {
	*BaseStage
	eval *bestpractices.Evaluator
}

// NewEvaluationStage creates a new evaluation stage backed by the embedded rule registry.
func NewEvaluationStage() *EvaluationStage {
	registry, err := recommendations.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load rule definitions")
	}
	return &EvaluationStage{
		BaseStage: NewBaseStage("evaluation"),
		eval:      bestpractices.NewEvaluator(registry),
	}
}

func (s *EvaluationStage) Execute(ctx *ScanContext) error {
	log.Info().Msg("Running best-practice evaluations...")

	for key, data := range ctx.Results {
		switch {
		case strings.HasPrefix(key, "organization:"):
			org := toType[scanners.OrganizationData](data)
			if org == nil {
				continue
			}
			orgName := strings.TrimPrefix(key, "organization:")
			ctx.Results["evaluation:"+key] = s.eval.EvaluateOrganizationSecurity(org.Settings)

			// Org security defaults (IAM / new-repo policies)
			if org.Settings != nil {
				ctx.Results["evaluation:org_security_defaults:"+orgName] = s.eval.EvaluateOrgSecurityDefaults(&org.Settings.Security)
			}

			// GitHub Copilot
			if org.Copilot != nil {
				ctx.Results["evaluation:copilot:"+orgName] = s.eval.EvaluateCopilot(org.Copilot)
			}

			// GitHub Actions permissions
			if org.ActionsPermissions != nil {
				ctx.Results["evaluation:actions_permissions:"+orgName] = s.eval.EvaluateActionsPermissions(org.ActionsPermissions)
			}

			// Org-level security alerts (GHAS)
			if org.SecurityAlerts != nil {
				ctx.Results["evaluation:org_security_alerts:"+orgName] = s.eval.EvaluateOrgSecurityAlerts(org.SecurityAlerts)
			}

			// Security managers
			if org.SecurityManagers != nil {
				ctx.Results["evaluation:security_managers:"+orgName] = s.eval.EvaluateSecurityManagers(org.SecurityManagers)
			}

		case strings.HasPrefix(key, "enterprise:"):
			enterprise := toType[scanners.EnterpriseData](data)
			if enterprise == nil {
				continue
			}
			enterpriseName := strings.TrimPrefix(key, "enterprise:")
			if enterprise.AuditLog != nil {
				ctx.Results["evaluation:audit_log:"+enterpriseName] = s.eval.EvaluateEnterpriseAuditLog(enterprise.AuditLog)
			}
			if enterprise.SecurityAlerts != nil {
				ctx.Results["evaluation:enterprise_security_alerts:"+enterpriseName] = s.eval.EvaluateEnterpriseSecurityAlerts(enterprise.SecurityAlerts)
			}
			// Enterprise-wide GHAS policy defaults (REST: GET /enterprises/{slug}/code_security/settings)
			ctx.Results["evaluation:enterprise_ghas:"+enterpriseName] = s.eval.EvaluateEnterpriseGHASSettings(enterprise.GHASSettings)

		case strings.HasPrefix(key, "repository:"):
			repo := toType[scanners.RepositoryData](data)
			if repo == nil {
				continue
			}
			repoName := strings.TrimPrefix(key, "repository:")

			// Repository features (security, access, features)
			result := s.eval.EvaluateRepositoryFeatures(repo)

			// Branch protection detail (from GraphQL) — skip for archived repos (read-only)
			archived := repo.Access != nil && repo.Access.Archived
			if !archived {
				if repo.BranchProtection != nil && repo.BranchProtection.Protected {
					// Legacy branch protection is present — evaluate it.
					bpDetail := s.eval.EvaluateBranchProtectionDetail(repo.BranchProtection)
					result.Recommendations = append(result.Recommendations, bpDetail.Recommendations...)
				} else if repo.RulesetProtection != nil && repo.RulesetProtection.Protected {
					// No legacy BP, but ruleset-based protection is present — evaluate it.
					rsDetail := s.eval.EvaluateRulesetProtection(repo.RulesetProtection)
					if rsDetail != nil {
						result.Recommendations = append(result.Recommendations, rsDetail.Recommendations...)
					}
				} else if repo.BranchProtection != nil {
					// No legacy BP and no rulesets — flag as unprotected.
					bpDetail := s.eval.EvaluateBranchProtectionDetail(repo.BranchProtection)
					result.Recommendations = append(result.Recommendations, bpDetail.Recommendations...)
				}
			}

			// Recalculate summary after all findings are merged
			result.Summary = s.eval.Summary(result.Recommendations)

			ctx.Results["evaluation:"+key] = result

			// Collaborators
			if len(repo.Collaborators) > 0 {
				ctx.Results["evaluation:collaborators:"+repoName] = s.eval.EvaluateCollaborators(repo.Collaborators)
			}

			// Deploy keys
			if len(repo.DeployKeys) > 0 {
				ctx.Results["evaluation:deploy_keys:"+repoName] = s.eval.EvaluateDeployKeys(repo.DeployKeys)
			}

			// Dependabot configuration
			var dependabotInfo *scanners.DependabotInfo
			if repo.Security != nil {
				dependabotInfo = repo.Security.DependabotAlerts
			}
			ctx.Results["evaluation:dependabot:"+repoName] = s.eval.EvaluateDependabotConfig(repo.DependabotConfig, dependabotInfo)

			// Code scanning configuration
			ctx.Results["evaluation:code_scanning:"+repoName] = s.eval.EvaluateCodeScanningConfig(repo.CodeScanningConfig)

			// Discussion settings
			if repo.DiscussionSettings != nil {
				ctx.Results["evaluation:discussions:"+repoName] = s.eval.EvaluateDiscussionSettings(repo)
			}

			// Repository metadata: description, topics, dormancy (G3, R8)
			ctx.Results["evaluation:metadata:"+repoName] = s.eval.EvaluateRepositoryMetadata(repo)
		}
	}

	log.Info().Msg("Evaluations completed")
	return nil
}

func (s *EvaluationStage) Skip(ctx *ScanContext) bool {
	return len(ctx.Results) == 0
}

// toType converts an interface{} value to *T, handling both direct type assertions
// and round-tripping through JSON for map[string]interface{} values from prior unmarshalling.
func toType[T any](v interface{}) *T {
	if v == nil {
		return nil
	}
	if t, ok := v.(*T); ok {
		return t
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return &out
}
