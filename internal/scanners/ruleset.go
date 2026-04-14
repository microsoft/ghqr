// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// rulesetQuery is the GraphQL query to fetch active rulesets for a repository.
// It uses includeParents:true to capture org-level rulesets as well.
const rulesetQuery = `
query FetchRulesets($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    rulesets(first: 25, includeParents: true) {
      totalCount
      nodes {
        name
        enforcement
        target
        rules(first: 30) {
          nodes {
            type
            parameters {
              ... on PullRequestParameters {
                requiredApprovingReviewCount
                dismissStaleReviewsOnPush
                requireCodeOwnerReview
              }
              ... on RequiredStatusChecksParameters {
                strictRequiredStatusChecksPolicy
                requiredStatusChecks { context }
              }
            }
          }
        }
      }
    }
  }
}
`

// gqlRulesetResponse maps the GraphQL response for the rulesets query.
type gqlRulesetResponse struct {
	Data struct {
		Repository *struct {
			Rulesets struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Name        string `json:"name"`
					Enforcement string `json:"enforcement"`
					Target      string `json:"target"`
					Rules       struct {
						Nodes []struct {
							Type       string                `json:"type"`
							Parameters *gqlRulesetParameters `json:"parameters"`
						} `json:"nodes"`
					} `json:"rules"`
				} `json:"nodes"`
			} `json:"rulesets"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// gqlRulesetParameters is a flat struct capturing fields from multiple parameter
// union members. Only the fields relevant to the matching rule type will be populated.
type gqlRulesetParameters struct {
	// PullRequestParameters
	RequiredApprovingReviewCount int  `json:"requiredApprovingReviewCount"`
	DismissStaleReviewsOnPush    bool `json:"dismissStaleReviewsOnPush"`
	RequireCodeOwnerReview       bool `json:"requireCodeOwnerReview"`
	// RequiredStatusChecksParameters
	StrictRequiredStatusChecksPolicy bool `json:"strictRequiredStatusChecksPolicy"`
	RequiredStatusChecks             []struct {
		Context string `json:"context"`
	} `json:"requiredStatusChecks"`
}

// FetchRulesetProtection queries the GraphQL API for active repository rulesets
// and converts them into a RulesetProtectionDetail. It uses the raw HTTP client
// (same auth as batch queries) so it works reliably with all token types.
func FetchRulesetProtection(ctx context.Context, httpClient *http.Client, owner, repo, branch string) *RulesetProtectionDetail {
	if httpClient == nil || branch == "" {
		return nil
	}

	payload := struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}{
		Query: rulesetQuery,
		Variables: map[string]interface{}{
			"owner": owner,
			"name":  repo,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to marshal rulesets query")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubGraphQLEndpoint, bytes.NewReader(body))
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create rulesets request")
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Debug().Err(err).
			Str("owner", owner).
			Str("repo", repo).
			Msg("Failed to fetch rulesets via GraphQL")
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var gqlResp gqlRulesetResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		log.Debug().Err(err).Msg("Failed to decode rulesets response")
		return nil
	}

	if len(gqlResp.Errors) > 0 {
		log.Debug().
			Str("owner", owner).
			Str("repo", repo).
			Str("error", gqlResp.Errors[0].Message).
			Msg("GraphQL rulesets query returned errors")
		return nil
	}

	if gqlResp.Data.Repository == nil {
		return nil
	}

	return parseRulesets(gqlResp.Data.Repository.Rulesets.Nodes, branch)
}

// parseRulesets converts GraphQL ruleset nodes into RulesetProtectionDetail.
// Only ACTIVE rulesets targeting BRANCH are considered.
func parseRulesets(nodes []struct {
	Name        string `json:"name"`
	Enforcement string `json:"enforcement"`
	Target      string `json:"target"`
	Rules       struct {
		Nodes []struct {
			Type       string                `json:"type"`
			Parameters *gqlRulesetParameters `json:"parameters"`
		} `json:"nodes"`
	} `json:"rules"`
}, branch string) *RulesetProtectionDetail {
	detail := &RulesetProtectionDetail{
		Branch:           branch,
		AllowForcePushes: true,
		AllowDeletions:   true,
	}

	activeCount := 0

	for _, rs := range nodes {
		// Only count active, branch-targeting rulesets.
		if rs.Enforcement != "ACTIVE" || rs.Target != "BRANCH" {
			continue
		}
		activeCount++

		for _, rule := range rs.Rules.Nodes {
			switch rule.Type {
			case "PULL_REQUEST":
				if rule.Parameters != nil {
					if detail.RequiredPullRequestReviews == nil {
						detail.RequiredPullRequestReviews = &RequiredPRReviews{}
					}
					pr := detail.RequiredPullRequestReviews
					if rule.Parameters.RequiredApprovingReviewCount > pr.RequiredApprovingReviewCount {
						pr.RequiredApprovingReviewCount = rule.Parameters.RequiredApprovingReviewCount
					}
					if rule.Parameters.DismissStaleReviewsOnPush {
						pr.DismissStaleReviews = true
					}
					if rule.Parameters.RequireCodeOwnerReview {
						pr.RequireCodeOwnerReviews = true
					}
				}

			case "REQUIRED_STATUS_CHECKS":
				if rule.Parameters != nil {
					if detail.RequiredStatusChecks == nil {
						detail.RequiredStatusChecks = &RequiredStatusChecks{}
					}
					if rule.Parameters.StrictRequiredStatusChecksPolicy {
						detail.RequiredStatusChecks.Strict = true
					}
					seen := make(map[string]struct{})
					for _, c := range detail.RequiredStatusChecks.Contexts {
						seen[c] = struct{}{}
					}
					for _, sc := range rule.Parameters.RequiredStatusChecks {
						if _, ok := seen[sc.Context]; !ok {
							seen[sc.Context] = struct{}{}
							detail.RequiredStatusChecks.Contexts = append(detail.RequiredStatusChecks.Contexts, sc.Context)
						}
					}
				}

			case "REQUIRED_LINEAR_HISTORY":
				detail.RequiredLinearHistory = true

			case "REQUIRED_SIGNATURES":
				detail.RequiredSignatures = true

			case "NON_FAST_FORWARD":
				detail.AllowForcePushes = false

			case "DELETION":
				detail.AllowDeletions = false
			}
		}
	}

	detail.RulesetCount = activeCount
	detail.Protected = activeCount > 0

	if !detail.Protected {
		return nil
	}

	log.Debug().
		Str("branch", branch).
		Int("rulesets", activeCount).
		Msg("Rulesets detected via GraphQL")

	return detail
}

// FetchRulesetProtectionREST queries the REST API as a fallback for ruleset detection.
// Prefer FetchRulesetProtection (GraphQL) which uses the same auth as batch queries.
func FetchRulesetProtectionREST(ctx context.Context, restBaseURL, token, owner, repo, branch string) *RulesetProtectionDetail {
	// REST fallback is kept as a skeleton for future use if needed.
	_ = ctx
	_ = restBaseURL
	_ = token
	_ = owner
	_ = repo
	_ = branch
	return nil
}

// FormatRulesetScanError formats a user-friendly error message for ruleset scan failures.
func FormatRulesetScanError(owner, repo string, err error) string {
	return fmt.Sprintf("failed to fetch rulesets for %s/%s: %v", owner, repo, err)
}
