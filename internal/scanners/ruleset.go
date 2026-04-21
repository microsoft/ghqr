// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

// gqlRulesetNode is one ruleset entry returned by the rulesets GraphQL query.
type gqlRulesetNode struct {
	Name        string `json:"name"`
	Enforcement string `json:"enforcement"`
	Target      string `json:"target"`
	Rules       struct {
		Nodes []struct {
			Type       string                `json:"type"`
			Parameters *gqlRulesetParameters `json:"parameters"`
		} `json:"nodes"`
	} `json:"rules"`
}

// gqlRulesetResponse maps the GraphQL response for the rulesets query.
type gqlRulesetResponse struct {
	Data struct {
		Repository *struct {
			Rulesets struct {
				TotalCount int              `json:"totalCount"`
				Nodes      []gqlRulesetNode `json:"nodes"`
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
func FetchRulesetProtection(ctx context.Context, httpClient *http.Client, graphqlEndpoint, owner, repo, branch string) *RulesetProtectionDetail {
	if httpClient == nil || branch == "" {
		return nil
	}

	if graphqlEndpoint == "" {
		graphqlEndpoint = defaultGraphQLEndpoint
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlEndpoint, bytes.NewReader(body))
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

// RulesetBatchSize is the number of repositories fetched per batch ruleset GraphQL request.
// The ruleset query is lighter than the full repository query (no file checks, no topics/language),
// so we can safely alias more repositories per request.
const RulesetBatchSize = 10

// rulesetFieldsFragment is the GraphQL field selection for rulesets of a single repository alias.
const rulesetFieldsFragment = `
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
`

// RulesetBatchRepo holds the owner, name, and branch for a single repository in a batch request.
type RulesetBatchRepo struct {
	Owner  string
	Name   string
	Branch string
}

// batchRulesetGraphQLResponse is the top-level GraphQL response for batch ruleset queries.
type batchRulesetGraphQLResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// batchRulesetRepoData is the JSON shape for one aliased repository in a batch response.
type batchRulesetRepoData struct {
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
}

// FetchRulesetProtectionBatch queries the GraphQL API for rulesets of multiple
// repositories in a single request using aliases. It returns a map keyed by
// "owner/name" containing the parsed RulesetProtectionDetail (nil if not protected).
func FetchRulesetProtectionBatch(ctx context.Context, httpClient *http.Client, graphqlEndpoint string, repos []RulesetBatchRepo) map[string]*RulesetProtectionDetail {
	if httpClient == nil || len(repos) == 0 {
		return nil
	}
	if graphqlEndpoint == "" {
		graphqlEndpoint = defaultGraphQLEndpoint
	}

	// Build a query with one alias per repository.
	var qb strings.Builder
	qb.WriteString("query BatchRulesets(")
	for i := range repos {
		if i > 0 {
			qb.WriteString(", ")
		}
		fmt.Fprintf(&qb, "$owner%d: String!, $name%d: String!", i, i)
	}
	qb.WriteString(") {\n")
	for i := range repos {
		fmt.Fprintf(&qb, "  repo%d: repository(owner: $owner%d, name: $name%d) {%s  }\n", i, i, i, rulesetFieldsFragment)
	}
	qb.WriteString("}")

	vars := make(map[string]interface{}, len(repos)*2)
	for i, r := range repos {
		vars[fmt.Sprintf("owner%d", i)] = r.Owner
		vars[fmt.Sprintf("name%d", i)] = r.Name
	}

	payload := struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}{qb.String(), vars}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to marshal batch rulesets query")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlEndpoint, bytes.NewReader(body))
	if err != nil {
		log.Debug().Err(err).Msg("Failed to create batch rulesets request")
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to execute batch rulesets request")
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var gqlResp batchRulesetGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		log.Debug().Err(err).Msg("Failed to decode batch rulesets response")
		return nil
	}

	if len(gqlResp.Errors) > 0 {
		log.Debug().
			Str("error", gqlResp.Errors[0].Message).
			Msg("GraphQL batch rulesets query returned errors")
		return nil
	}

	results := make(map[string]*RulesetProtectionDetail, len(repos))
	for i, r := range repos {
		alias := fmt.Sprintf("repo%d", i)
		raw, ok := gqlResp.Data[alias]
		if !ok || string(raw) == "null" {
			continue
		}
		var d batchRulesetRepoData
		if err := json.Unmarshal(raw, &d); err != nil {
			log.Debug().Err(err).Str("repo", r.Name).Msg("Failed to decode batch ruleset repo data")
			continue
		}
		detail := parseRulesets(d.Rulesets.Nodes, r.Branch)
		key := fmt.Sprintf("%s/%s", r.Owner, r.Name)
		results[key] = detail
	}
	return results
}

// NewRulesetBatchRepo creates a RulesetBatchRepo entry for use with FetchRulesetProtectionBatch.
func NewRulesetBatchRepo(owner, name, branch string) RulesetBatchRepo {
	return RulesetBatchRepo{Owner: owner, Name: name, Branch: branch}
}

// ChunkRulesetBatchRepos splits a slice of RulesetBatchRepo into chunks of at most size n.
func ChunkRulesetBatchRepos(repos []RulesetBatchRepo, n int) [][]RulesetBatchRepo {
	if n <= 0 {
		n = RulesetBatchSize
	}
	var chunks [][]RulesetBatchRepo
	for len(repos) > 0 {
		end := len(repos)
		if end > n {
			end = n
		}
		chunks = append(chunks, repos[:end])
		repos = repos[end:]
	}
	return chunks
}

// parseRulesets converts GraphQL ruleset nodes into RulesetProtectionDetail.
// Only ACTIVE rulesets targeting BRANCH are considered.
func parseRulesets(nodes []gqlRulesetNode, branch string) *RulesetProtectionDetail {
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
