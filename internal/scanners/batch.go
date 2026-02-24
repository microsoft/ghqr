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
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
)

const githubGraphQLEndpoint = "https://api.github.com/graphql"

// BatchSize is the number of repositories fetched per batch GraphQL request.
// Kept small (5) to stay within GitHub's query-complexity resource limits;
// each alias multiplies the per-connection cost in GitHub's internal scorer.
const BatchSize = 5

// repoFieldsFragment is the GraphQL field selection for a single repository.
// It must stay in sync with RepositoryNode in graphql_client.go.
// File presence is checked via `oid` (a 40-char SHA), not `text`, to avoid
// fetching potentially large file contents.
//
// The following three connections are intentionally EXCLUDED from this fragment
// even though they are present in the single-repo (FetchRepositoryCore) query:
//
//   - vulnerabilityAlerts(first: N)  — open alert severity counts
//   - collaborators(first: N)         — per-user permission list
//   - deployKeys(first: N)            — deploy key details
//
// GitHub's internal complexity scorer multiplies each paginated connection's
// cost by the number of aliases in the query. With 5 aliases the score of even
// small `first:` values exceeds the per-request resource limit and every alias
// returns a "Resource limits for this query exceeded." error.
//
// Consequence for org-wide batch scans:
//   - hasVulnerabilityAlertsEnabled (scalar) is still fetched, so "alerts
//     disabled" is still detected. Per-severity open-alert counts are not
//     available; see MANUAL_CHECKS.md § "Batch scan omissions".
//   - Collaborator and deploy-key checks evaluate as "none found", producing
//     info-level recommendations rather than issues.
//
// To get full data for a specific repository use the --repository flag, which
// goes through FetchRepositoryCore and fetches all three connections.
const repoFieldsFragment = `
    name description pushedAt isPrivate visibility isFork isArchived isTemplate
    hasIssuesEnabled hasProjectsEnabled hasWikiEnabled hasDiscussionsEnabled
    deleteBranchOnMerge hasVulnerabilityAlertsEnabled
    primaryLanguage { name }
    licenseInfo { name key spdxId }
    repositoryTopics(first: 20) { nodes { topic { name } } }
    defaultBranchRef {
      name
      branchProtectionRule {
        pattern requiredApprovingReviewCount
        requiresStrictStatusChecks requiresStatusChecks
        requiresCodeOwnerReviews requiresCommitSignatures
        requiresLinearHistory allowsForcePushes allowsDeletions dismissesStaleReviews
        requiredStatusChecks { context }
      }
    }
    codeownersFile: object(expression: "HEAD:CODEOWNERS") { ... on Blob { oid } }
    githubCodeownersFile: object(expression: "HEAD:.github/CODEOWNERS") { ... on Blob { oid } }
    docsCodeownersFile: object(expression: "HEAD:docs/CODEOWNERS") { ... on Blob { oid } }
    securityMdFile: object(expression: "HEAD:SECURITY.md") { ... on Blob { oid } }
    dependabotYmlFile: object(expression: "HEAD:.github/dependabot.yml") { ... on Blob { oid } }
    dependabotYamlFile: object(expression: "HEAD:.github/dependabot.yaml") { ... on Blob { oid } }
    codeqlConfigFile: object(expression: "HEAD:.github/codeql/config.yml") { ... on Blob { oid } }
    codeqlAltConfigFile: object(expression: "HEAD:.github/codeql-config.yml") { ... on Blob { oid } }
`

// batchBlobOID is the JSON shape for an inline `... on Blob { oid }` fragment.
// A nil pointer means the file does not exist; a non-nil pointer means it does.
type batchBlobOID struct {
	OID string `json:"oid"`
}

// batchRepoData is the JSON-decoded representation of one repository entry in a batch response.
// Fields use plain Go types with json tags so encoding/json can decode GitHub's camelCase response.
type batchRepoData struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	PushedAt    string `json:"pushedAt"`
	IsPrivate   bool   `json:"isPrivate"`
	Visibility  string `json:"visibility"`
	IsFork      bool   `json:"isFork"`
	IsArchived  bool   `json:"isArchived"`
	IsTemplate  bool   `json:"isTemplate"`

	HasIssuesEnabled      bool `json:"hasIssuesEnabled"`
	HasProjectsEnabled    bool `json:"hasProjectsEnabled"`
	HasWikiEnabled        bool `json:"hasWikiEnabled"`
	HasDiscussionsEnabled bool `json:"hasDiscussionsEnabled"`
	DeleteBranchOnMerge   bool `json:"deleteBranchOnMerge"`

	HasVulnerabilityAlertsEnabled bool `json:"hasVulnerabilityAlertsEnabled"`

	PrimaryLanguage struct {
		Name string `json:"name"`
	} `json:"primaryLanguage"`

	LicenseInfo struct {
		Name   string `json:"name"`
		Key    string `json:"key"`
		SpdxId string `json:"spdxId"`
	} `json:"licenseInfo"`

	RepositoryTopics struct {
		Nodes []struct {
			Topic struct {
				Name string `json:"name"`
			} `json:"topic"`
		} `json:"nodes"`
	} `json:"repositoryTopics"`

	DefaultBranchRef struct {
		Name                 string `json:"name"`
		BranchProtectionRule *struct {
			Pattern                      string `json:"pattern"`
			RequiredApprovingReviewCount int    `json:"requiredApprovingReviewCount"`
			RequiresStrictStatusChecks   bool   `json:"requiresStrictStatusChecks"`
			RequiresStatusChecks         bool   `json:"requiresStatusChecks"`
			RequiresCodeOwnerReviews     bool   `json:"requiresCodeOwnerReviews"`
			RequiresCommitSignatures     bool   `json:"requiresCommitSignatures"`
			RequiresLinearHistory        bool   `json:"requiresLinearHistory"`
			AllowsForcePushes            bool   `json:"allowsForcePushes"`
			AllowsDeletions              bool   `json:"allowsDeletions"`
			DismissesStaleReviews        bool   `json:"dismissesStaleReviews"`
			RequiredStatusChecks         []struct {
				Context string `json:"context"`
			} `json:"requiredStatusChecks"`
		} `json:"branchProtectionRule"`
	} `json:"defaultBranchRef"`

	// File presence checks — nil when the file does not exist.
	CodeownersFile       *batchBlobOID `json:"codeownersFile"`
	GithubCodeownersFile *batchBlobOID `json:"githubCodeownersFile"`
	DocsCodeownersFile   *batchBlobOID `json:"docsCodeownersFile"`
	SecurityMdFile       *batchBlobOID `json:"securityMdFile"`
	DependabotYmlFile    *batchBlobOID `json:"dependabotYmlFile"`
	DependabotYamlFile   *batchBlobOID `json:"dependabotYamlFile"`
	CodeqlConfigFile     *batchBlobOID `json:"codeqlConfigFile"`
	CodeqlAltConfigFile  *batchBlobOID `json:"codeqlAltConfigFile"`
}

// batchRateLimitInfo holds the rate-limit metadata returned alongside each batch query.
type batchRateLimitInfo struct {
	Remaining int    `json:"remaining"`
	Cost      int    `json:"cost"`
	ResetAt   string `json:"resetAt"`
}

// batchGraphQLResponse is the top-level GraphQL response envelope for batch queries.
type batchGraphQLResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// FetchRepositoriesBatch retrieves data for up to BatchSize repositories in a single
// GraphQL request by aliasing each repository fetch. It returns a map keyed by
// repository name containing the fully-mapped RepositoryData.
//
// When the rate-limit budget is nearly exhausted the function proactively sleeps
// until the budget resets to avoid wasted retries.
func (c *GraphQLClient) FetchRepositoriesBatch(ctx context.Context, owner string, names []string) (map[string]*RepositoryData, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > BatchSize {
		names = names[:BatchSize]
	}
	if c.httpClient == nil {
		return nil, fmt.Errorf("batch queries require an HTTP client; use NewGraphQLClient with a non-nil httpClient")
	}

	// Build a query with one alias per repository plus a rateLimit field.
	var qb strings.Builder
	qb.WriteString("query BatchScan($owner: String!")
	for i := range names {
		fmt.Fprintf(&qb, ", $name%d: String!", i)
	}
	qb.WriteString(") {\n")
	for i := range names {
		fmt.Fprintf(&qb, "  repo%d: repository(owner: $owner, name: $name%d) {%s  }\n", i, i, repoFieldsFragment)
	}
	qb.WriteString("  rateLimit { remaining cost resetAt }\n}")

	// Build variables: $owner plus one $nameN per repo.
	vars := map[string]interface{}{"owner": owner}
	for i, name := range names {
		vars[fmt.Sprintf("name%d", i)] = name
	}

	payload := struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}{qb.String(), vars}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubGraphQLEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("batch request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var gqlResp batchGraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		return nil, fmt.Errorf("failed to decode batch response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, len(gqlResp.Errors))
		for i, e := range gqlResp.Errors {
			msgs[i] = e.Message
		}
		return nil, fmt.Errorf("GraphQL batch errors: %s", strings.Join(msgs, "; "))
	}

	// Extract and log rate-limit metadata; proactively pause if budget is nearly gone.
	if rl, ok := gqlResp.Data["rateLimit"]; ok {
		var info batchRateLimitInfo
		if err := json.Unmarshal(rl, &info); err == nil {
			log.Debug().
				Int("remaining", info.Remaining).
				Int("cost", info.Cost).
				Str("resetAt", info.ResetAt).
				Msg("GraphQL rate limit status")

			// If fewer than 3 full batches of budget remain, sleep until reset.
			if info.Remaining >= 0 && info.Cost > 0 && info.Remaining < info.Cost*3 && info.ResetAt != "" {
				if resetAt, err := time.Parse(time.RFC3339, info.ResetAt); err == nil {
					if wait := time.Until(resetAt); wait > 0 {
						log.Info().
							Dur("wait", wait).
							Int("remaining", info.Remaining).
							Msg("Rate limit budget nearly exhausted, proactively waiting for reset")
						select {
						case <-ctx.Done():
							return nil, fmt.Errorf("context cancelled while waiting for rate limit reset: %w", ctx.Err())
						case <-time.After(wait):
						}
					}
				}
			}
		}
	}

	results := make(map[string]*RepositoryData, len(names))
	for i, name := range names {
		alias := fmt.Sprintf("repo%d", i)
		raw, ok := gqlResp.Data[alias]
		if !ok || string(raw) == "null" {
			log.Warn().Str("owner", owner).Str("repo", name).Msg("Repository not found in batch response")
			continue
		}
		var d batchRepoData
		if err := json.Unmarshal(raw, &d); err != nil {
			log.Warn().Err(err).Str("owner", owner).Str("repo", name).Msg("Failed to decode batch repo data")
			continue
		}
		node := batchDataToRepositoryNode(&d)
		results[name] = MapNodeToData(node)
	}
	return results, nil
}

// batchDataToRepositoryNode converts a batch JSON response (plain Go types) into a
// RepositoryNode (githubv4 types) so that MapNodeToData can be reused for both
// single-repo and batch scan paths.
func batchDataToRepositoryNode(d *batchRepoData) RepositoryNode {
	node := RepositoryNode{
		Name:                          githubv4.String(d.Name),
		Description:                   githubv4.String(d.Description),
		PushedAt:                      githubv4.String(d.PushedAt),
		IsPrivate:                     githubv4.Boolean(d.IsPrivate),
		Visibility:                    githubv4.String(d.Visibility),
		IsFork:                        githubv4.Boolean(d.IsFork),
		IsArchived:                    githubv4.Boolean(d.IsArchived),
		IsTemplate:                    githubv4.Boolean(d.IsTemplate),
		HasIssuesEnabled:              githubv4.Boolean(d.HasIssuesEnabled),
		HasProjectsEnabled:            githubv4.Boolean(d.HasProjectsEnabled),
		HasWikiEnabled:                githubv4.Boolean(d.HasWikiEnabled),
		HasDiscussionsEnabled:         githubv4.Boolean(d.HasDiscussionsEnabled),
		DeleteBranchOnMerge:           githubv4.Boolean(d.DeleteBranchOnMerge),
		HasVulnerabilityAlertsEnabled: githubv4.Boolean(d.HasVulnerabilityAlertsEnabled),
	}

	node.PrimaryLanguage.Name = githubv4.String(d.PrimaryLanguage.Name)
	node.LicenseInfo.Name = githubv4.String(d.LicenseInfo.Name)
	node.LicenseInfo.Key = githubv4.String(d.LicenseInfo.Key)
	node.LicenseInfo.SpdxId = githubv4.String(d.LicenseInfo.SpdxId)

	node.RepositoryTopics.Nodes = make([]struct {
		Topic struct{ Name githubv4.String }
	}, len(d.RepositoryTopics.Nodes))
	for i, t := range d.RepositoryTopics.Nodes {
		node.RepositoryTopics.Nodes[i].Topic.Name = githubv4.String(t.Topic.Name)
	}

	node.DefaultBranchRef.Name = githubv4.String(d.DefaultBranchRef.Name)
	if bpr := d.DefaultBranchRef.BranchProtectionRule; bpr != nil {
		r := &node.DefaultBranchRef.BranchProtectionRule
		r.Pattern = githubv4.String(bpr.Pattern)
		r.RequiredApprovingReviewCount = githubv4.Int(bpr.RequiredApprovingReviewCount)
		r.RequiresStrictStatusChecks = githubv4.Boolean(bpr.RequiresStrictStatusChecks)
		r.RequiresStatusChecks = githubv4.Boolean(bpr.RequiresStatusChecks)
		r.RequiresCodeOwnerReviews = githubv4.Boolean(bpr.RequiresCodeOwnerReviews)
		r.RequiresCommitSignatures = githubv4.Boolean(bpr.RequiresCommitSignatures)
		r.RequiresLinearHistory = githubv4.Boolean(bpr.RequiresLinearHistory)
		r.AllowsForcePushes = githubv4.Boolean(bpr.AllowsForcePushes)
		r.AllowsDeletions = githubv4.Boolean(bpr.AllowsDeletions)
		r.DismissesStaleReviews = githubv4.Boolean(bpr.DismissesStaleReviews)
		for _, sc := range bpr.RequiredStatusChecks {
			r.RequiredStatusChecks = append(r.RequiredStatusChecks, struct {
				Context githubv4.String
			}{Context: githubv4.String(sc.Context)})
		}
	}

	blobOID := func(b *batchBlobOID) githubv4.String {
		if b != nil {
			return githubv4.String(b.OID)
		}
		return ""
	}
	node.CodeownersFile.Blob.Oid = blobOID(d.CodeownersFile)
	node.GithubCodeownersFile.Blob.Oid = blobOID(d.GithubCodeownersFile)
	node.DocsCodeownersFile.Blob.Oid = blobOID(d.DocsCodeownersFile)
	node.SecurityMdFile.Blob.Oid = blobOID(d.SecurityMdFile)
	node.DependabotYmlFile.Blob.Oid = blobOID(d.DependabotYmlFile)
	node.DependabotYamlFile.Blob.Oid = blobOID(d.DependabotYamlFile)
	node.CodeqlConfigFile.Blob.Oid = blobOID(d.CodeqlConfigFile)
	node.CodeqlAltConfigFile.Blob.Oid = blobOID(d.CodeqlAltConfigFile)

	return node
}

// ChunkStrings splits a slice into chunks of at most size n.
func ChunkStrings(s []string, n int) [][]string {
	if n <= 0 {
		n = BatchSize
	}
	var chunks [][]string
	for len(s) > 0 {
		end := len(s)
		if end > n {
			end = n
		}
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	return chunks
}
