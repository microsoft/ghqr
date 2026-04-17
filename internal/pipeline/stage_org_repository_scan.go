// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"strings"
	"sync"

	"github.com/microsoft/ghqr/internal/config"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// OrgRepositoryScanStage scans repositories discovered by prior organization scans.
// Repositories are fetched in batches (up to BatchSize per request) using aliased
// GraphQL queries, and batches are processed concurrently up to Workers goroutines.
type OrgRepositoryScanStage struct {
	*BaseStage
}

// NewOrgRepositoryScanStage creates a new org-repository scan stage.
func NewOrgRepositoryScanStage() *OrgRepositoryScanStage {
	return &OrgRepositoryScanStage{
		BaseStage: NewBaseStage("org_repository_scan"),
	}
}

func (s *OrgRepositoryScanStage) Execute(ctx *ScanContext) error {
	graphqlEndpoint := config.GraphQLEndpoint(ctx.Params.Hostname)
	graphqlClient := scanners.NewGraphQLClient(ctx.GitHubGraphQLClient, ctx.GitHubRawHTTPClient, graphqlEndpoint)

	workers := 5

	for key := range ctx.Results {
		if !strings.HasPrefix(key, "organization:") {
			continue
		}
		org := strings.TrimPrefix(key, "organization:")
		log.Info().Str("org", org).Msg("Fetching organization repository names via GraphQL")

		names, err := graphqlClient.FetchOrgRepositoryNames(ctx.Ctx, org)
		if err != nil {
			log.Error().Err(err).Str("org", org).Msg("Failed to fetch org repository names")
			continue
		}

		log.Info().
			Str("org", org).
			Int("count", len(names)).
			Int("workers", workers).
			Int("batch_size", scanners.BatchSize).
			Msg("Scanning repositories in batches")

		chunks := scanners.ChunkStrings(names, scanners.BatchSize)

		var (
			mu  sync.Mutex
			wg  sync.WaitGroup
			sem = make(chan struct{}, workers)
		)

		for _, chunk := range chunks {
			wg.Add(1)
			chunk := chunk // capture loop variable
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				results, err := graphqlClient.FetchRepositoriesBatch(ctx.Ctx, org, chunk)
				if err != nil {
					log.Warn().Err(err).Str("org", org).Strs("repos", chunk).Msg("Batch fetch failed, skipping chunk")
					return
				}

				mu.Lock()
				for name, data := range results {
					data.Organization = org
					data.Enterprise = ctx.Ownership[fmt.Sprintf("organization:%s", org)]
					ctx.Results[fmt.Sprintf("repository:%s/%s", org, name)] = data
				}
				mu.Unlock()
			}()
		}

		wg.Wait()

		// Enrich repos that lack legacy branch protection with ruleset data.
		// The REST API (GET /repos/{owner}/{repo}/rules/branches/{branch})
		// detects protection via repository rulesets which are invisible to
		// the GraphQL branchProtectionRule field.
		s.enrichWithRulesets(ctx, org)

		log.Info().Str("org", org).Int("scanned", len(names)).Msg("Org repository scan complete")
	}
	return nil
}

func (s *OrgRepositoryScanStage) Skip(ctx *ScanContext) bool {
	for key := range ctx.Results {
		if strings.HasPrefix(key, "organization:") {
			return false
		}
	}
	log.Debug().Msg("Skipping org-repository scan - no organization results found")
	return true
}

// enrichWithRulesets iterates repos belonging to the given org and, for those
// that have no legacy branch protection, fetches the effective rules from the
// GraphQL API to detect ruleset-based protection.
// Repositories are batched into a single GraphQL request per chunk to minimize
// round-trips.
func (s *OrgRepositoryScanStage) enrichWithRulesets(ctx *ScanContext, org string) {
	if ctx.GitHubRawHTTPClient == nil {
		return
	}

	graphqlEndpoint := config.GraphQLEndpoint(ctx.Params.Hostname)

	prefix := fmt.Sprintf("repository:%s/", org)
	var needsEnrichment []string
	for key, val := range ctx.Results {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		repo, ok := val.(*scanners.RepositoryData)
		if !ok || repo == nil {
			continue
		}
		// Skip archived repos — they are read-only.
		if repo.Access != nil && repo.Access.Archived {
			continue
		}
		// Only query rulesets when legacy branch protection is absent.
		if repo.BranchProtection != nil && repo.BranchProtection.Protected {
			continue
		}
		needsEnrichment = append(needsEnrichment, key)
	}

	if len(needsEnrichment) == 0 {
		return
	}

	// Build batch entries.
	batchRepos := make([]scanners.RulesetBatchRepo, 0, len(needsEnrichment))
	for _, key := range needsEnrichment {
		repo := ctx.Results[key].(*scanners.RepositoryData)
		branch := ""
		if repo.Metadata != nil {
			branch = repo.Metadata.DefaultBranch
		}
		if branch == "" {
			branch = "main"
		}
		batchRepos = append(batchRepos, scanners.NewRulesetBatchRepo(org, repo.Name, branch))
	}

	chunks := scanners.ChunkRulesetBatchRepos(batchRepos, scanners.RulesetBatchSize)

	rulesetWorkers := 10
	log.Info().
		Str("org", org).
		Int("repos", len(needsEnrichment)).
		Int("workers", rulesetWorkers).
		Int("chunks", len(chunks)).
		Msg("Enriching repositories with ruleset data via GraphQL (batched)")

	var wg sync.WaitGroup
	sem := make(chan struct{}, rulesetWorkers)
	var mu sync.Mutex
	allResults := make(map[string]*scanners.RulesetProtectionDetail)

	for _, chunk := range chunks {
		wg.Add(1)
		chunk := chunk // capture loop variable
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			results := scanners.FetchRulesetProtectionBatch(ctx.Ctx, ctx.GitHubRawHTTPClient, graphqlEndpoint, chunk)
			if results == nil {
				return
			}
			mu.Lock()
			for k, v := range results {
				allResults[k] = v
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Apply results to the scan context.
	for _, key := range needsEnrichment {
		repo := ctx.Results[key].(*scanners.RepositoryData)
		lookupKey := fmt.Sprintf("%s/%s", org, repo.Name)
		if detail, ok := allResults[lookupKey]; ok && detail != nil && detail.Protected {
			repo.RulesetProtection = detail
			log.Debug().
				Str("repo", repo.Name).
				Int("rulesets", detail.RulesetCount).
				Msg("Repository protected by rulesets")
		}
	}
}
