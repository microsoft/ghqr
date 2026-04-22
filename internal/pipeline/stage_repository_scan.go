// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"strings"
	"sync"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// RepositoryScanStage scans individual repositories specified via the -r flag.
// Each repository is fetched using the batch GraphQL query (batch size of 1 per owner group).
type RepositoryScanStage struct {
	*BaseStage
}

// NewRepositoryScanStage creates a new repository scan stage.
func NewRepositoryScanStage() *RepositoryScanStage {
	return &RepositoryScanStage{
		BaseStage: NewBaseStage("repository_scan"),
	}
}

// Execute fetches and stores data for each repository specified via the -r flag.
func (s *RepositoryScanStage) Execute(ctx *ScanContext) error {
	// Group repositories by owner so we can batch them efficiently.
	byOwner := make(map[string][]string)
	for _, repo := range ctx.Params.Repositories {
		parts := strings.SplitN(repo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			log.Warn().Str("repository", repo).Msg("Invalid repository format, expected owner/repo")
			continue
		}
		byOwner[parts[0]] = append(byOwner[parts[0]], parts[1])
	}

	for owner, names := range byOwner {
		chunks := scanners.ChunkStrings(names, scanners.BatchSize)

		workers := 5
		var (
			mu  sync.Mutex
			wg  sync.WaitGroup
			sem = make(chan struct{}, workers)
		)

		for _, chunk := range chunks {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()

				log.Info().
					Str("owner", owner).
					Strs("repos", chunk).
					Msg("Fetching repositories via GraphQL")

				results, err := ctx.GraphQLScanner.FetchRepositoriesBatch(ctx.Ctx, owner, chunk)
				if err != nil {
					log.Error().Err(err).Str("owner", owner).Strs("repos", chunk).Msg("Failed to fetch repositories")
					return
				}

				mu.Lock()
				for name, data := range results {
					data.Organization = owner
					ctx.Results[fmt.Sprintf("repository:%s/%s", owner, name)] = data
				}
				mu.Unlock()
			}()
		}

		wg.Wait()

		// Enrich repos that lack legacy branch protection with ruleset data.
		s.enrichWithRulesets(ctx, owner)
	}

	log.Info().
		Int("count", len(ctx.Params.Repositories)).
		Msg("Repository scan completed")
	return nil
}

// enrichWithRulesets iterates repos belonging to the given owner and, for those
// that have no legacy branch protection, fetches the effective rules from the
// GraphQL API to detect ruleset-based protection.
// Repositories are batched into a single GraphQL request per chunk to minimize
// round-trips.
func (s *RepositoryScanStage) enrichWithRulesets(ctx *ScanContext, owner string) {
	prefix := fmt.Sprintf("repository:%s/", owner)
	var needsEnrichment []string
	for key, val := range ctx.Results {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		repo, ok := val.(*scanners.RepositoryData)
		if !ok || repo == nil {
			continue
		}
		if repo.Access != nil && repo.Access.Archived {
			continue
		}
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
		branch := "main"
		if repo.Metadata != nil && repo.Metadata.DefaultBranch != "" {
			branch = repo.Metadata.DefaultBranch
		}
		batchRepos = append(batchRepos, scanners.NewRulesetBatchRepo(owner, repo.Name, branch))
	}

	chunks := scanners.ChunkRulesetBatchRepos(batchRepos, scanners.RulesetBatchSize)

	rulesetWorkers := 10
	log.Info().
		Str("owner", owner).
		Int("repos", len(needsEnrichment)).
		Int("workers", rulesetWorkers).
		Int("chunks", len(chunks)).
		Msg("Enriching repositories with ruleset data (batched)")

	var wg sync.WaitGroup
	sem := make(chan struct{}, rulesetWorkers)
	var mu sync.Mutex
	allResults := make(map[string]*scanners.RulesetProtectionDetail)

	for _, chunk := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			results := scanners.FetchRulesetProtectionBatch(ctx.Ctx, ctx.Clients.HTTP, ctx.GraphQLScanner.Endpoint(), chunk)
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
	totalRepos := len(needsEnrichment)
	for index, key := range needsEnrichment {
		repo := ctx.Results[key].(*scanners.RepositoryData)
		logEnrichmentProgress(index+1, totalRepos, owner, repo.Name)
		lookupKey := fmt.Sprintf("%s/%s", owner, repo.Name)
		if detail, ok := allResults[lookupKey]; ok && detail != nil && detail.Protected {
			repo.RulesetProtection = detail
			log.Debug().
				Str("repo", repo.Name).
				Int("rulesets", detail.RulesetCount).
				Msg("Repository protected by rulesets")
		}
	}
}

// logEnrichmentProgress outputs a structured log entry showing enrichment progress for a repository.
func logEnrichmentProgress(current int, total int, owner string, repoName string) {
	fullName := fmt.Sprintf("%s/%s", owner, repoName)
	log.Info().
		Str("repository", fullName).
		Int("current", current).
		Int("total", total).
		Msgf("Enriching repository %d of %d: %s", current, total, fullName)
}

// Skip returns true when no repositories were specified via the -r flag.
func (s *RepositoryScanStage) Skip(ctx *ScanContext) bool {
	if len(ctx.Params.Repositories) == 0 {
		log.Debug().Msg("Skipping repository scan - no repositories specified")
		return true
	}
	return false
}
