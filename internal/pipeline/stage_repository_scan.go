// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"strings"

	"github.com/microsoft/ghqr/internal/config"
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
	graphqlEndpoint := config.GraphQLEndpoint(ctx.Params.Hostname)
	graphqlClient := scanners.NewGraphQLClient(ctx.GitHubGraphQLClient, ctx.GitHubRawHTTPClient, graphqlEndpoint)

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
		for _, chunk := range chunks {
			log.Info().
				Str("owner", owner).
				Strs("repos", chunk).
				Msg("Fetching repositories via GraphQL")

			results, err := graphqlClient.FetchRepositoriesBatch(ctx.Ctx, owner, chunk)
			if err != nil {
				log.Error().Err(err).Str("owner", owner).Strs("repos", chunk).Msg("Failed to fetch repositories")
				continue
			}

			for name, data := range results {
				data.Organization = owner
				ctx.Results[fmt.Sprintf("repository:%s/%s", owner, name)] = data
			}
		}

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
// REST API to detect ruleset-based protection.
func (s *RepositoryScanStage) enrichWithRulesets(ctx *ScanContext, owner string) {
	if ctx.GitHubRawHTTPClient == nil {
		return
	}

	graphqlEndpoint := config.GraphQLEndpoint(ctx.Params.Hostname)

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

	log.Info().
		Str("owner", owner).
		Int("repos", len(needsEnrichment)).
		Msg("Enriching repositories with ruleset data")

	for _, key := range needsEnrichment {
		repo := ctx.Results[key].(*scanners.RepositoryData)
		branch := ""
		if repo.Metadata != nil {
			branch = repo.Metadata.DefaultBranch
		}
		if branch == "" {
			branch = "main"
		}

		detail := scanners.FetchRulesetProtection(ctx.Ctx, ctx.GitHubRawHTTPClient, graphqlEndpoint, owner, repo.Name, branch)
		if detail != nil && detail.Protected {
			repo.RulesetProtection = detail
			log.Debug().
				Str("repo", repo.Name).
				Int("rulesets", detail.RulesetCount).
				Msg("Repository protected by rulesets")
		}
	}
}

// Skip returns true when no repositories were specified via the -r flag.
func (s *RepositoryScanStage) Skip(ctx *ScanContext) bool {
	if len(ctx.Params.Repositories) == 0 {
		log.Debug().Msg("Skipping repository scan - no repositories specified")
		return true
	}
	return false
}
