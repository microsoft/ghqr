// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
)

// EnterpriseDiscoveryStage discovers enterprises the authenticated user administers
// when none are explicitly specified via flags.
type EnterpriseDiscoveryStage struct {
	*BaseStage
}

// NewEnterpriseDiscoveryStage creates a new enterprise discovery stage.
func NewEnterpriseDiscoveryStage() *EnterpriseDiscoveryStage {
	return &EnterpriseDiscoveryStage{
		BaseStage: NewBaseStage("enterprise_discovery"),
	}
}

func (s *EnterpriseDiscoveryStage) Execute(ctx *ScanContext) error {
	if ctx.GitHubGraphQLClient == nil {
		log.Warn().Msg("GraphQL client not available - skipping enterprise discovery")
		return nil
	}

	log.Info().Msg("Discovering enterprises for authenticated user...")

	var query struct {
		Viewer struct {
			Enterprises struct {
				Nodes []struct {
					Slug githubv4.String
				}
				PageInfo struct {
					EndCursor   githubv4.String
					HasNextPage githubv4.Boolean
				}
			} `graphql:"enterprises(first: 100, after: $cursor)"`
		}
	}

	var cursor *githubv4.String
	for {
		variables := map[string]interface{}{
			"cursor": cursor,
		}
		if err := ctx.GitHubGraphQLClient.Query(ctx.Ctx, &query, variables); err != nil {
			log.Warn().Err(err).Msg("Failed to discover enterprises - account may not have enterprise admin access")
			return nil
		}
		for _, node := range query.Viewer.Enterprises.Nodes {
			ctx.Params.Enterprises = append(ctx.Params.Enterprises, string(node.Slug))
		}
		if !bool(query.Viewer.Enterprises.PageInfo.HasNextPage) {
			break
		}
		c := query.Viewer.Enterprises.PageInfo.EndCursor
		cursor = &c
	}

	if len(ctx.Params.Enterprises) == 0 {
		log.Info().Msg("No enterprises found for the authenticated user")
		return nil
	}

	log.Info().
		Int("count", len(ctx.Params.Enterprises)).
		Strs("enterprises", ctx.Params.Enterprises).
		Msg("Enterprises discovered")

	return nil
}

func (s *EnterpriseDiscoveryStage) Skip(ctx *ScanContext) bool {
	// Skip auto-discovery when the user explicitly specified enterprises, organizations, or repositories.
	return len(ctx.Params.Enterprises) > 0 ||
		len(ctx.Params.Organizations) > 0 ||
		len(ctx.Params.Repositories) > 0
}
