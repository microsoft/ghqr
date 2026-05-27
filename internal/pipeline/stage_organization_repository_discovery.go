// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// OrgRepositoryDiscoveryStage discovers repository names for all organizations
// found in the scan context and appends them to ctx.Params.Repositories so that
// RepositoryScanStage can scan them in a later pipeline stage.
type OrgRepositoryDiscoveryStage struct {
	*BaseStage
}

// NewOrgRepositoryDiscoveryStage creates a new org-repository discovery stage.
func NewOrgRepositoryDiscoveryStage() *OrgRepositoryDiscoveryStage {
	return &OrgRepositoryDiscoveryStage{
		BaseStage: NewBaseStage("org_repository_discovery"),
	}
}

// Execute discovers repository names for each discovered organization and appends
// them to ctx.Params.Repositories as "owner/name" strings for RepositoryScanStage.
func (s *OrgRepositoryDiscoveryStage) Execute(ctx *ScanContext) error {
	for _, client := range ctx.GraphQLClients {
		for key := range ctx.Results {
			if !strings.HasPrefix(key, "organization:") {
				continue
			}
			org := strings.TrimPrefix(key, "organization:")
			log.Info().Str("org", org).Msg("Discovering repository names for organization")

			names, err := client.FetchOrgRepositoryNames(ctx.Ctx, org)
			if err != nil {
				log.Error().Err(err).Str("org", org).Msg("Failed to fetch org repository names")
				continue
			}

			for _, name := range names {
				ctx.Params.Repositories = append(ctx.Params.Repositories, fmt.Sprintf("%s/%s", org, name))
			}
			log.Info().Str("org", org).Int("count", len(names)).Msg("Discovered repositories")
		}
	}
	return nil
}

// Skip returns true when replaying from JSON or when no organization results are
// available to discover repositories from.
func (s *OrgRepositoryDiscoveryStage) Skip(ctx *ScanContext) bool {
	if ctx.Params.IsReplay() || len(ctx.Params.Repositories) > 0 {
		return true
	}
	for key := range ctx.Results {
		if strings.HasPrefix(key, "organization:") {
			return false
		}
	}
	return true
}
