// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog/log"
)

// OrganizationDiscoveryStage discovers organizations the authenticated user
// belongs to when none are explicitly specified via flags.
type OrganizationDiscoveryStage struct {
	*BaseStage
}

// NewOrganizationDiscoveryStage creates a new organization discovery stage.
func NewOrganizationDiscoveryStage() *OrganizationDiscoveryStage {
	return &OrganizationDiscoveryStage{
		BaseStage: NewBaseStage("organization_discovery"),
	}
}

func (s *OrganizationDiscoveryStage) Execute(ctx *ScanContext) error {
	log.Info().Msg("Discovering organizations for authenticated user...")

	var orgs []*github.Organization
	opts := &github.ListOptions{PerPage: 100}
	for {
		page, resp, err := ctx.GitHubClient.Organizations.List(ctx.Ctx, "", opts)
		if err != nil {
			return err
		}
		orgs = append(orgs, page...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	if len(orgs) == 0 {
		log.Warn().Msg("No organizations found for the authenticated user")
		return nil
	}

	for _, org := range orgs {
		ctx.Params.Organizations = append(ctx.Params.Organizations, org.GetLogin())
	}

	log.Info().
		Int("count", len(orgs)).
		Strs("organizations", ctx.Params.Organizations).
		Msg("Organizations discovered")

	return nil
}

func (s *OrganizationDiscoveryStage) Skip(ctx *ScanContext) bool {
	return len(ctx.Params.Organizations) > 0
}
