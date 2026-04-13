// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// OrganizationScanStage handles scanning of GitHub organizations.
type OrganizationScanStage struct {
	*BaseStage
}

// NewOrganizationScanStage creates a new organization scan stage.
func NewOrganizationScanStage() *OrganizationScanStage {
	return &OrganizationScanStage{
		BaseStage: NewBaseStage("organization_scan"),
	}
}

func (s *OrganizationScanStage) Execute(ctx *ScanContext) error {
	if len(ctx.Params.Organizations) == 0 {
		log.Warn().Msg("No organizations specified for scanning")
		return nil
	}

	log.Info().
		Int("count", len(ctx.Params.Organizations)).
		Msg("Starting organization scan")

	for _, org := range ctx.Params.Organizations {
		if err := s.scanOrganization(ctx, org); err != nil {
			log.Error().
				Err(err).
				Str("organization", org).
				Msg("Failed to scan organization")
			continue
		}
	}

	log.Info().Msg("Organization scan completed")
	return nil
}

func (s *OrganizationScanStage) scanOrganization(ctx *ScanContext, org string) error {
	log.Info().Str("organization", org).Msg("Scanning organization")

	scanner := scanners.NewOrganizationScanner(ctx.GitHubClient, ctx.GitHubGraphQLClient, org)
	data, err := scanner.ScanAll(ctx.Ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	ctx.Results[fmt.Sprintf("organization:%s", org)] = data

	// Record which enterprise owns this org (empty string for directly-specified orgs).
	data.Enterprise = ctx.Ownership[fmt.Sprintf("organization:%s", org)]

	// Propagate EMU status from the parent enterprise to the org settings.
	if data.Enterprise != "" && data.Settings != nil {
		if entData, ok := ctx.Results[fmt.Sprintf("enterprise:%s", data.Enterprise)]; ok {
			if ent, ok := entData.(*scanners.EnterpriseData); ok && ent.Settings != nil {
				data.Settings.Security.EMUEnabled = ent.Settings.EMUEnabled
			}
		}
	}

	log.Info().Str("organization", org).Msg("Organization scan completed successfully")
	return nil
}

func (s *OrganizationScanStage) Skip(ctx *ScanContext) bool {
	if len(ctx.Params.Organizations) == 0 {
		log.Debug().Msg("Skipping organization scan - no organizations to scan")
		return true
	}
	return false
}
