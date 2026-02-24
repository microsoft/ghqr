// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"

	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// EnterpriseScanStage handles scanning of GitHub enterprises and their organizations.
type EnterpriseScanStage struct {
	*BaseStage
}

// NewEnterpriseScanStage creates a new enterprise scan stage.
func NewEnterpriseScanStage() *EnterpriseScanStage {
	return &EnterpriseScanStage{
		BaseStage: NewBaseStage("enterprise_scan"),
	}
}

func (s *EnterpriseScanStage) Execute(ctx *ScanContext) error {
	if len(ctx.Params.Enterprises) == 0 {
		log.Warn().Msg("No enterprises specified for scanning")
		return nil
	}

	log.Info().
		Int("count", len(ctx.Params.Enterprises)).
		Msg("Starting enterprise scan")

	for _, enterprise := range ctx.Params.Enterprises {
		if err := s.scanEnterprise(ctx, enterprise); err != nil {
			log.Error().
				Err(err).
				Str("enterprise", enterprise).
				Msg("Failed to scan enterprise")
			continue
		}
	}

	log.Info().Msg("Enterprise scan completed")
	return nil
}

func (s *EnterpriseScanStage) scanEnterprise(ctx *ScanContext, enterprise string) error {
	log.Info().Str("enterprise", enterprise).Msg("Scanning enterprise")

	scanner := scanners.NewEnterpriseScanner(ctx.GitHubGraphQLClient, ctx.GitHubClient, enterprise)
	data, err := scanner.ScanAll(ctx.Ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	ctx.Results[fmt.Sprintf("enterprise:%s", enterprise)] = data

	// Feed discovered org names into ctx.Params.Organizations so OrganizationScanStage picks them up.
	// Also record which enterprise owns each org in ctx.Ownership.
	orgNames := s.extractOrganizationNames(data)
	ctx.Params.Organizations = append(ctx.Params.Organizations, orgNames...)
	for _, orgName := range orgNames {
		ctx.Ownership[fmt.Sprintf("organization:%s", orgName)] = enterprise
	}

	log.Info().
		Str("enterprise", enterprise).
		Int("organizations_detected", len(data.Organizations)).
		Msg("Enterprise scan completed successfully")

	return nil
}

func (s *EnterpriseScanStage) extractOrganizationNames(data *scanners.EnterpriseData) []string {
	names := make([]string, 0, len(data.Organizations))
	for _, org := range data.Organizations {
		if org != nil && org.Login != nil {
			names = append(names, *org.Login)
		}
	}
	return names
}

func (s *EnterpriseScanStage) Skip(ctx *ScanContext) bool {
	if len(ctx.Params.Enterprises) == 0 {
		log.Info().Msg("Skipping enterprise scan - no enterprises specified (use --enterprise or -e flag)")
		return true
	}
	return false
}
