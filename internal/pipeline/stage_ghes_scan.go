// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/config"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// GHESScanStage handles scanning of GitHub Enterprise Server instances.
type GHESScanStage struct {
	*BaseStage
}

// NewGHESScanStage creates a new GHES scan stage.
func NewGHESScanStage() *GHESScanStage {
	return &GHESScanStage{
		BaseStage: NewBaseStage("ghes_scan"),
	}
}

func (s *GHESScanStage) Execute(ctx *ScanContext) error {
	if len(ctx.Params.GHESInstances) == 0 {
		log.Warn().Msg("No GHES instances specified for scanning")
		return nil
	}

	if ctx.GHESClients == nil {
		ctx.GHESClients = make(map[string]*github.Client)
	}

	log.Info().
		Int("count", len(ctx.Params.GHESInstances)).
		Msg("Starting GHES instance scan")

	for _, hostname := range ctx.Params.GHESInstances {
		if err := s.scanInstance(ctx, hostname); err != nil {
			log.Error().
				Err(err).
				Str("hostname", hostname).
				Msg("Failed to scan GHES instance")
			continue
		}
	}

	log.Info().Msg("GHES instance scan completed")
	return nil
}

func (s *GHESScanStage) scanInstance(ctx *ScanContext, hostname string) error {
	log.Info().Str("hostname", hostname).Msg("Scanning GHES instance")

	// Create GHES-specific API client
	restClient, _, err := config.GHESClients(ctx.Ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to create GHES client for %s: %w", hostname, err)
	}
	ctx.GHESClients[hostname] = restClient

	scanner := scanners.NewGHESScanner(restClient, hostname)
	data, err := scanner.ScanAll(ctx.Ctx)
	if err != nil {
		return fmt.Errorf("GHES scan failed for %s: %w", hostname, err)
	}

	ctx.Results[fmt.Sprintf("ghes:%s", hostname)] = data

	log.Info().
		Str("hostname", hostname).
		Int("organizations", len(data.Organizations)).
		Msg("GHES instance scan completed successfully")

	return nil
}

func (s *GHESScanStage) Skip(ctx *ScanContext) bool {
	if len(ctx.Params.GHESInstances) == 0 {
		log.Debug().Msg("Skipping GHES scan - no GHES instances specified (use --ghes flag)")
		return true
	}
	return false
}
