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
	log.Info().
		Int("count", len(ctx.Params.GHESInstances)).
		Msg("Starting GHES instance scan")

	var failures []string

	for _, hostname := range ctx.Params.GHESInstances {
		log.Info().Str("hostname", hostname).Msg("Scanning GHES instance")

		clients, err := config.NewClients(ctx.Ctx, config.WithGHES(hostname))
		if err != nil {
			log.Error().Err(err).Str("hostname", hostname).Msg("Failed to create GHES client")
			failures = append(failures, fmt.Sprintf("%s: %v", hostname, err))
			continue
		}
		ctx.Clients[hostname] = clients

		ctx.GraphQLClients[hostname] = scanners.NewGraphQLClient(clients.GraphQL, clients.HTTP, clients.GraphQLEndpoint)

		scanner := scanners.NewGHESScanner(clients.REST, hostname)
		data, err := scanner.ScanAll(ctx.Ctx)
		if err != nil {
			log.Error().Err(err).Str("hostname", hostname).Msg("Failed to scan GHES instance")
			failures = append(failures, fmt.Sprintf("%s: %v", hostname, err))
			continue
		}

		ctx.Results[fmt.Sprintf("ghes:%s", hostname)] = data

		log.Info().
			Str("hostname", hostname).
			Int("organizations", len(data.Organizations)).
			Msg("GHES instance scan completed successfully")
	}

	// If every requested instance failed, surface the errors so callers receive a
	// meaningful failure instead of a silent no-op that leaves no output file.
	if len(failures) > 0 && len(failures) == len(ctx.Params.GHESInstances) {
		return fmt.Errorf("all GHES instance scans failed: %s", strings.Join(failures, "; "))
	}

	log.Info().Msg("GHES instance scan completed")
	return nil
}

func (s *GHESScanStage) Skip(ctx *ScanContext) bool {
	// Replay mode: GHES data is loaded from disk by LoadFromJSONStage; live
	// API calls must not be made.
	if ctx.Params.IsReplay() {
		log.Debug().Msg("Skipping GHES scan - replaying from JSON")
		return true
	}
	if len(ctx.Params.GHESInstances) == 0 {
		log.Debug().Msg("Skipping GHES scan - no GHES instances specified (use --ghes flag)")
		return true
	}
	return false
}
