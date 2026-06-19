// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"net/http"

	"github.com/microsoft/ghqr/internal/config"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/rs/zerolog/log"
)

// InitializationStage handles initial setup for the scan.
type InitializationStage struct {
	*BaseStage
}

// NewInitializationStage creates a new initialization stage.
func NewInitializationStage() *InitializationStage {
	return &InitializationStage{
		BaseStage: NewBaseStage("initialization"),
	}
}

func (s *InitializationStage) Execute(ctx *ScanContext) error {
	log.Info().Msg("Initializing scan...")

	hostname := ctx.Params.Hostname

	clients, err := config.NewClients(ctx.Ctx, config.WithHostname(hostname))
	if err != nil {
		return fmt.Errorf("failed to create GitHub clients: %w", err)
	}
	ctx.Clients[primaryClientKey] = clients

	graphqlEndpoint := config.GraphQLEndpoint(hostname)
	ctx.GraphQLClients[primaryClientKey] = scanners.NewGraphQLClient(clients.GraphQL, clients.HTTP, graphqlEndpoint)

	user, resp, err := ctx.Clients[primaryClientKey].REST.Users.Get(ctx.Ctx, "")
	if err != nil {
		if resp != nil && isGitHubAppUserEndpointForbidden(resp.StatusCode) {
			log.Info().Msg("Authenticated to GitHub as App (installation token)")
			return nil
		}
		return fmt.Errorf("GitHub authentication failed: %w", err)
	}

	log.Info().Str("user", user.GetLogin()).Msg("Authenticated to GitHub")
	return nil
}

func isGitHubAppUserEndpointForbidden(statusCode int) bool {
	return statusCode == http.StatusForbidden
}

func (s *InitializationStage) Skip(ctx *ScanContext) bool {
	// Skip GitHub authentication and client setup when replaying from JSON or when no github.com targets are specified (i.e. GHES-only scan).
	return ctx.Params.IsReplay() || ctx.Params.IsGHESScan()
}
