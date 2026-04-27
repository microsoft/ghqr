// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"

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

	clients, err := config.NewClients(ctx.Ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to create GitHub clients: %w", err)
	}
	ctx.Clients = clients

	graphqlEndpoint := config.GraphQLEndpoint(hostname)
	ctx.GraphQLScanner = scanners.NewGraphQLClient(clients.GraphQL, clients.HTTP, graphqlEndpoint)

	user, _, err := ctx.Clients.REST.Users.Get(ctx.Ctx, "")
	if err != nil {
		return fmt.Errorf("GitHub authentication failed: %w", err)
	}

	log.Info().Str("user", user.GetLogin()).Msg("Authenticated to GitHub")
	return nil
}

func (s *InitializationStage) Skip(ctx *ScanContext) bool {
	// Skip GitHub authentication and client setup when replaying from a JSON file.
	return ctx.Params != nil && ctx.Params.FromJSON != ""
}
