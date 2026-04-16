// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/config"
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

	token := getGitHubToken()
	if token == "" {
		return fmt.Errorf("GitHub token not found: set GH_TOKEN or GITHUB_TOKEN environment variable")
	}

	hostname := ctx.Params.Hostname

	// Create REST API client
	httpClient := &http.Client{
		Transport: &tokenTransport{token: token},
	}
	ctx.GitHubClient = github.NewClient(httpClient)

	if config.IsCustomHost(hostname) {
		baseURL, _ := url.Parse(config.RESTBaseURL(hostname))
		ctx.GitHubClient.BaseURL = baseURL
		log.Info().Str("hostname", hostname).Msg("Using custom GitHub hostname")
	}

	// Create GraphQL client (and keep the underlying HTTP client for batch queries).
	ctx.GitHubRawHTTPClient, ctx.GitHubGraphQLClient = config.GitHubClients(ctx.Ctx, hostname)

	user, _, err := ctx.GitHubClient.Users.Get(ctx.Ctx, "")
	if err != nil {
		return fmt.Errorf("GitHub authentication failed: %w", err)
	}

	log.Info().Str("user", user.GetLogin()).Msg("Authenticated to GitHub")
	return nil
}

// tokenTransport injects the Bearer token into every request.
type tokenTransport struct {
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}

func (s *InitializationStage) Skip(ctx *ScanContext) bool {
	return false
}

// getGitHubToken retrieves the GitHub token from environment variables
func getGitHubToken() string {
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	return os.Getenv("GITHUB_TOKEN")
}
