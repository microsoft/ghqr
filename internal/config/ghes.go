// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
)

// newGHESClients is the GHES-specific implementation called when NewClients
// receives a WithGHES option. It uses the same oauth2 + rateLimitTransport
// stack so GHES requests benefit from identical backoff behaviour.
func newGHESClients(ctx context.Context, baseURL string) (*Clients, error) {
	token, err := ghToken()
	if err != nil {
		return nil, fmt.Errorf("GHES token not found: set GH_TOKEN or GITHUB_TOKEN environment variable")
	}

	apiURL, uploadURL, graphqlURL, err := ghesEndpointURLs(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid GHES URL %q: %w", baseURL, err)
	}

	httpClient := newAuthenticatedHTTPClient(ctx, token)

	restClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiURL, uploadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create GHES REST client for %s: %w", apiURL, err)
	}

	graphqlClient := githubv4.NewEnterpriseClient(graphqlURL, httpClient)

	log.Debug().
		Str("api_url", apiURL).
		Str("upload_url", uploadURL).
		Str("graphql_url", graphqlURL).
		Msg("Created GHES API clients")

	return &Clients{
		HTTP:            httpClient,
		REST:            restClient,
		GraphQL:         graphqlClient,
		GraphQLEndpoint: graphqlURL,
	}, nil
}

// ghesEndpointURLs returns the REST API, upload, and GraphQL URLs for a GHES instance.
// go-github's WithEnterpriseURLs requires the REST URL to end in /api/v3/ and
// the upload URL to end in /api/uploads/; passing the same URL to both leaves
// the upload client pointed at the wrong endpoint, which is why these are
// derived separately.
func ghesEndpointURLs(raw string) (apiURL, uploadURL, graphqlURL string, err error) {
	apiURL, err = normalizeGHESURL(raw)
	if err != nil {
		return "", "", "", err
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", "", "", err
	}
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v3")
	u.Path = base + "/api/uploads/"
	graphqlURL = u.Scheme + "://" + u.Host + "/api/graphql"
	return apiURL, u.String(), graphqlURL, nil
}

// normalizeGHESURL ensures the GHES URL ends with /api/v3/ for the REST API.
func normalizeGHESURL(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v3") + "/api/v3/"
	return u.String(), nil
}
