// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/rs/zerolog/log"
)

// GHESClients creates REST and HTTP clients configured for a GitHub Enterprise
// Server instance. The baseURL should be the hostname (e.g. "ghes.example.com")
// or a full URL.
//
// Authentication uses the first non-empty of GHES_TOKEN, GH_TOKEN, or
// GITHUB_TOKEN. GHES_TOKEN takes precedence so an operator can authenticate to
// a GHES appliance without overwriting the credentials they already use for
// github.com.
//
// The HTTP transport is the same oauth2 + rateLimitTransport stack used by the
// github.com client built in NewClients. Centralising on that stack means GHES
// requests benefit from the same automatic backoff on x-ratelimit-remaining=0
// and on secondary rate-limit 403s — and prevents a future change to the
// shared retry policy from silently regressing on GHES.
func GHESClients(ctx context.Context, baseURL string) (*github.Client, *http.Client, error) {
	token := ghesToken()
	if token == "" {
		return nil, nil, fmt.Errorf("GHES token not found: set GHES_TOKEN, GH_TOKEN, or GITHUB_TOKEN environment variable")
	}

	apiURL, uploadURL, err := ghesEndpointURLs(baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid GHES URL %q: %w", baseURL, err)
	}

	httpClient := newAuthenticatedHTTPClient(ctx, token)

	restClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiURL, uploadURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GHES REST client for %s: %w", apiURL, err)
	}

	log.Debug().
		Str("api_url", apiURL).
		Str("upload_url", uploadURL).
		Msg("Created GHES API clients")
	return restClient, httpClient, nil
}

// ghesToken returns the GHES authentication token from environment variables.
// Precedence: GHES_TOKEN > GH_TOKEN > GITHUB_TOKEN. Documented in GHESClients.
func ghesToken() string {
	if token := os.Getenv("GHES_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	return os.Getenv("GITHUB_TOKEN")
}

// ghesEndpointURLs returns the REST API and upload URLs for a GHES instance.
// go-github's WithEnterpriseURLs requires the REST URL to end in /api/v3/ and
// the upload URL to end in /api/uploads/; passing the same URL to both leaves
// the upload client pointed at the wrong endpoint, which is why these are
// derived separately.
func ghesEndpointURLs(raw string) (apiURL, uploadURL string, err error) {
	apiURL, err = normalizeGHESURL(raw)
	if err != nil {
		return "", "", err
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", "", err
	}
	base := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api/v3")
	u.Path = base + "/api/uploads/"
	return apiURL, u.String(), nil
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
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/api/v3") {
		u.Path += "/api/v3/"
	} else {
		u.Path += "/"
	}
	return u.String(), nil
}
