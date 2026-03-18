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

// GHESClients creates REST and HTTP clients configured for a GitHub Enterprise Server instance.
// The baseURL should be the hostname (e.g. "ghes.example.com") or a full URL.
// Authentication uses the GHES_TOKEN environment variable (falls back to GITHUB_TOKEN).
func GHESClients(ctx context.Context, baseURL string) (*github.Client, *http.Client, error) {
	token := ghesToken()
	if token == "" {
		return nil, nil, fmt.Errorf("GHES token not found: set GHES_TOKEN or GITHUB_TOKEN environment variable")
	}

	apiURL, err := normalizeGHESURL(baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid GHES URL %q: %w", baseURL, err)
	}

	httpClient := &http.Client{
		Transport: &ghesTokenTransport{token: token},
	}

	restClient, err := github.NewClient(httpClient).WithEnterpriseURLs(apiURL, apiURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GHES REST client for %s: %w", apiURL, err)
	}

	log.Debug().Str("base_url", apiURL).Msg("Created GHES API clients")
	return restClient, httpClient, nil
}

// ghesToken returns the GHES authentication token from environment variables.
func ghesToken() string {
	if token := os.Getenv("GHES_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	return os.Getenv("GITHUB_TOKEN")
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
	// Ensure path ends with /api/v3/
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/api/v3") {
		u.Path += "/api/v3/"
	} else {
		u.Path += "/"
	}
	return u.String(), nil
}

// ghesTokenTransport injects the Bearer token into every GHES request.
type ghesTokenTransport struct {
	token string
}

func (t *ghesTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}
