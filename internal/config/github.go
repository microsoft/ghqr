// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v83/github"
	"github.com/shurcooL/githubv4"
)

// Clients holds the three GitHub API clients that share a single authenticated,
// rate-limit-aware HTTP transport. Build once via NewClients and reuse everywhere.
type Clients struct {
	// HTTP is the shared authenticated transport. Use for raw HTTP calls (e.g. batch GraphQL).
	HTTP *http.Client
	// GraphQL is the githubv4 client for typed GraphQL queries.
	GraphQL *githubv4.Client
	// REST is the go-github client for REST API calls.
	REST *github.Client
	// GraphQLEndpoint is the full GraphQL API URL for this instance.
	GraphQLEndpoint string
}

// ClientOption configures the behaviour of NewClients.
type ClientOption func(*clientOptions)

type clientOptions struct {
	// hostname is the GitHub hostname for GHE.com Data Residency (e.g. "mycompany.ghe.com").
	// Leave empty for standard GitHub.com.
	hostname string
	// ghesBaseURL, when non-empty, enables GHES mode: the token is resolved
	// via the credential chain (gh CLI config, GH_TOKEN, GITHUB_TOKEN) and
	// the REST client is configured via WithEnterpriseURLs against the given
	// appliance URL.
	ghesBaseURL string
}

// WithHostname configures NewClients to target a GHE.com Data Residency instance
// at the given hostname (e.g. "mycompany.ghe.com"). Pass "" or omit for standard
// GitHub.com.
func WithHostname(hostname string) ClientOption {
	return func(o *clientOptions) { o.hostname = hostname }
}

// WithGHES configures NewClients to connect to a GitHub Enterprise Server
// appliance at baseURL (e.g. "ghes.example.com" or "https://ghes.example.com").
// In GHES mode the token is resolved via the credential chain (GH_TOKEN env var →
// gh CLI config → system keyring; GITHUB_TOKEN is also accepted as a backward-compat
// fallback) and the REST client is built with WithEnterpriseURLs.
func WithGHES(baseURL string) ClientOption {
	return func(o *clientOptions) { o.ghesBaseURL = baseURL }
}

// NewClients builds all three GitHub API clients from a single oauth2 + rate-limit
// transport. Use WithHostname to target a GHE.com Data Residency instance, or
// WithGHES to target a GitHub Enterprise Server appliance. Omit both options for
// standard GitHub.com.
// Returns an error when no token is found via the credential chain.
func NewClients(ctx context.Context, opts ...ClientOption) (*Clients, error) {
	o := &clientOptions{}
	for _, opt := range opts {
		opt(o)
	}

	if o.ghesBaseURL != "" {
		return newGHESClients(ctx, o.ghesBaseURL)
	}

	hostname := o.hostname
	if !IsCustomHost(hostname) {
		hostname = "github.com"
	}

	token, err := ghTokenForHost(hostname)
	if err != nil {
		return nil, err
	}

	httpClient := newAuthenticatedHTTPClient(ctx, token)

	var graphqlClient *githubv4.Client
	if IsCustomHost(o.hostname) {
		graphqlURL := "https://api." + o.hostname + "/graphql"
		graphqlClient = githubv4.NewEnterpriseClient(graphqlURL, httpClient)
	} else {
		graphqlClient = githubv4.NewClient(httpClient)
	}

	restClient := github.NewClient(httpClient)
	if IsCustomHost(o.hostname) {
		baseURL, err := url.Parse(RESTBaseURL(o.hostname))
		if err != nil {
			return nil, fmt.Errorf("invalid REST base URL for hostname %q: %w", o.hostname, err)
		}
		restClient.BaseURL = baseURL
	}

	return &Clients{
		HTTP:            httpClient,
		GraphQL:         graphqlClient,
		REST:            restClient,
		GraphQLEndpoint: GraphQLEndpoint(o.hostname),
	}, nil
}

// IsCustomHost returns true when the hostname refers to a non-default GitHub instance
// (e.g. a GHE.com Data Residency subdomain).
func IsCustomHost(hostname string) bool {
	return hostname != "" && hostname != "github.com"
}

// GraphQLEndpoint returns the GraphQL API endpoint for the given hostname.
func GraphQLEndpoint(hostname string) string {
	if IsCustomHost(hostname) {
		return "https://api." + hostname + "/graphql"
	}
	return "https://api.github.com/graphql"
}

// RESTBaseURL returns the REST API base URL for the given hostname.
func RESTBaseURL(hostname string) string {
	if IsCustomHost(hostname) {
		return "https://api." + hostname + "/"
	}
	return "https://api.github.com/"
}

// ghTokenForHost resolves a GitHub authentication token for the given hostname
// using a credential chain:
//  1. GH_TOKEN env var (all hosts — ghqr convention, highest priority)
//  2. GITHUB_TOKEN env var (all hosts — backward compat; note: go-gh scopes
//     this to github.com/ghe.com only per CVE-2024-53859, but ghqr accepts it
//     for GHES to avoid breaking existing workflows)
//  3. gh CLI config file / system keyring via auth.TokenForHost (new!)
//     This also picks up GH_ENTERPRISE_TOKEN / GITHUB_ENTERPRISE_TOKEN for GHES.
func ghTokenForHost(hostname string) (string, error) {
	// Check GH_TOKEN first — highest priority across all hosts.
	if t := os.Getenv("GH_TOKEN"); t != "" {
		return t, nil
	}

	// Check GITHUB_TOKEN for all hosts to preserve existing GHES behavior.
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t, nil
	}

	// Fall back to gh CLI config, system keyring, and enterprise env vars
	// (GH_ENTERPRISE_TOKEN / GITHUB_ENTERPRISE_TOKEN for GHES hosts).
	if token, _ := auth.TokenForHost(hostname); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("GitHub token not found for %q: run 'gh auth login --hostname %s', or set GH_TOKEN or GITHUB_TOKEN", hostname, hostname)
}
