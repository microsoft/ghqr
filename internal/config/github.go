// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

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
	// via GH_TOKEN > GITHUB_TOKEN and the REST client is configured
	// via WithEnterpriseURLs against the given appliance URL.
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
// In GHES mode the token is resolved with GH_TOKEN > GITHUB_TOKEN precedence
// and the REST client is built with WithEnterpriseURLs.
// The GraphQL field of the returned Clients is nil; GHES does not use GraphQL
// in this tool.
func WithGHES(baseURL string) ClientOption {
	return func(o *clientOptions) { o.ghesBaseURL = baseURL }
}

// NewClients builds all three GitHub API clients from a single oauth2 + rate-limit
// transport. Use WithHostname to target a GHE.com Data Residency instance, or
// WithGHES to target a GitHub Enterprise Server appliance. Omit both options for
// standard GitHub.com.
// Returns an error when no token is found in the environment.
func NewClients(ctx context.Context, opts ...ClientOption) (*Clients, error) {
	o := &clientOptions{}
	for _, opt := range opts {
		opt(o)
	}

	if o.ghesBaseURL != "" {
		return newGHESClients(ctx, o.ghesBaseURL)
	}

	token, err := ghToken()
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

func ghToken() (string, error) {
	token := os.Getenv("GH_TOKEN")
	if token != "" {
		return token, nil
	}

	token = os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return "", fmt.Errorf("GitHub token not found: set GITHUB_TOKEN environment variable")
	}
	return token, nil
}
