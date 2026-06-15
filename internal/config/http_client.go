// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// sharedTransport is the single HTTP transport shared by all authenticated clients.
// Sharing the transport means all GitHub API callers reuse the same TCP/TLS
// connection pool, eliminating repeated TLS handshakes on every client creation.
// MaxIdleConnsPerHost is raised from Go's default of 2 to allow enough warm
// connections for concurrent GraphQL and REST requests (up to 10 ruleset workers).
var sharedTransport = &http.Transport{
	MaxIdleConns:        200,
	MaxIdleConnsPerHost: 50,
	IdleConnTimeout:     90 * time.Second,
	ForceAttemptHTTP2:   true,
}

// newAuthenticatedHTTPClient wraps an oauth2 static-token transport with the
// shared rate-limit-aware transport so both github.com and GHES requests get
// identical retry semantics. Centralising the constructor here means a
// future change to the transport stack (additional retries, telemetry,
// proxy support) automatically applies to both code paths.
func newAuthenticatedHTTPClient(_ context.Context, token string) *http.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	oauthTransport := &oauth2.Transport{
		Source: ts,
		Base:   sharedTransport,
	}
	return &http.Client{
		Transport: &rateLimitTransport{wrapped: oauthTransport},
	}
}
