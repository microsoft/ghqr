// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// newAuthenticatedHTTPClient wraps an oauth2 static-token transport with the
// shared rate-limit-aware transport so both github.com and GHES requests get
// identical retry semantics. Centralising the constructor here means a
// future change to the transport stack (additional retries, telemetry,
// proxy support) automatically applies to both code paths.
func newAuthenticatedHTTPClient(ctx context.Context, token string) *http.Client {
	oauthTransport := oauth2.NewClient(
		ctx,
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	).Transport
	return &http.Client{
		Transport: &rateLimitTransport{wrapped: oauthTransport},
	}
}
