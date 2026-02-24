// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// GitHubClients creates and returns a configured HTTP client and GraphQL client that share
// the same authentication and rate-limit retry transport.
// Use the returned *http.Client for raw HTTP requests (e.g. batch GraphQL queries).
func GitHubClients(ctx context.Context) (*http.Client, *githubv4.Client) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, nil
	}

	oauthTransport := oauth2.NewClient(
		ctx,
		oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
	).Transport

	httpClient := &http.Client{
		Transport: &rateLimitTransport{wrapped: oauthTransport},
	}
	return httpClient, githubv4.NewClient(httpClient)
}

// rateLimitTransport retries requests that hit GitHub rate limits.
// It distinguishes between:
//   - Secondary rate limits (retry-after header): retry after the specified delay.
//   - Primary rate limit exhaustion (x-ratelimit-remaining: 0): sleep until
//     the budget resets (x-ratelimit-reset), then retry once.
type rateLimitTransport struct {
	wrapped http.RoundTripper
}

const maxRateLimitRetries = 3

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt <= maxRateLimitRetries; attempt++ {
		// Clone the request body for each attempt (body is consumed on first read).
		cloned, err := cloneRequest(req)
		if err != nil {
			return nil, err
		}

		resp, err := t.wrapped.RoundTrip(cloned)
		if err != nil {
			return nil, err
		}

		// Not a rate limit response — return immediately.
		if resp.StatusCode != http.StatusForbidden {
			return resp, nil
		}

		// Give up after max retries regardless of the reason.
		if attempt == maxRateLimitRetries {
			return resp, nil
		}

		// Secondary or primary rate limit — wait and retry.
		if isSecondaryRateLimitResponse(resp) || isPrimaryRateLimitExhausted(resp) {
			wait := retryAfterDuration(resp)
			log.Warn().
				Int("attempt", attempt+1).
				Dur("wait", wait).
				Msg("Rate limit hit, retrying after wait")
			_ = resp.Body.Close()
			if err := waitForReset(req.Context(), wait); err != nil {
				return nil, err
			}
			continue
		}

		// Unknown 403 — return as-is.
		return resp, nil
	}
	return nil, nil // unreachable
}

// waitForReset blocks until the given duration elapses or the context is cancelled.
func waitForReset(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// isSecondaryRateLimitResponse returns true when the response is a secondary rate limit 403.
// Secondary rate limits are indicated by the presence of a retry-after header.
func isSecondaryRateLimitResponse(resp *http.Response) bool {
	return resp.StatusCode == http.StatusForbidden &&
		resp.Header.Get("retry-after") != ""
}

// isPrimaryRateLimitExhausted returns true when the hourly GraphQL budget is exhausted.
// GitHub signals this with a 403, x-ratelimit-remaining: 0, and x-ratelimit-reset.
func isPrimaryRateLimitExhausted(resp *http.Response) bool {
	return resp.StatusCode == http.StatusForbidden &&
		strings.EqualFold(resp.Header.Get("x-ratelimit-remaining"), "0")
}

// retryAfterDuration reads the retry-after or x-ratelimit-reset header and returns
// how long to wait. Falls back to 60 seconds as recommended by GitHub docs.
func retryAfterDuration(resp *http.Response) time.Duration {
	if v := resp.Header.Get("retry-after"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	if v := resp.Header.Get("x-ratelimit-reset"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(epoch, 0)); d > 0 {
				return d
			}
		}
	}
	return 60 * time.Second
}

// cloneRequest creates a shallow clone of req with a fresh GetBody-derived body
// so the same request can be retried after the body has been consumed.
func cloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}
