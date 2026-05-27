// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeGHESURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare hostname", "ghes.example.com", "https://ghes.example.com/api/v3/"},
		{"https hostname", "https://ghes.example.com", "https://ghes.example.com/api/v3/"},
		{"hostname with trailing slash", "https://ghes.example.com/", "https://ghes.example.com/api/v3/"},
		{"already has api/v3", "https://ghes.example.com/api/v3", "https://ghes.example.com/api/v3/"},
		{"already has api/v3 with slash", "https://ghes.example.com/api/v3/", "https://ghes.example.com/api/v3/"},
		{"hostname with port", "https://ghes.example.com:8443", "https://ghes.example.com:8443/api/v3/"},
		{"http scheme preserved (lab use)", "http://ghes.test:8080", "http://ghes.test:8080/api/v3/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeGHESURL(c.in)
			if err != nil {
				t.Fatalf("normalizeGHESURL(%q) error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("normalizeGHESURL(%q) = %q, want %q", c.in, got, c.want)
			}
			if _, err := url.Parse(got); err != nil {
				t.Errorf("output %q is not a valid URL: %v", got, err)
			}
			if !strings.HasSuffix(got, "/api/v3/") {
				t.Errorf("output %q does not end with /api/v3/ (go-github expectation)", got)
			}
		})
	}
}

// TestGHESClients_BuildsClientWithCorrectBaseURL verifies the go-github
// WithEnterpriseURLs(apiURL, apiURL) pattern actually configures the client
// to hit /api/v3/<endpoint> on the given host. PR review asked whether
// passing the same URL as both REST and upload URL is correct — this test
// locks that assumption in by exercising a real round trip.
func TestGHESClients_BuildsClientWithCorrectBaseURL(t *testing.T) {
	gotPath := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotPath <- r.URL.Path:
		default:
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	t.Setenv("GH_TOKEN", "test-token")

	clients, err := NewClients(context.Background(), WithGHES(srv.URL))
	if err != nil {
		t.Fatalf("NewClients(WithGHES): %v", err)
	}
	rest := clients.REST

	req, err := rest.NewRequest("GET", "meta", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := rest.Do(context.Background(), req, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}

	path := <-gotPath
	wantPath := "/api/v3/meta"
	if path != wantPath {
		t.Errorf("request hit %q, want %q (WithEnterpriseURLs misconfigured)", path, wantPath)
	}

	// Upload URL must resolve to /api/uploads/ on the same host (go-github
	// expects the upload endpoint to be /api/uploads/, NOT /api/v3/). This
	// locks in the fix for the WithEnterpriseURLs(api, api) bug raised in
	// PR review — passing the same URL silently misconfigures uploads.
	if rest.UploadURL == nil || rest.BaseURL == nil {
		t.Fatal("rest client has nil BaseURL or UploadURL")
	}
	if !strings.HasSuffix(rest.BaseURL.Path, "/api/v3/") {
		t.Errorf("BaseURL %q should end with /api/v3/", rest.BaseURL.Path)
	}
	if !strings.HasSuffix(rest.UploadURL.Path, "/api/uploads/") {
		t.Errorf("UploadURL %q should end with /api/uploads/ (go-github expectation)", rest.UploadURL.Path)
	}
	if rest.BaseURL.Host != rest.UploadURL.Host {
		t.Errorf("BaseURL host %q != UploadURL host %q", rest.BaseURL.Host, rest.UploadURL.Host)
	}
}

func TestGHESEndpointURLs(t *testing.T) {
	cases := []struct {
		in          string
		wantAPI     string
		wantUpload  string
		wantGraphQL string
	}{
		{"ghes.example.com", "https://ghes.example.com/api/v3/", "https://ghes.example.com/api/uploads/", "https://ghes.example.com/api/graphql"},
		{"https://ghes.example.com", "https://ghes.example.com/api/v3/", "https://ghes.example.com/api/uploads/", "https://ghes.example.com/api/graphql"},
		{"https://ghes.example.com/", "https://ghes.example.com/api/v3/", "https://ghes.example.com/api/uploads/", "https://ghes.example.com/api/graphql"},
		{"https://ghes.example.com/api/v3/", "https://ghes.example.com/api/v3/", "https://ghes.example.com/api/uploads/", "https://ghes.example.com/api/graphql"},
		{"https://ghes.example.com:8443", "https://ghes.example.com:8443/api/v3/", "https://ghes.example.com:8443/api/uploads/", "https://ghes.example.com:8443/api/graphql"},
		{"http://ghes.test:8080", "http://ghes.test:8080/api/v3/", "http://ghes.test:8080/api/uploads/", "http://ghes.test:8080/api/graphql"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			gotAPI, gotUpload, gotGraphQL, err := ghesEndpointURLs(c.in)
			if err != nil {
				t.Fatalf("ghesEndpointURLs(%q): %v", c.in, err)
			}
			if gotAPI != c.wantAPI {
				t.Errorf("api = %q, want %q", gotAPI, c.wantAPI)
			}
			if gotUpload != c.wantUpload {
				t.Errorf("upload = %q, want %q", gotUpload, c.wantUpload)
			}
			if gotGraphQL != c.wantGraphQL {
				t.Errorf("graphql = %q, want %q", gotGraphQL, c.wantGraphQL)
			}
		})
	}
}
