// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package config

import "testing"

func TestIsCustomHost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{name: "empty string", hostname: "", want: false},
		{name: "github.com", hostname: "github.com", want: false},
		{name: "ghe.com subdomain", hostname: "mycompany.ghe.com", want: true},
		{name: "ghes instance", hostname: "github.example.com", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCustomHost(tt.hostname)
			if got != tt.want {
				t.Errorf("IsCustomHost(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestGraphQLEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "empty defaults to github.com", hostname: "", want: "https://api.github.com/graphql"},
		{name: "github.com", hostname: "github.com", want: "https://api.github.com/graphql"},
		{name: "ghe.com subdomain", hostname: "mycompany.ghe.com", want: "https://api.mycompany.ghe.com/graphql"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GraphQLEndpoint(tt.hostname)
			if got != tt.want {
				t.Errorf("GraphQLEndpoint(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestRESTBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "empty defaults to github.com", hostname: "", want: "https://api.github.com/"},
		{name: "github.com", hostname: "github.com", want: "https://api.github.com/"},
		{name: "ghe.com subdomain", hostname: "mycompany.ghe.com", want: "https://api.mycompany.ghe.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RESTBaseURL(tt.hostname)
			if got != tt.want {
				t.Errorf("RESTBaseURL(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestGHESToken_Precedence(t *testing.T) {
	// GH_TOKEN only -> returned as-is.
	t.Setenv("GH_TOKEN", "gh")
	t.Setenv("GITHUB_TOKEN", "")
	got, err := ghTokenForHost("github.com")
	if err != nil {
		t.Fatalf("ghTokenForHost() unexpected error: %v", err)
	}
	if got != "gh" {
		t.Errorf("ghTokenForHost() = %q, want %q", got, "gh")
	}

	// GH_TOKEN takes precedence over GITHUB_TOKEN.
	t.Setenv("GH_TOKEN", "gh")
	t.Setenv("GITHUB_TOKEN", "github")
	got, err = ghTokenForHost("github.com")
	if err != nil {
		t.Fatalf("ghTokenForHost() unexpected error: %v", err)
	}
	if got != "gh" {
		t.Errorf("ghTokenForHost() = %q, want %q (GH_TOKEN should win)", got, "gh")
	}

	// GITHUB_TOKEN only -> returned as fallback for github.com.
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "github")
	got, err = ghTokenForHost("github.com")
	if err != nil {
		t.Fatalf("ghTokenForHost() unexpected error: %v", err)
	}
	if got != "github" {
		t.Errorf("ghTokenForHost() = %q, want %q", got, "github")
	}

	// Nothing set for a fake host -> error (go-gh has no config for a fake host).
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "")
	if _, err = ghTokenForHost("no-such-host.example.com"); err == nil {
		t.Error("ghTokenForHost() expected error when no token is set, got nil")
	}
}

func TestGHESToken_GHESFallbackAcceptsGITHUB_TOKEN(t *testing.T) {
	// For non-github.com hosts go-gh does not use GITHUB_TOKEN (CVE-2024-53859
	// fix), but ghqr preserves it as an explicit backward-compat fallback.
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GH_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_ENTERPRISE_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "ghes-pat")

	got, err := ghTokenForHost("ghes.example.com")
	if err != nil {
		t.Fatalf("ghTokenForHost() unexpected error: %v", err)
	}
	if got != "ghes-pat" {
		t.Errorf("ghTokenForHost() = %q, want %q", got, "ghes-pat")
	}
}
