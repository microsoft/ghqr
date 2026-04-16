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
