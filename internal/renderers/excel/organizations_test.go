// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package excel

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/scanners"
)

// defaultCodeSecurityConfigColumn is the index of the
// "Default Code Security Config (New Repos)" column in buildOrganizationsTable rows.
const defaultCodeSecurityConfigColumn = 8

func TestBuildOrganizationsTable_DefaultCodeSecurityConfig(t *testing.T) {
	withDefaults := &scanners.OrgCodeSecurityConfigurations{
		ConfigurationsReadable: true,
		Configurations:         []*github.CodeSecurityConfiguration{},
		DefaultsReadable:       true,
		DefaultConfigurations: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
			{DefaultForNewRepos: github.Ptr("public"), Configuration: &github.CodeSecurityConfiguration{Name: "Public baseline"}},
			{DefaultForNewRepos: github.Ptr("private_and_internal"), Configuration: &github.CodeSecurityConfiguration{Name: "GitHub recommended"}},
			{DefaultForNewRepos: github.Ptr("all")},
			nil,
		},
	}

	tests := []struct {
		name string
		csc  *scanners.OrgCodeSecurityConfigurations
		want string
	}{
		{name: "not collected", csc: nil, want: ""},
		{
			name: "not readable",
			csc:  &scanners.OrgCodeSecurityConfigurations{DefaultsUnavailableReason: scanners.CodeSecurityConfigUnavailableForbidden},
			want: "not readable (forbidden)",
		},
		{
			name: "readable without defaults",
			csc: &scanners.OrgCodeSecurityConfigurations{
				DefaultsReadable:      true,
				DefaultConfigurations: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{},
			},
			want: "none",
		},
		{
			name: "readable with defaults",
			csc:  withDefaults,
			want: "all: unknown; private_and_internal: GitHub recommended; public: Public baseline",
		},
	}

	for _, tt := range tests {
		org := &scanners.OrganizationData{Settings: &scanners.OrgSettings{
			Security: scanners.OrgSecurity{CodeSecurityConfigurations: tt.csc},
		}}

		// Replayed reports (--from-json) hold organizations as generic maps.
		raw, err := json.Marshal(org)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tt.name, err)
		}
		var replayed map[string]interface{}
		if err := json.Unmarshal(raw, &replayed); err != nil {
			t.Fatalf("%s: unmarshal: %v", tt.name, err)
		}

		for source, val := range map[string]interface{}{"live": org, "replay": replayed} {
			t.Run(tt.name+"/"+source, func(t *testing.T) {
				rows := buildOrganizationsTable(map[string]interface{}{"organization:acme": val})
				if len(rows) != 1 {
					t.Fatalf("rows = %d, want 1", len(rows))
				}
				if got := rows[0][defaultCodeSecurityConfigColumn]; got != tt.want {
					t.Errorf("default code security config = %q, want %q", got, tt.want)
				}
			})
		}
	}
}
