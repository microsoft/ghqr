// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"errors"
	"testing"
)

func TestValidateScanTargets(t *testing.T) {
	cases := []struct {
		name      string
		fromJSON  string
		ents      []string
		orgs      []string
		repos     []string
		ghes      []string
		wantErr   error
		wantNoErr bool
	}{
		{
			name:    "no targets at all errors",
			wantErr: errNoScanTarget,
		},
		{
			name:      "enterprise only is valid",
			ents:      []string{"my-enterprise"},
			wantNoErr: true,
		},
		{
			name:      "organization only is valid",
			orgs:      []string{"my-org"},
			wantNoErr: true,
		},
		{
			name:      "repository only is valid",
			repos:     []string{"owner/repo"},
			wantNoErr: true,
		},
		{
			name:      "ghes only is valid",
			ghes:      []string{"ghes.example.com"},
			wantNoErr: true,
		},
		{
			name:      "from-json only is valid",
			fromJSON:  "report.json",
			wantNoErr: true,
		},
		{
			name:     "from-json with enterprise is rejected",
			fromJSON: "report.json",
			ents:     []string{"my-enterprise"},
			wantErr:  errFromJSONWithLiveTarget,
		},
		{
			name:     "from-json with organization is rejected",
			fromJSON: "report.json",
			orgs:     []string{"my-org"},
			wantErr:  errFromJSONWithLiveTarget,
		},
		{
			name:     "from-json with repository is rejected",
			fromJSON: "report.json",
			repos:    []string{"owner/repo"},
			wantErr:  errFromJSONWithLiveTarget,
		},
		{
			name:     "from-json with ghes is rejected",
			fromJSON: "report.json",
			ghes:     []string{"ghes.example.com"},
			wantErr:  errFromJSONWithLiveTarget,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := validateScanTargets(c.fromJSON, c.ents, c.orgs, c.repos, c.ghes)
			if c.wantNoErr {
				if got != nil {
					t.Fatalf("expected no error, got %v", got)
				}
				return
			}
			if !errors.Is(got, c.wantErr) {
				t.Fatalf("error = %v, want %v", got, c.wantErr)
			}
		})
	}
}
