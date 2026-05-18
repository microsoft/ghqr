// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/scanners"
)

// TestLoadFromJSONStage_GHES verifies that --from-json replay correctly
// loads the top-level "ghes" block into typed scanners.GHESData values
// keyed under ghes:<hostname>, strips the embedded evaluation field, and
// parses the tri-state *bool settings + "unlimited" license seats back
// into their native types. This is the regression for PR #84 review
// feedback that the replay loader was ignoring GHES objects entirely.
func TestLoadFromJSONStage_GHES(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	payload := `{
		"generated_at": "2026-04-17T14:34:26Z",
		"ghes": {
			"ghes.test.local": {
				"server_info": {
					"installed_version": "3.20.1",
					"hostname": "ghes.test.local",
					"verifiable_password_authentication": true
				},
				"license": {
					"seats": "unlimited",
					"seats_used": 2,
					"seats_available": "unlimited",
					"kind": "unlimited",
					"days_until_expiration": 230,
					"expire_at": "2027-01-01T23:59:59-08:00"
				},
				"settings": {
					"source": "manage_api",
					"private_mode": false,
					"subdomain_isolation": true
				},
				"feature_support": {
					"actions_api_available": true,
					"dependabot_api_available": false,
					"code_scanning_api_available": false,
					"secret_scanning_api_available": false
				},
				"organizations": ["alpha", "beta"],
				"evaluation": {"stale": true}
			}
		}
	}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	stage := NewLoadFromJSONStage()
	ctx := &ScanContext{
		Ctx:     context.Background(),
		Params:  &models.ScanParams{FromJSON: path},
		Results: map[string]interface{}{},
	}
	if err := stage.Execute(ctx); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	raw, ok := ctx.Results["ghes:ghes.test.local"]
	if !ok {
		t.Fatal("expected ghes:ghes.test.local result key")
	}
	data, ok := raw.(*scanners.GHESData)
	if !ok {
		t.Fatalf("expected *scanners.GHESData, got %T", raw)
	}

	if data.ServerInfo == nil || data.ServerInfo.InstalledVersion != "3.20.1" {
		t.Errorf("server info round-trip lost data: %+v", data.ServerInfo)
	}
	if data.License == nil || !data.License.Seats.Unlimited {
		t.Errorf("license seats should round-trip as Unlimited, got %+v", data.License)
	}
	if data.Settings == nil || data.Settings.PrivateMode == nil || *data.Settings.PrivateMode {
		t.Errorf("PrivateMode should be observed-false after round-trip, got %+v", data.Settings)
	}
	if data.Settings.SubdomainIsolation == nil || !*data.Settings.SubdomainIsolation {
		t.Errorf("SubdomainIsolation should be observed-true after round-trip, got %+v", data.Settings)
	}
	if data.FeatureSupport == nil || data.FeatureSupport.DependabotAPIAvailable {
		t.Errorf("FeatureSupport.DependabotAPIAvailable should be false, got %+v", data.FeatureSupport)
	}

	// The embedded "evaluation" field must be stripped on load (otherwise
	// replay would re-emit stale findings nested inside the new ones).
	roundTrip, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(roundTrip), `"stale"`) {
		t.Errorf("embedded evaluation should have been stripped: %s", roundTrip)
	}
}

// TestGHESScanStage_SkipOnReplay verifies the belt-and-braces guard: even
// if a future builder change reorders stages, GHESScanStage.Skip() returns
// true whenever FromJSON is set, so a replay run cannot accidentally issue
// live GHES API calls.
func TestGHESScanStage_SkipOnReplay(t *testing.T) {
	stage := NewGHESScanStage()

	replay := &ScanContext{Params: &models.ScanParams{
		FromJSON:      "snapshot.json",
		GHESInstances: []string{"ghes.example.com"},
	}}
	if !stage.Skip(replay) {
		t.Error("GHESScanStage.Skip() must return true when FromJSON is set, even if GHESInstances is also specified")
	}

	live := &ScanContext{Params: &models.ScanParams{
		GHESInstances: []string{"ghes.example.com"},
	}}
	if stage.Skip(live) {
		t.Error("GHESScanStage.Skip() should return false on a normal live run with GHESInstances set")
	}

	noInstances := &ScanContext{Params: &models.ScanParams{}}
	if !stage.Skip(noInstances) {
		t.Error("GHESScanStage.Skip() should return true when no GHESInstances are set")
	}
}
