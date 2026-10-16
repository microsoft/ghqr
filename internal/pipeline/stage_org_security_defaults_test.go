// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/renderers"
	"github.com/microsoft/ghqr/internal/scanners"
	"github.com/microsoft/ghqr/internal/scanners/bestpractices"
)

const orgSecurityDefaultsKey = "evaluation:org_security_defaults:acme"

// A live scan and a --from-json replay of its output must yield identical org-def-*
// findings, and the rendered JSON must expose them as org_security_defaults_evaluation.
func TestOrgSecurityDefaults_LiveAndReplayParity(t *testing.T) {
	cfg := &github.CodeSecurityConfiguration{
		Name:                          "GitHub recommended",
		TargetType:                    github.Ptr("global"),
		AdvancedSecurity:              github.Ptr("enabled"),
		DependabotAlerts:              github.Ptr("enabled"),
		DependabotSecurityUpdates:     github.Ptr("not_set"),
		DependencyGraph:               github.Ptr("enabled"),
		SecretScanning:                github.Ptr("enabled"),
		SecretScanningPushProtection:  github.Ptr("enabled"),
		PrivateVulnerabilityReporting: github.Ptr("enabled"),
	}
	org := &scanners.OrganizationData{
		Settings: &scanners.OrgSettings{Security: scanners.OrgSecurity{
			CodeSecurityConfigurations: &scanners.OrgCodeSecurityConfigurations{
				DefaultsReadable: true,
				DefaultConfigurations: []*github.CodeSecurityConfigurationWithDefaultForNewRepos{
					{DefaultForNewRepos: github.Ptr("public"), Configuration: cfg},
				},
			},
		}},
	}

	stage := NewEvaluationStage()
	live := &ScanContext{Ctx: context.Background(), Params: &models.ScanParams{}, Results: map[string]interface{}{"organization:acme": org}}
	if err := stage.Execute(live); err != nil {
		t.Fatalf("live evaluation: %v", err)
	}
	liveResult, ok := live.Results[orgSecurityDefaultsKey].(*bestpractices.EvaluationResult)
	if !ok || len(liveResult.Recommendations) == 0 {
		t.Fatalf("expected org-def-* findings from live evaluation, got %#v", live.Results[orgSecurityDefaultsKey])
	}

	outPath, err := renderers.RenderJSON(live.Results, filepath.Join(t.TempDir(), "report"))
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report struct {
		Organizations map[string]map[string]json.RawMessage `json:"organizations"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if _, has := report.Organizations["acme"]["org_security_defaults_evaluation"]; !has {
		t.Fatal("expected org_security_defaults_evaluation in rendered JSON")
	}

	replay := &ScanContext{Ctx: context.Background(), Params: &models.ScanParams{FromJSON: outPath}, Results: map[string]interface{}{}}
	if err := NewLoadFromJSONStage().Execute(replay); err != nil {
		t.Fatalf("load replay: %v", err)
	}
	loaded := replay.Results["organization:acme"].(map[string]interface{})
	if _, has := loaded["org_security_defaults_evaluation"]; has {
		t.Fatal("expected org_security_defaults_evaluation to be stripped on replay")
	}
	if err := stage.Execute(replay); err != nil {
		t.Fatalf("replay evaluation: %v", err)
	}
	replayResult := replay.Results[orgSecurityDefaultsKey].(*bestpractices.EvaluationResult)
	if !reflect.DeepEqual(replayResult.Recommendations, liveResult.Recommendations) {
		t.Errorf("replay findings differ from live findings:\nlive:   %+v\nreplay: %+v", liveResult.Recommendations, replayResult.Recommendations)
	}
}
