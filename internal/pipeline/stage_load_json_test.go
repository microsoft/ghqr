// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/microsoft/ghqr/internal/models"
)

func TestLoadFromJSONStage_Skip(t *testing.T) {
	stage := NewLoadFromJSONStage()

	ctxEmpty := &ScanContext{Params: &models.ScanParams{}}
	if !stage.Skip(ctxEmpty) {
		t.Fatal("expected Skip=true when FromJSON is empty")
	}

	ctxSet := &ScanContext{Params: &models.ScanParams{FromJSON: "x.json"}}
	if stage.Skip(ctxSet) {
		t.Fatal("expected Skip=false when FromJSON is set")
	}
}

func TestLoadFromJSONStage_Execute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	payload := `{
		"generated_at": "2026-04-17T14:34:26Z",
		"organizations": {
			"acme": {
				"settings": {"login": "acme"},
				"evaluation": {"stale": true},
				"copilot_evaluation": {"stale": true}
			}
		},
		"repositories": {
			"acme/widget": {
				"access": {"archived": false},
				"evaluation": {"stale": true},
				"collaborator_summary": {"admin": 2}
			}
		},
		"enterprises": {
			"acme-ent": {"slug": "acme-ent"}
		}
	}`
	if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	scanCtx := &ScanContext{
		Ctx:     context.Background(),
		Params:  &models.ScanParams{FromJSON: path},
		Results: map[string]interface{}{},
	}

	stage := NewLoadFromJSONStage()
	if err := stage.Execute(scanCtx); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	for _, key := range []string{"organization:acme", "repository:acme/widget", "enterprise:acme-ent"} {
		if _, ok := scanCtx.Results[key]; !ok {
			t.Errorf("missing key %q in Results", key)
		}
	}

	org := scanCtx.Results["organization:acme"].(map[string]interface{})
	if _, has := org["evaluation"]; has {
		t.Error("expected embedded 'evaluation' field to be stripped from organization")
	}
	if _, has := org["copilot_evaluation"]; has {
		t.Error("expected embedded 'copilot_evaluation' field to be stripped from organization")
	}

	repo := scanCtx.Results["repository:acme/widget"].(map[string]interface{})
	if _, has := repo["evaluation"]; has {
		t.Error("expected embedded 'evaluation' field to be stripped from repository")
	}
}

func TestLoadFromJSONStage_Execute_MissingFile(t *testing.T) {
	scanCtx := &ScanContext{
		Ctx:     context.Background(),
		Params:  &models.ScanParams{FromJSON: filepath.Join(t.TempDir(), "missing.json")},
		Results: map[string]interface{}{},
	}
	if err := NewLoadFromJSONStage().Execute(scanCtx); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromJSONStage_Execute_EmptyReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	scanCtx := &ScanContext{
		Ctx:     context.Background(),
		Params:  &models.ScanParams{FromJSON: path},
		Results: map[string]interface{}{},
	}
	if err := NewLoadFromJSONStage().Execute(scanCtx); err == nil {
		t.Fatal("expected error for empty report")
	}
}

func TestNewScanContext_ReplayOutputName(t *testing.T) {
	params := &models.ScanParams{FromJSON: "/tmp/myscan.json"}
	ctx := NewScanContext(params)
	if got := ctx.OutputName; len(got) == 0 || got[:len("myscan_replay_")] != "myscan_replay_" {
		t.Fatalf("expected output name to start with 'myscan_replay_', got %q", got)
	}
}
