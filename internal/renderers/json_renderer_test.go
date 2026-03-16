// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package renderers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustReadReport(t *testing.T, path string) ScanReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read report file: %v", err)
	}
	var r ScanReport
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	return r
}

func TestRenderJSON_HappyPath(t *testing.T) {
	dir := t.TempDir()
	outputName := filepath.Join(dir, "test_report")

	results := map[string]interface{}{
		"organization:my-org": map[string]interface{}{
			"login": "my-org",
			"plan":  "enterprise",
		},
		"repository:my-org/repo1": map[string]interface{}{
			"name":           "repo1",
			"default_branch": "main",
		},
	}

	outPath, err := RenderJSON(results, outputName)
	if err != nil {
		t.Fatalf("RenderJSON returned unexpected error: %v", err)
	}

	if outPath != outputName+".json" {
		t.Errorf("outPath = %q, want %q", outPath, outputName+".json")
	}

	report := mustReadReport(t, outPath)

	if _, ok := report.Organizations["my-org"]; !ok {
		t.Error("expected 'my-org' in organizations map")
	}

	if _, ok := report.Repositories["my-org/repo1"]; !ok {
		t.Error("expected 'my-org/repo1' in repositories map")
	}

	if report.GeneratedAt == "" {
		t.Error("expected generated_at to be set")
	}
}

func TestRenderJSON_EvaluationEmbedded(t *testing.T) {
	dir := t.TempDir()
	outputName := filepath.Join(dir, "eval_report")

	orgData := map[string]interface{}{"login": "eval-org"}
	evalData := map[string]interface{}{"score": 92}

	results := map[string]interface{}{
		"organization:eval-org":            orgData,
		"evaluation:organization:eval-org": evalData,
	}

	outPath, err := RenderJSON(results, outputName)
	if err != nil {
		t.Fatalf("RenderJSON returned unexpected error: %v", err)
	}

	report := mustReadReport(t, outPath)

	orgRaw, ok := report.Organizations["eval-org"]
	if !ok {
		t.Fatal("expected 'eval-org' in organizations")
	}

	orgMap, ok := orgRaw.(map[string]interface{})
	if !ok {
		t.Fatal("organization value should be a map")
	}

	if _, hasEval := orgMap["evaluation"]; !hasEval {
		t.Error("expected evaluation to be embedded in organization")
	}
}

func TestRenderJSON_WriteError(t *testing.T) {
	// Pass a path inside a non-existent directory hierarchy to force a write error.
	outputName := filepath.Join(t.TempDir(), "nonexistent", "nested", "dir", "report")

	_, err := RenderJSON(map[string]interface{}{}, outputName)
	if err == nil {
		t.Fatal("expected an error writing to a non-existent directory, got nil")
	}

	if !strings.Contains(err.Error(), "failed to write report") {
		t.Errorf("error message should mention 'failed to write report', got: %v", err)
	}
}

func TestRenderJSON_EmptyResults(t *testing.T) {
	dir := t.TempDir()
	outputName := filepath.Join(dir, "empty_report")

	outPath, err := RenderJSON(map[string]interface{}{}, outputName)
	if err != nil {
		t.Fatalf("RenderJSON with empty results returned error: %v", err)
	}

	mustReadReport(t, outPath)
}

func TestRenderJSON_CollaboratorSummary(t *testing.T) {
	dir := t.TempDir()
	outputName := filepath.Join(dir, "collab_report")

	results := map[string]interface{}{
		"repository:org/repo": map[string]interface{}{
			"collaborators": []interface{}{
				map[string]interface{}{"login": "user1", "permissions": "admin"},
				map[string]interface{}{"login": "user2", "permissions": "write"},
				map[string]interface{}{"login": "user3", "permissions": "write"},
			},
		},
	}

	outPath, err := RenderJSON(results, outputName)
	if err != nil {
		t.Fatalf("RenderJSON returned unexpected error: %v", err)
	}

	report := mustReadReport(t, outPath)

	repoRaw := report.Repositories["org/repo"]
	repoMap, ok := repoRaw.(map[string]interface{})
	if !ok {
		t.Fatal("repository value should be a map")
	}

	if _, hasCollabs := repoMap["collaborators"]; hasCollabs {
		t.Error("raw collaborators array should have been replaced by a summary")
	}

	summary, hasSummary := repoMap["collaborator_summary"]
	if !hasSummary {
		t.Fatal("expected collaborator_summary to be present")
	}

	summaryMap, ok := summary.(map[string]interface{})
	if !ok {
		t.Fatal("collaborator_summary should be a map")
	}

	if summaryMap["write"] != float64(2) {
		t.Errorf("expected write count = 2, got %v", summaryMap["write"])
	}
}
