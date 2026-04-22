// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestLogEnrichmentProgress(t *testing.T) {
	var output bytes.Buffer
	originalLogger := log.Logger
	log.Logger = zerolog.New(&output)
	t.Cleanup(func() {
		log.Logger = originalLogger
	})

	logEnrichmentProgress(2, 5, "octo-org", "octo-repo")

	logLine := strings.TrimSpace(output.String())
	if logLine == "" {
		t.Fatal("expected log output, got empty output")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(logLine), &entry); err != nil {
		t.Fatalf("expected JSON log line, got error: %v", err)
	}

	if entry["level"] != "info" {
		t.Fatalf("expected info level, got %v", entry["level"])
	}
	if entry["repository"] != "octo-org/octo-repo" {
		t.Fatalf("expected repository field, got %v", entry["repository"])
	}
	if entry["current"] != float64(2) {
		t.Fatalf("expected current=2, got %v", entry["current"])
	}
	if entry["total"] != float64(5) {
		t.Fatalf("expected total=5, got %v", entry["total"])
	}
	if entry["message"] != "Enriching repository 2 of 5: octo-org/octo-repo" {
		t.Fatalf("expected progress message, got %v", entry["message"])
	}
}
