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

	logEnrichmentProgress(2, 5, "octo-org/octo-repo")

	logLine := strings.TrimSpace(output.String())
	if logLine == "" {
		t.Fatal("expected log output, got empty output")
	}

	var logEntry map[string]any
	if err := json.Unmarshal([]byte(logLine), &logEntry); err != nil {
		t.Fatalf("expected JSON log line, got error: %v", err)
	}

	if logEntry["level"] != "info" {
		t.Fatalf("expected info level, got %v", logEntry["level"])
	}
	if logEntry["repository"] != "octo-org/octo-repo" {
		t.Fatalf("expected repository field, got %v", logEntry["repository"])
	}
	if logEntry["current"] != float64(2) {
		t.Fatalf("expected current=2, got %v", logEntry["current"])
	}
	if logEntry["total"] != float64(5) {
		t.Fatalf("expected total=5, got %v", logEntry["total"])
	}
	if logEntry["message"] != "Enriching repository 2 of 5: octo-org/octo-repo" {
		t.Fatalf("expected progress message, got %v", logEntry["message"])
	}
}
