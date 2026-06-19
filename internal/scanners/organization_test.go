// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package scanners

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v83/github"
)

func newOrganizationTestScanner(t *testing.T, handler http.Handler) (*OrganizationScanner, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	base, err := url.Parse(srv.URL + "/api/v3/")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	client := github.NewClient(nil)
	client.BaseURL = base
	client.UploadURL = base

	return NewOrganizationScanner(client, nil, "test-org"), srv
}

func TestScanSecurityAlerts_PaginatesAllPages(t *testing.T) {
	const pathPrefix = "/api/v3/orgs/test-org"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "open" {
			t.Fatalf("state query = %q, want open", r.URL.Query().Get("state"))
		}
		if r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("per_page query = %q, want 100", r.URL.Query().Get("per_page"))
		}

		switch {
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/dependabot/alerts"):
			if r.URL.Query().Get("page") != "" {
				t.Fatalf("dependabot request unexpectedly used page query: %s", r.URL.String())
			}
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", `<http://example.test?after=cursor-2>; rel="next"`)
				writeDependabotAlerts(t, w, 100, "critical")
				return
			}
			if after == "cursor-2" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{"security_advisory": map[string]string{"severity": "high"}},
					{"security_advisory": map[string]string{"severity": "critical"}},
					{"security_advisory": map[string]string{"severity": "low"}},
				})
				return
			}
			t.Fatalf("unexpected dependabot after cursor: %q", after)
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/code-scanning/alerts"):
			page := r.URL.Query().Get("page")
			if page == "" {
				t.Fatalf("code-scanning request missing page query: %s", r.URL.String())
			}
			if page == "1" {
				w.Header().Set("Link", `<http://example.test?page=2>; rel="next"`)
				writeEmptyObjects(t, w, 100)
				return
			}
			if page == "2" {
				writeEmptyObjects(t, w, 12)
				return
			}
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/secret-scanning/alerts"):
			page := r.URL.Query().Get("page")
			if page == "" {
				t.Fatalf("secret-scanning request missing page query: %s", r.URL.String())
			}
			if page == "1" {
				w.Header().Set("Link", `<http://example.test?page=2>; rel="next"`)
				writeEmptyObjects(t, w, 100)
				return
			}
			if page == "2" {
				w.Header().Set("Link", `<http://example.test?page=3>; rel="next"`)
				writeEmptyObjects(t, w, 50)
				return
			}
			if page == "3" {
				writeEmptyObjects(t, w, 1)
				return
			}
		}

		t.Fatalf("unexpected request: %s", r.URL.String())
	})

	scanner, _ := newOrganizationTestScanner(t, handler)

	alerts, err := scanner.scanSecurityAlerts(context.Background())
	if err != nil {
		t.Fatalf("scanSecurityAlerts: %v", err)
	}

	if !alerts.Available {
		t.Fatalf("Available = false, want true")
	}
	if alerts.OpenDependabotAlerts != 103 {
		t.Fatalf("OpenDependabotAlerts = %d, want 103", alerts.OpenDependabotAlerts)
	}
	if alerts.CriticalDependabot != 101 {
		t.Fatalf("CriticalDependabot = %d, want 101", alerts.CriticalDependabot)
	}
	if alerts.HighDependabot != 1 {
		t.Fatalf("HighDependabot = %d, want 1", alerts.HighDependabot)
	}
	if alerts.OpenCodeScanningAlerts != 112 {
		t.Fatalf("OpenCodeScanningAlerts = %d, want 112", alerts.OpenCodeScanningAlerts)
	}
	if alerts.OpenSecretScanningAlerts != 151 {
		t.Fatalf("OpenSecretScanningAlerts = %d, want 151", alerts.OpenSecretScanningAlerts)
	}
}

func TestScanSecurityAlerts_EscapesDependabotAfterCursor(t *testing.T) {
	const (
		pathPrefix     = "/api/v3/orgs/test-org"
		rawCursor      = "cursor with spaces&x=y"
		encodedCursor  = "cursor+with+spaces%26x%3Dy"
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/dependabot/alerts"):
			after := r.URL.Query().Get("after")
			if after == "" {
				w.Header().Set("Link", `<http://example.test?after=`+encodedCursor+`>; rel="next"`)
				writeDependabotAlerts(t, w, 1, "critical")
				return
			}
			if after != rawCursor {
				t.Fatalf("dependabot after = %q, want %q", after, rawCursor)
			}
			if !strings.Contains(r.URL.RawQuery, "after="+encodedCursor) {
				t.Fatalf("dependabot raw query did not contain encoded cursor: %s", r.URL.RawQuery)
			}
			writeDependabotAlerts(t, w, 1, "high")
			return
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/code-scanning/alerts"):
			writeEmptyObjects(t, w, 0)
			return
		case strings.HasSuffix(r.URL.Path, pathPrefix+"/secret-scanning/alerts"):
			writeEmptyObjects(t, w, 0)
			return
		}

		t.Fatalf("unexpected request: %s", r.URL.String())
	})

	scanner, _ := newOrganizationTestScanner(t, handler)
	alerts, err := scanner.scanSecurityAlerts(context.Background())
	if err != nil {
		t.Fatalf("scanSecurityAlerts: %v", err)
	}

	if alerts.OpenDependabotAlerts != 2 {
		t.Fatalf("OpenDependabotAlerts = %d, want 2", alerts.OpenDependabotAlerts)
	}
	if alerts.CriticalDependabot != 1 {
		t.Fatalf("CriticalDependabot = %d, want 1", alerts.CriticalDependabot)
	}
	if alerts.HighDependabot != 1 {
		t.Fatalf("HighDependabot = %d, want 1", alerts.HighDependabot)
	}
}

func writeDependabotAlerts(t *testing.T, w http.ResponseWriter, count int, severity string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	alerts := make([]map[string]any, count)
	for i := range count {
		alerts[i] = map[string]any{
			"security_advisory": map[string]string{
				"severity": severity,
			},
		}
	}
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		t.Fatalf("encode dependabot alerts: %v", err)
	}
}

func writeEmptyObjects(t *testing.T, w http.ResponseWriter, count int) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	alerts := make([]map[string]any, count)
	for i := range count {
		alerts[i] = map[string]any{}
	}
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		t.Fatalf("encode alerts: %v", err)
	}
}
