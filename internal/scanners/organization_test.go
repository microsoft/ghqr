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
		pathPrefix    = "/api/v3/orgs/test-org"
		rawCursor     = "cursor with spaces&x=y"
		encodedCursor = "cursor+with+spaces%26x%3Dy"
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

const (
	codeSecurityConfigsPath  = "/api/v3/orgs/test-org/code-security/configurations"
	codeSecurityDefaultsPath = "/api/v3/orgs/test-org/code-security/configurations/defaults"
)

type httpStep func(t *testing.T, w http.ResponseWriter, r *http.Request)

func respondJSON(body any) httpStep {
	return func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		writeJSON(t, w, http.StatusOK, body)
	}
}

func respondStatus(status int) httpStep {
	return func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		writeJSON(t, w, status, map[string]string{"message": http.StatusText(status)})
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func codeSecurityConfig(id int64, name string) map[string]any {
	return map[string]any{
		"id":                              id,
		"name":                            name,
		"target_type":                     "organization",
		"advanced_security":               "enabled",
		"dependency_graph":                "enabled",
		"dependabot_alerts":               "enabled",
		"dependabot_security_updates":     "enabled",
		"secret_scanning":                 "enabled",
		"secret_scanning_push_protection": "enabled",
		"secret_scanning_delegated_bypass_options": map[string]any{
			"reviewers": []map[string]any{{"reviewer_id": 7, "reviewer_type": "TEAM"}},
		},
		"enforcement": "enforced",
	}
}

func TestScanCodeSecurityConfigurations(t *testing.T) {
	const (
		rawCursor     = "cursor with spaces&x=y"
		encodedCursor = "cursor+with+spaces%26x%3Dy"
	)

	paginatedList := func(t *testing.T, w http.ResponseWriter, r *http.Request) {
		t.Helper()
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q, want 100", got)
		}
		switch after := r.URL.Query().Get("after"); after {
		case "":
			w.Header().Set("Link", `<http://example.test?after=`+encodedCursor+`>; rel="next"`)
			writeJSON(t, w, http.StatusOK, []any{codeSecurityConfig(1, "GitHub recommended"), codeSecurityConfig(2, "Custom")})
		case rawCursor:
			writeJSON(t, w, http.StatusOK, []any{codeSecurityConfig(3, "Legacy")})
		default:
			t.Errorf("unexpected after cursor %q", after)
			writeJSON(t, w, http.StatusBadRequest, map[string]string{"message": "bad cursor"})
		}
	}

	failingSecondPage := func(t *testing.T, w http.ResponseWriter, r *http.Request) {
		t.Helper()
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<http://example.test?after=next>; rel="next"`)
			writeJSON(t, w, http.StatusOK, []any{codeSecurityConfig(1, "First")})
			return
		}
		writeJSON(t, w, http.StatusForbidden, map[string]string{"message": "Forbidden"})
	}

	repeatingCursor := func(t *testing.T, w http.ResponseWriter, _ *http.Request) {
		t.Helper()
		w.Header().Set("Link", `<http://example.test?after=same>; rel="next"`)
		writeJSON(t, w, http.StatusOK, []any{codeSecurityConfig(1, "Loop")})
	}

	twoDefaults := respondJSON([]any{
		map[string]any{"default_for_new_repos": "public", "configuration": codeSecurityConfig(1, "GitHub recommended")},
		map[string]any{"default_for_new_repos": "private_and_internal", "configuration": codeSecurityConfig(2, "Custom")},
	})

	tests := []struct {
		name                  string
		list                  httpStep
		defaults              httpStep
		wantConfigsReadable   bool
		wantConfigsReason     string
		wantConfigIDs         []int64
		wantDefaultsReadable  bool
		wantDefaultsReason    string
		wantDefaultScopes     []string
		wantDefaultConfigName []string
	}{
		{
			name:                  "readable with cursor pagination and defaults",
			list:                  paginatedList,
			defaults:              twoDefaults,
			wantConfigsReadable:   true,
			wantConfigIDs:         []int64{1, 2, 3},
			wantDefaultsReadable:  true,
			wantDefaultScopes:     []string{"public", "private_and_internal"},
			wantDefaultConfigName: []string{"GitHub recommended", "Custom"},
		},
		{
			name:                 "readable but nothing configured",
			list:                 respondJSON([]any{}),
			defaults:             respondJSON([]any{}),
			wantConfigsReadable:  true,
			wantConfigIDs:        []int64{},
			wantDefaultsReadable: true,
			wantDefaultScopes:    []string{},
		},
		{
			name:               "both forbidden",
			list:               respondStatus(http.StatusForbidden),
			defaults:           respondStatus(http.StatusForbidden),
			wantConfigsReason:  CodeSecurityConfigUnavailableForbidden,
			wantDefaultsReason: CodeSecurityConfigUnavailableForbidden,
		},
		{
			name:                  "list not found while defaults readable",
			list:                  respondStatus(http.StatusNotFound),
			defaults:              twoDefaults,
			wantConfigsReason:     CodeSecurityConfigUnavailableNotFound,
			wantDefaultsReadable:  true,
			wantDefaultScopes:     []string{"public", "private_and_internal"},
			wantDefaultConfigName: []string{"GitHub recommended", "Custom"},
		},
		{
			name:                "list readable while defaults forbidden",
			list:                respondJSON([]any{codeSecurityConfig(9, "Only")}),
			defaults:            respondStatus(http.StatusForbidden),
			wantConfigsReadable: true,
			wantConfigIDs:       []int64{9},
			wantDefaultsReason:  CodeSecurityConfigUnavailableForbidden,
		},
		{
			name:               "server errors",
			list:               respondStatus(http.StatusInternalServerError),
			defaults:           respondStatus(http.StatusBadGateway),
			wantConfigsReason:  CodeSecurityConfigUnavailableError,
			wantDefaultsReason: CodeSecurityConfigUnavailableError,
		},
		{
			name:                 "failure on second page discards partial list",
			list:                 failingSecondPage,
			defaults:             respondJSON([]any{}),
			wantConfigsReason:    CodeSecurityConfigUnavailableForbidden,
			wantDefaultsReadable: true,
			wantDefaultScopes:    []string{},
		},
		{
			name:                 "repeated cursor stops pagination",
			list:                 repeatingCursor,
			defaults:             respondJSON([]any{}),
			wantConfigsReason:    CodeSecurityConfigUnavailableError,
			wantDefaultsReadable: true,
			wantDefaultScopes:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case codeSecurityConfigsPath:
					tt.list(t, w, r)
				case codeSecurityDefaultsPath:
					tt.defaults(t, w, r)
				default:
					t.Errorf("unexpected request: %s", r.URL.String())
					w.WriteHeader(http.StatusNotFound)
				}
			})
			scanner, _ := newOrganizationTestScanner(t, handler)

			got := scanner.scanCodeSecurityConfigurations(context.Background())
			if got == nil {
				t.Fatal("scanCodeSecurityConfigurations returned nil")
			}

			if got.ConfigurationsReadable != tt.wantConfigsReadable {
				t.Errorf("ConfigurationsReadable = %v, want %v", got.ConfigurationsReadable, tt.wantConfigsReadable)
			}
			if got.ConfigurationsUnavailableReason != tt.wantConfigsReason {
				t.Errorf("ConfigurationsUnavailableReason = %q, want %q", got.ConfigurationsUnavailableReason, tt.wantConfigsReason)
			}
			if tt.wantConfigsReadable {
				if got.Configurations == nil {
					t.Fatal("Configurations = nil, want non-nil when readable")
				}
				ids := make([]int64, 0, len(got.Configurations))
				for _, c := range got.Configurations {
					ids = append(ids, c.GetID())
				}
				if !equalSlices(ids, tt.wantConfigIDs) {
					t.Errorf("configuration IDs = %v, want %v", ids, tt.wantConfigIDs)
				}
			} else if got.Configurations != nil {
				t.Errorf("Configurations = %v, want nil when not readable", got.Configurations)
			}

			if got.DefaultsReadable != tt.wantDefaultsReadable {
				t.Errorf("DefaultsReadable = %v, want %v", got.DefaultsReadable, tt.wantDefaultsReadable)
			}
			if got.DefaultsUnavailableReason != tt.wantDefaultsReason {
				t.Errorf("DefaultsUnavailableReason = %q, want %q", got.DefaultsUnavailableReason, tt.wantDefaultsReason)
			}
			if tt.wantDefaultsReadable {
				if got.DefaultConfigurations == nil {
					t.Fatal("DefaultConfigurations = nil, want non-nil when readable")
				}
				scopes := make([]string, 0, len(got.DefaultConfigurations))
				names := make([]string, 0, len(got.DefaultConfigurations))
				for _, d := range got.DefaultConfigurations {
					scopes = append(scopes, d.GetDefaultForNewRepos())
					names = append(names, d.GetConfiguration().Name)
				}
				if !equalSlices(scopes, tt.wantDefaultScopes) {
					t.Errorf("default scopes = %v, want %v", scopes, tt.wantDefaultScopes)
				}
				if tt.wantDefaultConfigName != nil && !equalSlices(names, tt.wantDefaultConfigName) {
					t.Errorf("default configuration names = %v, want %v", names, tt.wantDefaultConfigName)
				}
			} else if got.DefaultConfigurations != nil {
				t.Errorf("DefaultConfigurations = %v, want nil when not readable", got.DefaultConfigurations)
			}
		})
	}
}

func TestScanAll_AttachesCodeSecurityConfigurations(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/orgs/test-org":
			// Legacy fields are false even though a default configuration exists.
			writeJSON(t, w, http.StatusOK, map[string]any{
				"login": "test-org",
				"advanced_security_enabled_for_new_repositories": false,
				"secret_scanning_enabled_for_new_repositories":   false,
			})
		case codeSecurityConfigsPath:
			writeJSON(t, w, http.StatusOK, []any{codeSecurityConfig(1, "GitHub recommended")})
		case codeSecurityDefaultsPath:
			writeJSON(t, w, http.StatusOK, []any{
				map[string]any{"default_for_new_repos": "all", "configuration": codeSecurityConfig(1, "GitHub recommended")},
			})
		default:
			writeJSON(t, w, http.StatusNotFound, map[string]string{"message": "Not Found"})
		}
	})
	scanner, _ := newOrganizationTestScanner(t, handler)

	data, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if data.Settings == nil {
		t.Fatal("Settings = nil")
	}
	sec := data.Settings.Security
	if sec.AdvancedSecurityForNewRepos || sec.SecretScanningForNewRepos {
		t.Error("legacy *_for_new_repos fields changed; they must still mirror the organization API")
	}
	csc := sec.CodeSecurityConfigurations
	if csc == nil {
		t.Fatal("Settings.Security.CodeSecurityConfigurations = nil, want populated")
	}
	if !csc.ConfigurationsReadable || len(csc.Configurations) != 1 {
		t.Errorf("configurations readable=%v len=%d, want true/1", csc.ConfigurationsReadable, len(csc.Configurations))
	}
	if !csc.DefaultsReadable || len(csc.DefaultConfigurations) != 1 {
		t.Fatalf("defaults readable=%v len=%d, want true/1", csc.DefaultsReadable, len(csc.DefaultConfigurations))
	}
	if got := csc.DefaultConfigurations[0].GetDefaultForNewRepos(); got != "all" {
		t.Errorf("default_for_new_repos = %q, want all", got)
	}
}

func TestOrgCodeSecurityConfigurations_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantNil         bool
		wantConfigsNil  bool
		wantDefaultsNil bool
		wantReason      string
		wantJSONSubstrs []string
	}{
		{
			name:    "report from older ghqr has no field",
			input:   `{"settings":{"security":{"advanced_security_enabled_for_new_repos":false}}}`,
			wantNil: true,
		},
		{
			name:            "readable but empty keeps empty arrays",
			input:           `{"settings":{"security":{"code_security_configurations":{"configurations_readable":true,"configurations":[],"defaults_readable":true,"default_configurations":[]}}}}`,
			wantJSONSubstrs: []string{`"configurations":[]`, `"default_configurations":[]`},
		},
		{
			name:            "not readable keeps null and reason",
			input:           `{"settings":{"security":{"code_security_configurations":{"configurations_readable":false,"configurations_unavailable_reason":"forbidden","configurations":null,"defaults_readable":false,"defaults_unavailable_reason":"forbidden","default_configurations":null}}}}`,
			wantConfigsNil:  true,
			wantDefaultsNil: true,
			wantReason:      CodeSecurityConfigUnavailableForbidden,
			wantJSONSubstrs: []string{`"configurations":null`, `"configurations_unavailable_reason":"forbidden"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data OrganizationData
			if err := json.Unmarshal([]byte(tt.input), &data); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			csc := data.Settings.Security.CodeSecurityConfigurations
			out, err := json.Marshal(data)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if tt.wantNil {
				if csc != nil {
					t.Fatalf("CodeSecurityConfigurations = %+v, want nil", csc)
				}
				if strings.Contains(string(out), "code_security_configurations") {
					t.Errorf("marshalled output unexpectedly contains code_security_configurations: %s", out)
				}
				return
			}
			if csc == nil {
				t.Fatal("CodeSecurityConfigurations = nil, want populated")
			}
			if (csc.Configurations == nil) != tt.wantConfigsNil {
				t.Errorf("Configurations nil = %v, want %v", csc.Configurations == nil, tt.wantConfigsNil)
			}
			if (csc.DefaultConfigurations == nil) != tt.wantDefaultsNil {
				t.Errorf("DefaultConfigurations nil = %v, want %v", csc.DefaultConfigurations == nil, tt.wantDefaultsNil)
			}
			if csc.ConfigurationsUnavailableReason != tt.wantReason {
				t.Errorf("ConfigurationsUnavailableReason = %q, want %q", csc.ConfigurationsUnavailableReason, tt.wantReason)
			}
			for _, sub := range tt.wantJSONSubstrs {
				if !strings.Contains(string(out), sub) {
					t.Errorf("marshalled output missing %s: %s", sub, out)
				}
			}
		})
	}
}

func equalSlices[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
