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

// newGHESTestScanner wires a GHESScanner to a test HTTP server. The provided
// handler implements whichever GHES REST endpoints the test needs; everything
// else returns 404.
func newGHESTestScanner(t *testing.T, handler http.Handler) (*GHESScanner, *httptest.Server) {
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
	return NewGHESScanner(client, "test.invalid"), srv
}

// TestGetSettings_ManagementAPIInaccessible verifies the false-positive class
// raised in PR #84 review: when /manage/v1/config/settings returns 401/403,
// the scanner must report Source=Unavailable and leave every boolean field
// nil, so the evaluator cannot fabricate Critical findings.
func TestGetSettings_ManagementAPIInaccessible(t *testing.T) {
	statuses := []int{401, 403, 404, 500}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/manage/v1/config/settings"):
					w.WriteHeader(status)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			scanner, _ := newGHESTestScanner(t, handler)

			settings, err := scanner.getSettings(context.Background())
			if err != nil {
				t.Fatalf("getSettings should not return an error when management API is unreachable, got %v", err)
			}
			if settings == nil {
				t.Fatal("getSettings should always return a non-nil settings struct")
			}
			if settings.Source != SettingsSourceUnavailable {
				t.Errorf("Source = %q, want %q", settings.Source, SettingsSourceUnavailable)
			}

			// Every boolean enablement field must remain nil — that is the
			// whole point of the tri-state model.
			if settings.PrivateMode != nil {
				t.Errorf("PrivateMode should be nil (unknown), got %v", *settings.PrivateMode)
			}
			if settings.SubdomainIsolation != nil {
				t.Errorf("SubdomainIsolation should be nil, got %v", *settings.SubdomainIsolation)
			}
			if settings.GHASEnabled != nil {
				t.Errorf("GHASEnabled should be nil, got %v", *settings.GHASEnabled)
			}
			if settings.CodeScanningEnabled != nil {
				t.Errorf("CodeScanningEnabled should be nil, got %v", *settings.CodeScanningEnabled)
			}
			if settings.AuthMode != nil {
				t.Errorf("AuthMode should be nil, got %q", *settings.AuthMode)
			}
		})
	}
}

// TestGetSettings_ManagementAPIAccessible verifies that explicitly-disabled
// settings are surfaced as observed-false (non-nil pointers to false), so
// downstream evaluators still emit real findings.
func TestGetSettings_ManagementAPIAccessible(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/manage/v1/config/settings") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"private_mode":              false,
			"subdomain_isolation":       false,
			"advanced_security_enabled": false,
			"actions_enabled":           true,
			"auth_mode":                 "saml",
		})
	})
	scanner, _ := newGHESTestScanner(t, handler)

	settings, err := scanner.getSettings(context.Background())
	if err != nil {
		t.Fatalf("getSettings: %v", err)
	}
	if settings.Source != SettingsSourceManageAPI {
		t.Errorf("Source = %q, want %q", settings.Source, SettingsSourceManageAPI)
	}
	if settings.PrivateMode == nil || *settings.PrivateMode {
		t.Errorf("PrivateMode should be observed-false, got %v", settings.PrivateMode)
	}
	if settings.SubdomainIsolation == nil || *settings.SubdomainIsolation {
		t.Errorf("SubdomainIsolation should be observed-false, got %v", settings.SubdomainIsolation)
	}
	if settings.GHASEnabled == nil || *settings.GHASEnabled {
		t.Errorf("GHASEnabled should be observed-false, got %v", settings.GHASEnabled)
	}
	if settings.ActionsEnabled == nil || !*settings.ActionsEnabled {
		t.Errorf("ActionsEnabled should be observed-true, got %v", settings.ActionsEnabled)
	}
	if settings.AuthMode == nil || *settings.AuthMode != "saml" {
		t.Errorf("AuthMode = %v, want \"saml\"", settings.AuthMode)
	}
	// SAML derivation should be observed-true; LDAP / CAS observed-false.
	if settings.SAMLEnabled == nil || !*settings.SAMLEnabled {
		t.Errorf("SAMLEnabled should be observed-true, got %v", settings.SAMLEnabled)
	}
	if settings.LDAPEnabled == nil || *settings.LDAPEnabled {
		t.Errorf("LDAPEnabled should be observed-false, got %v", settings.LDAPEnabled)
	}

	// Fields not present in the response must stay nil ("unknown"), not
	// collapse to false. This is the regression that the pointer-aware
	// parser exists to prevent.
	if settings.SignupEnabled != nil {
		t.Errorf("SignupEnabled should be nil (key absent), got %v", *settings.SignupEnabled)
	}
	if settings.MaintenanceMode != nil {
		t.Errorf("MaintenanceMode should be nil (key absent), got %v", *settings.MaintenanceMode)
	}
}

// TestProbeFeatures_OnlyConfirmsOn2xx verifies that probeFeatures does not
// treat 401/403/5xx responses as "feature supported". Only an actual 2xx
// from the endpoint should mark the API as available.
func TestProbeFeatures_OnlyConfirmsOn2xx(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"200_available", http.StatusOK, true},
		{"204_available", http.StatusNoContent, true},
		{"401_unknown", http.StatusUnauthorized, false},
		{"403_unknown", http.StatusForbidden, false},
		{"404_unsupported", http.StatusNotFound, false},
		{"500_unknown", http.StatusInternalServerError, false},
		{"429_unknown", http.StatusTooManyRequests, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
			})
			scanner, _ := newGHESTestScanner(t, handler)
			got := scanner.probeEndpoint(context.Background(), "enterprises/actions/permissions")
			if got != c.want {
				t.Errorf("probeEndpoint() = %v, want %v for status %d", got, c.want, c.status)
			}
		})
	}
}

// TestGetLicense_403Returns_NilNotError verifies the existing graceful
// behaviour when the license endpoint is forbidden (non-site-admin token):
// the license is reported as missing, not as a hard error. Locked in here
// so the partial-permissions paths called out in PR review stay covered.
func TestGetLicense_403Returns_NilNotError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/enterprise/settings/license") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	scanner, _ := newGHESTestScanner(t, handler)

	license, err := scanner.getLicense(context.Background())
	if err != nil {
		t.Fatalf("getLicense should swallow 403 and return nil, got err=%v", err)
	}
	if license != nil {
		t.Errorf("license should be nil on 403, got %+v", license)
	}
}

// TestGetAdminStats_404Returns_NilNotError covers the same degraded-token
// case for /enterprise/stats/all.
func TestGetAdminStats_404Returns_NilNotError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	scanner, _ := newGHESTestScanner(t, handler)

	stats, err := scanner.getAdminStats(context.Background())
	if err != nil {
		t.Fatalf("getAdminStats should swallow 404 and return nil, got err=%v", err)
	}
	if stats != nil {
		t.Errorf("stats should be nil on 404, got %+v", stats)
	}
}
