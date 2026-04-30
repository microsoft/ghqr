// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package mockgen

import (
	"encoding/json"
	"strings"
	"testing"
)

// embeddedEvalFields mirrors the list in pipeline.LoadFromJSONStage. The
// generator must never emit any of these — they are computed by the
// evaluation stage on replay.
var embeddedEvalFields = []string{
	"evaluation",
	"copilot_evaluation",
	"actions_permissions_evaluation",
	"org_security_alerts_evaluation",
	"security_managers_evaluation",
	"enterprise_security_alerts_evaluation",
	"enterprise_ghas_evaluation",
	"org_security_defaults_evaluation",
	"audit_log_evaluation",
	"metadata_evaluation",
	"collaborators_evaluation",
	"deploy_keys_evaluation",
	"dependabot_evaluation",
	"code_scanning_evaluation",
	"discussions_evaluation",
}

func TestGenerateProducesExpectedShape(t *testing.T) {
	report, err := Generate(Options{
		Orgs:        2,
		ReposPerOrg: 3,
		Enterprise:  "test-ent",
		Profile:     ProfileTypical,
		Seed:        42,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if got, want := len(report.Organizations), 2; got != want {
		t.Errorf("organizations: got %d want %d", got, want)
	}
	if got, want := len(report.Repositories), 6; got != want {
		t.Errorf("repositories: got %d want %d", got, want)
	}
	if _, ok := report.Enterprises["test-ent"]; !ok {
		t.Errorf("enterprise %q not found in report", "test-ent")
	}

	for name, entity := range report.Repositories {
		m, ok := entity.(map[string]interface{})
		if !ok {
			t.Fatalf("repository %q is not a map", name)
			continue
		}
		for _, banned := range embeddedEvalFields {
			if _, has := m[banned]; has {
				t.Errorf("repository %q must not contain field %q (it is computed on replay)", name, banned)
			}
		}
		if !strings.Contains(name, "/") {
			t.Errorf("repository key %q should be owner/repo", name)
		}
	}

	for name, entity := range report.Organizations {
		m, ok := entity.(map[string]interface{})
		if !ok {
			t.Fatalf("organization %q is not a map", name)
			continue
		}
		for _, banned := range embeddedEvalFields {
			if _, has := m[banned]; has {
				t.Errorf("organization %q must not contain field %q", name, banned)
			}
		}
	}

	// JSON round-trip must succeed and preserve top-level keys.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip Report
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(roundtrip.Repositories) != len(report.Repositories) {
		t.Errorf("roundtrip repos mismatch")
	}
}

func TestGenerateIsDeterministicWithSeed(t *testing.T) {
	a, err := Generate(Options{Orgs: 1, ReposPerOrg: 4, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(Options{Orgs: 1, ReposPerOrg: 4, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("identical seeds produced different output")
	}
}

func TestUnknownProfileReturnsError(t *testing.T) {
	if _, err := Generate(Options{Profile: Profile("bogus")}); err == nil {
		t.Errorf("expected error for unknown profile")
	}
}
