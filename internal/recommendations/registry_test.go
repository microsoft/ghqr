// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package recommendations_test

import (
	"testing"

	"github.com/microsoft/ghqr/internal/recommendations"
)

func TestLoad_ReturnsRegistry(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}
	if reg.Count() == 0 {
		t.Fatal("registry is empty; expected rules to be loaded from embedded YAML files")
	}
}

func TestLoad_NoDuplicateIDs(t *testing.T) {
	// Load is guaranteed by the loader to reject duplicates, but verify it succeeds.
	_, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() unexpected error (possible duplicate IDs): %v", err)
	}
}

func TestLoad_AllRulesHaveRequiredFields(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	for _, r := range reg.All() {
		if r.ID == "" {
			t.Errorf("rule has empty id")
		}
		if r.Scope == "" {
			t.Errorf("rule %s has empty scope", r.ID)
		}
		if r.Title == "" {
			t.Errorf("rule %s has empty title", r.ID)
		}
		if r.Category == "" {
			t.Errorf("rule %s has empty category", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s has empty severity", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty description", r.ID)
		}
		if r.Recommendation == "" {
			t.Errorf("rule %s has empty recommendation", r.ID)
		}
	}
}

func TestLoad_AllRulesEnabled(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}
	for _, r := range reg.All() {
		if !r.Enabled {
			t.Errorf("rule %s is disabled; all shipped rules should be enabled by default", r.ID)
		}
	}
}

func TestRegistry_Get(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	rule, ok := reg.Get("repo-bp-001")
	if !ok {
		t.Fatal("Get(repo-bp-001) not found")
	}
	if rule.Scope != recommendations.ScopeRepository {
		t.Errorf("repo-bp-001 scope = %s, want %s", rule.Scope, recommendations.ScopeRepository)
	}
	if rule.Severity != "critical" {
		t.Errorf("repo-bp-001 severity = %s, want critical", rule.Severity)
	}

	_, ok = reg.Get("nonexistent-rule")
	if ok {
		t.Error("Get(nonexistent-rule) returned ok=true, want false")
	}
}

func TestRegistry_ByScope(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	repoRules := reg.ByScope(recommendations.ScopeRepository)
	if len(repoRules) == 0 {
		t.Fatal("ByScope(repository) returned empty slice")
	}
	for _, r := range repoRules {
		if r.Scope != recommendations.ScopeRepository {
			t.Errorf("ByScope(repository) returned rule %s with scope %s", r.ID, r.Scope)
		}
	}

	orgRules := reg.ByScope(recommendations.ScopeOrganization)
	if len(orgRules) == 0 {
		t.Fatal("ByScope(organization) returned empty slice")
	}

	entRules := reg.ByScope(recommendations.ScopeEnterprise)
	if len(entRules) == 0 {
		t.Fatal("ByScope(enterprise) returned empty slice")
	}
}

func TestRegistry_ByCategory(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	bpRules := reg.ByCategory("branch_protection")
	if len(bpRules) == 0 {
		t.Fatal("ByCategory(branch_protection) returned empty slice")
	}
	for _, r := range bpRules {
		if r.Category != "branch_protection" {
			t.Errorf("ByCategory(branch_protection) returned rule %s with category %s", r.ID, r.Category)
		}
	}
}

func TestRegistry_All_SortedByID(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	all := reg.All()
	for i := 1; i < len(all); i++ {
		if all[i].ID < all[i-1].ID {
			t.Errorf("All() not sorted: %s appears before %s", all[i-1].ID, all[i].ID)
		}
	}
}

func TestRegistry_KnownRuleIDs(t *testing.T) {
	reg, err := recommendations.Load()
	if err != nil {
		t.Fatalf("recommendations.Load() error = %v", err)
	}

	// Spot-check a rule from each YAML file to ensure loading works end-to-end.
	knownIDs := []string{
		// repository
		"repo-bp-001", "repo-bp-013",
		"repo-sec-001", "repo-sec-008",
		"repo-acc-001", "repo-acc-005",
		"repo-feat-001", "repo-feat-002",
		"repo-meta-001", "repo-meta-003",
		"repo-comm-001",
		// organization
		"org-sec-001", "org-sec-005",
		"org-def-001", "org-def-006",
		"org-act-001", "org-act-003",
		"org-alert-001", "org-alert-005",
		"org-cop-001", "org-cop-003",
		// enterprise
		"ent-log-001", "ent-log-002",
		"ent-ghas-001", "ent-ghas-007",
		"ent-alert-001", "ent-alert-004",
	}

	for _, id := range knownIDs {
		if _, ok := reg.Get(id); !ok {
			t.Errorf("known rule %s not found in registry", id)
		}
	}
}
