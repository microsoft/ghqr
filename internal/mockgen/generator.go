// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package mockgen synthesizes ghqr-shaped scan output without calling the
// GitHub API. It emits only the raw entity facts that the existing pipeline's
// evaluation and rendering stages consume; recommendations and summaries are
// produced by replaying the file through `ghqr scan --from-json`.
package mockgen

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"
)

// Options controls synthesis. Zero values are replaced with sensible defaults
// (1 org, 5 repos, "typical" profile, time-based seed).
type Options struct {
	// Orgs is the number of organizations to generate (>= 1).
	Orgs int
	// ReposPerOrg is the number of repositories to generate per organization (>= 0).
	ReposPerOrg int
	// Enterprise, when non-empty, wraps all generated organizations in a single
	// synthetic enterprise with that slug.
	Enterprise string
	// Profile biases the distribution of compliant vs. non-compliant facts.
	Profile Profile
	// Seed deterministically controls the RNG. Zero means "use the current time".
	Seed int64
	// OrgPrefix overrides the default "mock-org" naming prefix.
	OrgPrefix string
	// RepoPrefix overrides the default "repo" naming prefix.
	RepoPrefix string
}

// Report is the JSON shape consumed by `ghqr scan --from-json`. It mirrors the
// top-level keys produced by renderers.RenderJSON.
type Report struct {
	GeneratedAt   string                 `json:"generated_at"`
	Enterprises   map[string]interface{} `json:"enterprises,omitempty"`
	Organizations map[string]interface{} `json:"organizations,omitempty"`
	Repositories  map[string]interface{} `json:"repositories,omitempty"`
}

// Generate synthesizes a Report according to opts.
func Generate(opts Options) (*Report, error) {
	if opts.Orgs <= 0 {
		opts.Orgs = 1
	}
	if opts.ReposPerOrg < 0 {
		opts.ReposPerOrg = 0
	}
	if opts.OrgPrefix == "" {
		opts.OrgPrefix = "mock-org"
	}
	if opts.RepoPrefix == "" {
		opts.RepoPrefix = "repo"
	}
	if opts.Profile == "" {
		opts.Profile = ProfileTypical
	}

	weights, err := weightsFor(opts.Profile)
	if err != nil {
		return nil, err
	}

	seed := opts.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	r := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic synthetic data, not security sensitive
	now := time.Unix(0, seed).UTC()
	if now.Year() < 2000 || now.Year() > 2100 {
		now = time.Now().UTC()
	}

	report := &Report{
		GeneratedAt:   now.Format(time.RFC3339),
		Enterprises:   map[string]interface{}{},
		Organizations: map[string]interface{}{},
		Repositories:  map[string]interface{}{},
	}

	orgLogins := make([]string, 0, opts.Orgs)
	for i := 1; i <= opts.Orgs; i++ {
		orgLogins = append(orgLogins, fmt.Sprintf("%s-%03d", opts.OrgPrefix, i))
	}

	emuEnabled := false
	if opts.Enterprise != "" {
		ent := buildEnterprise(r, opts.Enterprise, orgLogins, weights, now)
		report.Enterprises[opts.Enterprise] = ent
		if settings, ok := ent["settings"].(map[string]interface{}); ok {
			if v, ok := settings["emu_enabled"].(bool); ok {
				emuEnabled = v
			}
		}
	}

	for _, login := range orgLogins {
		report.Organizations[login] = buildOrganization(r, login, opts.Enterprise, weights, emuEnabled)
		for j := 1; j <= opts.ReposPerOrg; j++ {
			repoName := fmt.Sprintf("%s-%03d", opts.RepoPrefix, j)
			fullName := fmt.Sprintf("%s/%s", login, repoName)
			report.Repositories[fullName] = buildRepository(r, repoName, login, opts.Enterprise, weights, now)
		}
	}

	return report, nil
}

// WriteJSON marshals report to outPath with indented formatting and 0600 perms.
func WriteJSON(report *Report, outPath string) error {
	data, err := json.MarshalIndent(report, "", "\t")
	if err != nil {
		return fmt.Errorf("marshal mock report: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return fmt.Errorf("write mock report to %q: %w", outPath, err)
	}
	return nil
}
