// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/microsoft/ghqr/internal/recommendations"
	"github.com/spf13/cobra"
)

var listRecommendationsCmd = &cobra.Command{
	Use:   "list-recommendations",
	Short: "List all best-practice recommendations in the registry",
	Long: `Enumerate all best-practice rules that ghqr evaluates.

Each recommendation has a stable ID, scope (repository/organization/enterprise),
category, severity, and a human-readable title. This catalog is the
direct equivalent of azqr's recommendations documentation.

Flags can be combined to filter the output. Use --json for machine-readable output.`,
	RunE: runListRecommendations,
}

var (
	listRecsFlagScope    string
	listRecsFlagCategory string
	listRecsFlagSeverity string
	listRecsFlagJSON     bool
)

func init() {
	listRecommendationsCmd.Flags().StringVarP(&listRecsFlagScope, "scope", "s", "", "Filter by scope (repository, organization, enterprise)")
	listRecommendationsCmd.Flags().StringVarP(&listRecsFlagCategory, "category", "c", "", "Filter by category (e.g. security, branch_protection)")
	listRecommendationsCmd.Flags().StringVar(&listRecsFlagSeverity, "severity", "", "Filter by severity (critical, high, medium, low, info)")
	listRecommendationsCmd.Flags().BoolVar(&listRecsFlagJSON, "json", false, "Output as JSON")
	rootCmd.AddCommand(listRecommendationsCmd)
}

func runListRecommendations(cmd *cobra.Command, args []string) error {
	registry, err := recommendations.Load()
	if err != nil {
		return fmt.Errorf("loading recommendation registry: %w", err)
	}

	all := registry.All()

	// Apply filters.
	filtered := all[:0]
	for _, r := range all {
		if listRecsFlagScope != "" && string(r.Scope) != listRecsFlagScope {
			continue
		}
		if listRecsFlagCategory != "" && r.Category != listRecsFlagCategory {
			continue
		}
		if listRecsFlagSeverity != "" && r.Severity != listRecsFlagSeverity {
			continue
		}
		filtered = append(filtered, r)
	}

	if listRecsFlagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(filtered)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSCOPE\tCATEGORY\tSEVERITY\tTITLE")
	_, _ = fmt.Fprintln(w, "──────────────────\t──────────────\t──────────────────────\t──────────\t─────────────────────────────────────────────────────")
	for _, r := range filtered {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Scope, r.Category, r.Severity, r.Title)
	}
	_ = w.Flush()

	_, _ = fmt.Fprintf(os.Stderr, "\n%d recommendation(s) shown (total in registry: %d)\n", len(filtered), registry.Count())
	return nil
}
