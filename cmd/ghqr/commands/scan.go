// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"os"

	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/pipeline"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	scanCmd.PersistentFlags().StringArrayP("enterprise", "e", []string{}, "GitHub Enterprise(s) to scan (can be specified multiple times)")
	scanCmd.PersistentFlags().StringArrayP("organization", "o", []string{}, "GitHub Organization(s) to scan (can be specified multiple times)")
	scanCmd.PersistentFlags().StringArrayP("repository", "r", []string{}, "GitHub Repository (owner/repo)")
	scanCmd.PersistentFlags().StringArrayP("ghes", "", []string{}, "GitHub Enterprise Server hostname(s) to scan (e.g. ghes.example.com)")
	scanCmd.PersistentFlags().StringP("output-name", "n", "", "Output file name without extension")
	scanCmd.PersistentFlags().StringP("hostname", "H", "", "GitHub hostname (e.g. mycompany.ghe.com for Data Residency). Defaults to github.com. Also reads GH_HOST env var")
	scanCmd.PersistentFlags().Bool("xlsx", true, "Create Excel (.xlsx) report")
	scanCmd.PersistentFlags().Bool("markdown", true, "Create Markdown (.md) executive report")
	scanCmd.PersistentFlags().String("from-json", "", "Replay enrichment from an existing scan JSON file (skips all GitHub API calls)")

	rootCmd.AddCommand(scanCmd)
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan GitHub Resources",
	Long: `Scan GitHub Resources (enterprises, organizations, repositories, etc.)
	
Examples:
  # Scan an enterprise (auto-discovers and scans all organizations)
  ghqr scan -e my-enterprise

  # Scan a single organization
  ghqr scan -o my-org

  # Scan multiple organizations
  ghqr scan -o org1 -o org2

  # Scan enterprise and specific organizations
  ghqr scan -e my-enterprise -o org1 -o org2
  
  # Scan GitHub data residency (custom hostname)
  ghqr scan -H mycompany.ghe.com -e my-enterprise

  # Scan specific repositories
  ghqr scan -r owner1/repo1 -r owner2/repo2

  # Scan a GitHub Enterprise Server instance
  ghqr scan --ghes ghes.example.com

  # Scan multiple GHES instances
  ghqr scan --ghes ghes1.example.com --ghes ghes2.example.com

  # Scan with custom output name
  ghqr scan -e my-enterprise -n my-audit-2024

  # Scan and generate JSON output
  ghqr scan -e my-enterprise --json

  # Replay enrichment against an existing scan JSON (no GitHub API calls)
  ghqr scan --from-json ghqr_20260417_143426.json`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		scan(cmd)
	},
}

func scan(cmd *cobra.Command) {
	hostname := getString(cmd, "hostname")
	if hostname == "" {
		hostname = os.Getenv("GH_HOST")
	}

	fromJSON := getString(cmd, "from-json")
	enterprises := getStringArray(cmd, "enterprise")
	organizations := getStringArray(cmd, "organization")
	repositories := getStringArray(cmd, "repository")
	ghesInstances := getStringArray(cmd, "ghes")

	if err := validateScanTargets(fromJSON, enterprises, organizations, repositories, ghesInstances); err != nil {
		log.Fatal().Msg(err.Error())
	}
	if fromJSON != "" {
		if _, err := os.Stat(fromJSON); err != nil {
			log.Fatal().Err(err).Str("path", fromJSON).Msg("--from-json file is not accessible")
		}
	}

	params := models.ScanParams{
		Enterprises:   enterprises,
		Organizations: organizations,
		Repositories:  repositories,
		GHESInstances: ghesInstances,
		OutputName:    getString(cmd, "output-name"),
		Hostname:      hostname,
		Debug:         getBool(cmd, "debug"),
		Xlsx:          getBool(cmd, "xlsx"),
		Markdown:      getBool(cmd, "markdown"),
		FromJSON:      fromJSON,
	}

	scanner := pipeline.Scanner{}
	if _, err := scanner.Scan(&params); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}

	log.Info().Msg("Scan completed")
}

// validateScanTargets enforces two CLI invariants:
//
//  1. The user supplied at least one scan target (--enterprise, -o, -r,
//     --ghes, or --from-json). Without this check the pipeline's GHES-only
//     short-circuit silently completes with zero work, masking both
//     missing credentials and missing flags. This was raised as a
//     regression in PR #84 review.
//  2. --from-json is not combined with any live-target flag, since the
//     replay loader is the sole data source in that mode.
//
// Returning an error (rather than log.Fatal directly) keeps the function
// unit-testable.
func validateScanTargets(fromJSON string, enterprises, organizations, repositories, ghesInstances []string) error {
	noTargets := fromJSON == "" &&
		len(enterprises) == 0 &&
		len(organizations) == 0 &&
		len(repositories) == 0 &&
		len(ghesInstances) == 0
	if noTargets {
		return errNoScanTarget
	}
	if fromJSON != "" && (len(enterprises) > 0 || len(organizations) > 0 || len(repositories) > 0 || len(ghesInstances) > 0) {
		return errFromJSONWithLiveTarget
	}
	return nil
}

var (
	errNoScanTarget           = errScanf("no scan target specified: use -e/--enterprise, -o/--organization, -r/--repository, --ghes, or --from-json")
	errFromJSONWithLiveTarget = errScanf("--from-json cannot be combined with -e/--enterprise, -o/--organization, -r/--repository, or --ghes")
)

// errScanf wraps a string in an error without depending on fmt.Errorf so
// the validation table reads at a glance.
func errScanf(msg string) error { return scanError(msg) }

type scanError string

func (e scanError) Error() string { return string(e) }

func getString(cmd *cobra.Command, flag string) string {
	v, _ := cmd.Flags().GetString(flag)
	return v
}

func getStringArray(cmd *cobra.Command, flag string) []string {
	v, _ := cmd.Flags().GetStringArray(flag)
	return v
}

func getBool(cmd *cobra.Command, flag string) bool {
	v, _ := cmd.Flags().GetBool(flag)
	return v
}
