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
	scanCmd.PersistentFlags().StringP("output-name", "n", "", "Output file name without extension")
	scanCmd.PersistentFlags().StringP("hostname", "H", "", "GitHub hostname (e.g. mycompany.ghe.com for Data Residency). Defaults to github.com. Also reads GH_HOST env var")
	scanCmd.PersistentFlags().Bool("xlsx", true, "Create Excel (.xlsx) report")
	scanCmd.PersistentFlags().Bool("markdown", true, "Create Markdown (.md) executive report")

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

  # Scan with custom output name
  ghqr scan -e my-enterprise -n my-audit-2024

  # Scan and generate JSON output
  ghqr scan -e my-enterprise --json`,
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

	params := models.ScanParams{
		Enterprises:   getStringArray(cmd, "enterprise"),
		Organizations: getStringArray(cmd, "organization"),
		Repositories:  getStringArray(cmd, "repository"),
		OutputName:    getString(cmd, "output-name"),
		Hostname:      hostname,
		Debug:         getBool(cmd, "debug"),
		Xlsx:          getBool(cmd, "xlsx"),
		Markdown:      getBool(cmd, "markdown"),
	}

	scanner := pipeline.Scanner{}
	if _, err := scanner.Scan(&params); err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}

	log.Info().Msg("Scan completed")
}

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
