// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"fmt"
	"time"

	"github.com/microsoft/ghqr/internal/mockgen"
	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/pipeline"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	mockCmd.PersistentFlags().IntP("orgs", "o", 1, "Number of organizations to synthesize")
	mockCmd.PersistentFlags().IntP("repos", "r", 5, "Number of repositories per organization")
	mockCmd.PersistentFlags().StringP("enterprise", "e", "", "Optional enterprise slug to wrap all generated organizations")
	mockCmd.PersistentFlags().String("profile", "typical", "Distribution profile: clean | typical | noisy")
	mockCmd.PersistentFlags().Int64("seed", 0, "Random seed for deterministic output (0 = time-based)")
	mockCmd.PersistentFlags().StringP("output", "O", "", "Output JSON path (default ghqr_mock_<timestamp>.json)")
	mockCmd.PersistentFlags().Bool("render", false, "After writing JSON, replay it through the scan pipeline to also produce md/xlsx reports")
	mockCmd.PersistentFlags().Bool("xlsx", true, "When --render is set, produce an Excel (.xlsx) report")
	mockCmd.PersistentFlags().Bool("markdown", true, "When --render is set, produce a Markdown (.md) report")

	rootCmd.AddCommand(mockCmd)
}

var mockCmd = &cobra.Command{
	Use:   "mock",
	Short: "Generate a synthetic ghqr scan JSON without calling the GitHub API",
	Long: `Generate a synthetic ghqr scan JSON for O organizations and N repositories
per organization. The output is shaped like a real scan result and can be
replayed through 'ghqr scan --from-json <file>' to produce markdown/xlsx
reports with realistic recommendations.

The generator emits only raw entity facts; the existing evaluation stage
computes recommendations and summaries on replay, guaranteeing they stay in
sync with the rule definitions in internal/recommendations/definitions/.

Examples:
  # 1 org, 5 repos, typical noise level
  ghqr mock

  # 3 orgs, 10 repos each, wrapped in an enterprise, deterministic
  ghqr mock -o 3 -r 10 -e mock-ent --seed 42

  # Generate and immediately render md/xlsx in one shot
  ghqr mock -o 2 -r 8 --profile noisy --render`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runMock(cmd)
	},
}

func runMock(cmd *cobra.Command) {
	orgs := getInt(cmd, "orgs")
	repos := getInt(cmd, "repos")
	enterprise := getString(cmd, "enterprise")
	profile := getString(cmd, "profile")
	seed := getInt64(cmd, "seed")
	output := getString(cmd, "output")
	render := getBool(cmd, "render")

	if orgs < 1 {
		log.Fatal().Int("orgs", orgs).Msg("--orgs must be >= 1")
	}
	if repos < 0 {
		log.Fatal().Int("repos", repos).Msg("--repos must be >= 0")
	}

	report, err := mockgen.Generate(mockgen.Options{
		Orgs:        orgs,
		ReposPerOrg: repos,
		Enterprise:  enterprise,
		Profile:     mockgen.Profile(profile),
		Seed:        seed,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Mock generation failed")
	}

	if output == "" {
		output = fmt.Sprintf("ghqr_mock_%s.json", time.Now().Format("20060102_150405"))
	}
	if err := mockgen.WriteJSON(report, output); err != nil {
		log.Fatal().Err(err).Msg("Failed to write mock report")
	}
	log.Info().
		Str("path", output).
		Int("organizations", len(report.Organizations)).
		Int("repositories", len(report.Repositories)).
		Int("enterprises", len(report.Enterprises)).
		Msg("Mock scan written")

	if !render {
		return
	}

	params := models.ScanParams{
		FromJSON: output,
		Xlsx:     getBool(cmd, "xlsx"),
		Markdown: getBool(cmd, "markdown"),
		Debug:    getBool(cmd, "debug"),
	}
	scanner := pipeline.Scanner{}
	if _, err := scanner.Scan(&params); err != nil {
		log.Fatal().Err(err).Msg("Render of mock scan failed")
	}
	log.Info().Msg("Render completed")
}

func getInt(cmd *cobra.Command, flag string) int {
	v, _ := cmd.Flags().GetInt(flag)
	return v
}

func getInt64(cmd *cobra.Command, flag string) int64 {
	v, _ := cmd.Flags().GetInt64(flag)
	return v
}
