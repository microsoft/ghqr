// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:     "ghqr",
	Short:   "GitHub Quick Review (ghqr) goal is to produce a high level assessment of a GitHub Organization or Repository",
	Long:    `GitHub Quick Review (ghqr) goal is to produce a high level assessment of a GitHub Organization or Repository`,
	Args:    cobra.NoArgs,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debug, _ := cmd.Flags().GetBool("debug")
		initializeLogLevel(debug)
	},
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Usage()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolP("debug", "", false, "Enable debug logging")
}

func initializeLogLevel(debug bool) {
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug logging enabled")
		return
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

func Execute() {
	output := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	cobra.CheckErr(rootCmd.Execute())
}
