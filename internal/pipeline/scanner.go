// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"time"

	"github.com/microsoft/ghqr/internal/models"
	"github.com/rs/zerolog/log"
)

// Scanner orchestrates the scan execution using the pipeline pattern.
type Scanner struct{}

// Scan performs a full scan using the default pipeline and returns the output directory used.
func (sc *Scanner) Scan(params *models.ScanParams) string {
	builder := NewScanPipelineBuilder()
	scanCtx := NewScanContext(params)

	pipe := builder.BuildDefault()

	err := pipe.Execute(scanCtx)
	if err != nil {
		log.Fatal().Err(err).Msg("Scan failed")
	}

	if params.Debug {
		pipe.LogMetrics()
	}

	log.Info().Msgf("Scan completed in %s", time.Since(scanCtx.StartTime).Round(time.Second))
	return scanCtx.OutputName
}
