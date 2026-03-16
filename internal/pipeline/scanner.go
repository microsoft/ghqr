// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"fmt"
	"time"

	"github.com/microsoft/ghqr/internal/models"
	"github.com/rs/zerolog/log"
)

// Scanner orchestrates the scan execution using the pipeline pattern.
type Scanner struct{}

// Scan performs a full scan using the default pipeline and returns the output path and any error.
func (sc *Scanner) Scan(params *models.ScanParams) (string, error) {
	builder := NewScanPipelineBuilder()
	scanCtx := NewScanContext(params)

	pipe := builder.BuildDefault()

	if err := pipe.Execute(scanCtx); err != nil {
		return scanCtx.OutputName, fmt.Errorf("scan failed: %w", err)
	}

	if params.Debug {
		pipe.LogMetrics()
	}

	log.Info().Msgf("Scan completed in %s", time.Since(scanCtx.StartTime).Round(time.Second))
	return scanCtx.OutputName, nil
}
