// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"strings"

	"github.com/microsoft/ghqr/internal/renderers"
	"github.com/microsoft/ghqr/internal/renderers/excel"
	"github.com/rs/zerolog/log"
)

// ReportRenderingStage writes all scan results to disk.
type ReportRenderingStage struct {
	*BaseStage
}

// NewReportRenderingStage creates a new report rendering stage.
func NewReportRenderingStage() *ReportRenderingStage {
	return &ReportRenderingStage{
		BaseStage: NewBaseStage("report-rendering"),
	}
}

func (s *ReportRenderingStage) Execute(ctx *ScanContext) error {
	if len(ctx.Results) == 0 {
		log.Info().Msg("No scan results to render")
		return nil
	}

	log.Info().Int("results", len(ctx.Results)).Msg("Rendering reports...")

	jsonPath, err := renderers.RenderJSON(ctx.Results, ctx.OutputName)
	if err != nil {
		log.Error().Err(err).Msg("Failed to render JSON report")
	} else {
		log.Info().Str("path", jsonPath).Msg("JSON report written")
	}

	if ctx.Params.Xlsx {
		excel.CreateExcelReport(ctx.Results, ctx.OutputName)
	}

	s.printSummary(ctx)
	return nil
}

func (s *ReportRenderingStage) printSummary(ctx *ScanContext) {
	var enterprises, orgs, repos int
	for key := range ctx.Results {
		switch {
		case strings.HasPrefix(key, "enterprise:"):
			enterprises++
		case strings.HasPrefix(key, "organization:"):
			orgs++
		case strings.HasPrefix(key, "repository:"):
			repos++
		}
	}

	log.Info().
		Int("enterprises", enterprises).
		Int("organizations", orgs).
		Int("repositories", repos).
		Str("output", ctx.OutputName).
		Msg("Scan summary")
}

func (s *ReportRenderingStage) Skip(ctx *ScanContext) bool {
	return false
}
