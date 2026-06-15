// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/microsoft/ghqr/internal/config"
	"github.com/microsoft/ghqr/internal/models"
	"github.com/microsoft/ghqr/internal/scanners"
)

// ScanPipelineBuilder provides a fluent interface for building scan pipelines.
type ScanPipelineBuilder struct {
	stages []Stage
}

// NewScanPipelineBuilder creates a new pipeline builder.
func NewScanPipelineBuilder() *ScanPipelineBuilder {
	return &ScanPipelineBuilder{
		stages: []Stage{},
	}
}

// With appends a stage to the pipeline and returns the builder for chaining.
func (b *ScanPipelineBuilder) With(s Stage) *ScanPipelineBuilder {
	b.stages = append(b.stages, s)
	return b
}

// Build creates the pipeline with all configured stages.
func (b *ScanPipelineBuilder) Build() *Pipeline {
	return NewPipeline(b.stages...)
}

// BuildDefault creates a pipeline with all standard stages.
//
// LoadFromJSON runs BEFORE any scanning stage so that --from-json replays do
// not issue any live API calls. Every scanning stage must additionally check
// ctx.Params.FromJSON in its Skip() method as a belt-and-braces guard.
func (b *ScanPipelineBuilder) BuildDefault() *Pipeline {
	return b.
		With(NewInitializationStage()).
		With(NewLoadFromJSONStage()).
		With(NewGHESScanStage()).
		With(NewEnterpriseDiscoveryStage()).
		With(NewEnterpriseScanStage()).
		With(NewOrganizationDiscoveryStage()).
		With(NewOrganizationScanStage()).
		With(NewOrgRepositoryDiscoveryStage()).
		With(NewRepositoryScanStage()).
		With(NewEvaluationStage()).
		With(NewReportRenderingStage()).
		Build()
}

// NewScanContext creates a scan context from ScanParams.
func NewScanContext(params *models.ScanParams) *ScanContext {
	ctx, cancel := context.WithCancel(context.Background())
	startTime := time.Now()

	outputName := params.OutputName
	if outputName == "" {
		if params.FromJSON != "" {
			base := filepath.Base(params.FromJSON)
			base = strings.TrimSuffix(base, filepath.Ext(base))
			outputName = fmt.Sprintf("%s_replay_%s", base, startTime.Format("20060102_150405"))
		} else {
			outputName = fmt.Sprintf("ghqr_%s", startTime.Format("20060102_150405"))
		}
	}

	return &ScanContext{
		Ctx:            ctx,
		Cancel:         cancel,
		StartTime:      startTime,
		OutputName:     outputName,
		Params:         params,
		Clients:        make(map[string]*config.Clients),
		GraphQLClients: make(map[string]*scanners.GraphQLClient),
		Results:        make(map[string]interface{}),
		Ownership:      make(map[string]string),
	}
}
