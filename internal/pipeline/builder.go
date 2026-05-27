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

func (b *ScanPipelineBuilder) addStage(stage Stage) *ScanPipelineBuilder {
	b.stages = append(b.stages, stage)
	return b
}

// WithInitialization adds the initialization stage.
func (b *ScanPipelineBuilder) WithInitialization() *ScanPipelineBuilder {
	return b.addStage(NewInitializationStage())
}

// WithLoadFromJSON adds the load-from-json replay stage. The stage self-skips
// unless ScanParams.FromJSON is set.
func (b *ScanPipelineBuilder) WithLoadFromJSON() *ScanPipelineBuilder {
	return b.addStage(NewLoadFromJSONStage())
}

// WithEnterpriseScan adds the enterprise scanning stage.
func (b *ScanPipelineBuilder) WithEnterpriseScan() *ScanPipelineBuilder {
	return b.addStage(NewEnterpriseScanStage())
}

// WithEnterpriseDiscovery adds the enterprise discovery stage.
func (b *ScanPipelineBuilder) WithEnterpriseDiscovery() *ScanPipelineBuilder {
	return b.addStage(NewEnterpriseDiscoveryStage())
}

// WithOrganizationDiscovery adds the organization discovery stage.
func (b *ScanPipelineBuilder) WithOrganizationDiscovery() *ScanPipelineBuilder {
	return b.addStage(NewOrganizationDiscoveryStage())
}

// WithOrganizationScan adds the organization scanning stage.
func (b *ScanPipelineBuilder) WithOrganizationScan() *ScanPipelineBuilder {
	return b.addStage(NewOrganizationScanStage())
}

// WithOrgRepositoryDiscovery adds the org-repository discovery stage.
func (b *ScanPipelineBuilder) WithOrgRepositoryDiscovery() *ScanPipelineBuilder {
	return b.addStage(NewOrgRepositoryDiscoveryStage())
}

// WithRepositoryScan adds the individual repository scanning stage.
func (b *ScanPipelineBuilder) WithRepositoryScan() *ScanPipelineBuilder {
	return b.addStage(NewRepositoryScanStage())
}

// WithReportRendering adds the report rendering stage.
func (b *ScanPipelineBuilder) WithReportRendering() *ScanPipelineBuilder {
	return b.addStage(NewReportRenderingStage())
}

// WithEvaluation adds the evaluation stage.
func (b *ScanPipelineBuilder) WithEvaluation() *ScanPipelineBuilder {
	return b.addStage(NewEvaluationStage())
}

// WithGHESScan adds the GitHub Enterprise Server scanning stage.
func (b *ScanPipelineBuilder) WithGHESScan() *ScanPipelineBuilder {
	return b.addStage(NewGHESScanStage())
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
		WithInitialization().
		WithLoadFromJSON().
		WithGHESScan().
		WithEnterpriseDiscovery().
		WithEnterpriseScan().
		WithOrganizationDiscovery().
		WithOrganizationScan().
		WithOrgRepositoryDiscovery().
		WithRepositoryScan().
		WithEvaluation().
		WithReportRendering().
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
