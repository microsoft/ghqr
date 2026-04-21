// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/microsoft/ghqr/internal/models"
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

// WithOrgRepositoryScan adds the org-repository scanning stage.
func (b *ScanPipelineBuilder) WithOrgRepositoryScan() *ScanPipelineBuilder {
	return b.addStage(NewOrgRepositoryScanStage())
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

// Build creates the pipeline with all configured stages.
func (b *ScanPipelineBuilder) Build() *Pipeline {
	return NewPipeline(b.stages...)
}

// BuildDefault creates a pipeline with all standard stages.
func (b *ScanPipelineBuilder) BuildDefault() *Pipeline {
	return b.
		WithInitialization().
		WithEnterpriseDiscovery().
		WithEnterpriseScan().
		WithOrganizationDiscovery().
		WithOrganizationScan().
		WithOrgRepositoryScan().
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
		outputName = fmt.Sprintf("ghqr_%s", startTime.Format("20060102_150405"))
	}

	return &ScanContext{
		Ctx:        ctx,
		Cancel:     cancel,
		StartTime:  startTime,
		OutputName: outputName,
		Params:     params,
		Results:    make(map[string]interface{}),
		Ownership:  make(map[string]string),
	}
}
